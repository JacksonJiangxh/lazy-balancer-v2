package caddychain

import (
	"bytes"
	"crypto/tls"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"
)

// newTestHandler 绕过 Provision（无需 caddy.Context），手动装配 transport。
func newTestHandler(ups []ChainUpstream, raceIntervalMS, requestTimeoutMS int, replayLimit int) *ChainProxy {
	h := &ChainProxy{
		Upstreams:            ups,
		RaceIntervalMS:       raceIntervalMS,
		RequestTimeoutMS:     requestTimeoutMS,
		DialTimeoutMS:        2000,
		BodyReplayLimitBytes: replayLimit,
		baseTransport:        newTestTransport(),
	}
	if replayLimit <= 0 {
		h.BodyReplayLimitBytes = DefaultBodyReplayLimitBytes
	}
	return h
}

func newTestTransport() *http.Transport {
	return &http.Transport{
		MaxIdleConns:        100,
		MaxIdleConnsPerHost: 10,
		IdleConnTimeout:     90 * time.Second,
		TLSClientConfig:     &tls.Config{InsecureSkipVerify: true}, //nolint:gosec
		ForceAttemptHTTP2:   false,
	}
}

// do 通过面向客户端的 httptest 服务器调用 handler（获得真实的 Caddy 式
// ResponseWriter），返回代理后的响应。
func do(t *testing.T, h *ChainProxy, method, path, body string) *http.Response {
	t.Helper()
	proxy := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if err := h.ServeHTTP(w, r, nil); err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
		}
	}))
	t.Cleanup(proxy.Close)
	req, err := http.NewRequest(method, proxy.URL+path, strings.NewReader(body))
	if err != nil {
		t.Fatalf("new request: %v", err)
	}
	resp, err := proxy.Client().Do(req)
	if err != nil {
		t.Fatalf("proxy request: %v", err)
	}
	return resp
}

func dialOf(ts *httptest.Server) string {
	return ts.Listener.Addr().String()
}

func readAll(t *testing.T, resp *http.Response) string {
	t.Helper()
	defer resp.Body.Close()
	b, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("read body: %v", err)
	}
	return string(b)
}

// TestRace_SecondLaneWins 车道 0 慢、车道 1 快：竞速间隔到点发第二路，
// 第二路 200 胜出，车道 0 被取消截断。
func TestRace_SecondLaneWins(t *testing.T) {
	var lane0Canceled = make(chan struct{})
	slow := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		select {
		case <-r.Context().Done():
			close(lane0Canceled)
		case <-time.After(5 * time.Second):
			w.WriteHeader(http.StatusOK)
		}
	}))
	t.Cleanup(slow.Close)
	fast := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		fmt.Fprint(w, "fast-wins")
	}))
	t.Cleanup(fast.Close)

	h := newTestHandler([]ChainUpstream{
		{Dial: dialOf(slow)},
		{Dial: dialOf(fast)},
	}, 100, 9000, 0)

	start := time.Now()
	resp := do(t, h, http.MethodGet, "/", "")
	elapsed := time.Since(start)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d, want 200", resp.StatusCode)
	}
	if body := readAll(t, resp); body != "fast-wins" {
		t.Fatalf("body = %q, want fast-wins", body)
	}
	if elapsed > 2*time.Second {
		t.Fatalf("elapsed = %v, racing did not happen", elapsed)
	}
	select {
	case <-lane0Canceled:
	case <-time.After(2 * time.Second):
		t.Fatal("lane 0 was not canceled after winner decided")
	}
}

// TestRace_FirstLaneWinsNoSecondLaunch 车道 0 快速 200：竞速间隔未到即胜出，
// 第二路绝不发出。
func TestRace_FirstLaneWinsNoSecondLaunch(t *testing.T) {
	var secondHits int
	var mu sync.Mutex
	first := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		fmt.Fprint(w, "first")
	}))
	t.Cleanup(first.Close)
	second := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		secondHits++
		mu.Unlock()
		w.WriteHeader(http.StatusOK)
	}))
	t.Cleanup(second.Close)

	h := newTestHandler([]ChainUpstream{
		{Dial: dialOf(first)},
		{Dial: dialOf(second)},
	}, 10_000, 9000, 0)

	resp := do(t, h, http.MethodGet, "/", "")
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d", resp.StatusCode)
	}
	readAll(t, resp)
	time.Sleep(100 * time.Millisecond)
	mu.Lock()
	defer mu.Unlock()
	if secondHits != 0 {
		t.Fatalf("second lane hit %d times, want 0", secondHits)
	}
}

// TestFailover_BadStatusLaunchesNextImmediately 车道 0 返回 502：不等竞速
// 间隔，立即发出车道 1 并以 200 胜出。
func TestFailover_BadStatusLaunchesNextImmediately(t *testing.T) {
	bad := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusBadGateway)
	}))
	t.Cleanup(bad.Close)
	good := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		fmt.Fprint(w, "recovered")
	}))
	t.Cleanup(good.Close)

	h := newTestHandler([]ChainUpstream{
		{Dial: dialOf(bad)},
		{Dial: dialOf(good)},
	}, 30_000, 9000, 0) // 竞速间隔极大：证明 502 触发的是「失败即切」

	start := time.Now()
	resp := do(t, h, http.MethodGet, "/", "")
	elapsed := time.Since(start)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d, want 200", resp.StatusCode)
	}
	if body := readAll(t, resp); body != "recovered" {
		t.Fatalf("body = %q", body)
	}
	if elapsed > 2*time.Second {
		t.Fatalf("elapsed = %v, failover was not immediate", elapsed)
	}
}

// TestAllBad_ReturnsFirstBadResponse 全部落定为 bad：透传最先到达的 bad 响应。
func TestAllBad_ReturnsFirstBadResponse(t *testing.T) {
	notFound := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNotFound)
		fmt.Fprint(w, "first-bad")
	}))
	t.Cleanup(notFound.Close)
	forbidden := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusForbidden)
	}))
	t.Cleanup(forbidden.Close)

	h := newTestHandler([]ChainUpstream{
		{Dial: dialOf(notFound)},
		{Dial: dialOf(forbidden)},
	}, 50, 9000, 0)

	resp := do(t, h, http.MethodGet, "/", "")
	if resp.StatusCode != http.StatusNotFound {
		t.Fatalf("status = %d, want 404 (first-arrived bad)", resp.StatusCode)
	}
	if body := readAll(t, resp); body != "first-bad" {
		t.Fatalf("body = %q, want first-bad", body)
	}
}

// TestAllTimeout_504 全部车道兜底截断：504。
func TestAllTimeout_504(t *testing.T) {
	hang := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		<-r.Context().Done()
	}))
	t.Cleanup(hang.Close)
	hang2 := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		<-r.Context().Done()
	}))
	t.Cleanup(hang2.Close)

	h := newTestHandler([]ChainUpstream{
		{Dial: dialOf(hang)},
		{Dial: dialOf(hang2)},
	}, 50, 200, 0)

	start := time.Now()
	resp := do(t, h, http.MethodGet, "/", "")
	elapsed := time.Since(start)
	if resp.StatusCode != http.StatusGatewayTimeout {
		t.Fatalf("status = %d, want 504", resp.StatusCode)
	}
	readAll(t, resp)
	if elapsed > 3*time.Second {
		t.Fatalf("elapsed = %v, truncation did not bound the wait", elapsed)
	}
}

// TestBodyReplay 请求体重放：POST 体在两条车道上重放一致。
func TestBodyReplay(t *testing.T) {
	const want = "hello-chain-replay"
	var mu sync.Mutex
	received := make([]string, 0, 2)
	newReplayServer := func(delay time.Duration) *httptest.Server {
		return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			b, _ := io.ReadAll(r.Body)
			mu.Lock()
			received = append(received, string(b))
			mu.Unlock()
			time.Sleep(delay)
			w.WriteHeader(http.StatusOK)
			fmt.Fprint(w, "ok")
		}))
	}
	slow := newReplayServer(300 * time.Millisecond)
	t.Cleanup(slow.Close)
	fast := newReplayServer(0)
	t.Cleanup(fast.Close)

	h := newTestHandler([]ChainUpstream{
		{Dial: dialOf(slow)},
		{Dial: dialOf(fast)},
	}, 80, 9000, 0)

	resp := do(t, h, http.MethodPost, "/", want)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d", resp.StatusCode)
	}
	readAll(t, resp)
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		mu.Lock()
		got := len(received)
		mu.Unlock()
		if got >= 2 {
			break
		}
		time.Sleep(20 * time.Millisecond)
	}
	mu.Lock()
	defer mu.Unlock()
	if len(received) < 2 {
		t.Fatalf("received %d lane bodies, want 2", len(received))
	}
	for i, got := range received {
		if got != want {
			t.Fatalf("lane %d body = %q, want %q", i, got, want)
		}
	}
}

// TestOversizeBody_SingleLane 请求体超重放上限：仅车道 0，前缀续传无丢失。
func TestOversizeBody_SingleLane(t *testing.T) {
	want := strings.Repeat("x", 32)
	var secondHits int
	var mu sync.Mutex
	var gotBody string
	first := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b, _ := io.ReadAll(r.Body)
		gotBody = string(b)
		w.WriteHeader(http.StatusOK)
		fmt.Fprint(w, "lane0")
	}))
	t.Cleanup(first.Close)
	second := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		secondHits++
		mu.Unlock()
		w.WriteHeader(http.StatusOK)
	}))
	t.Cleanup(second.Close)

	h := newTestHandler([]ChainUpstream{
		{Dial: dialOf(first)},
		{Dial: dialOf(second)},
	}, 50, 9000, 8)

	resp := do(t, h, http.MethodPost, "/", want)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d", resp.StatusCode)
	}
	if body := readAll(t, resp); body != "lane0" {
		t.Fatalf("body = %q", body)
	}
	if gotBody != want {
		t.Fatalf("upstream body = %d bytes, want full %d bytes (prefix continuation lost)", len(gotBody), len(want))
	}
	mu.Lock()
	defer mu.Unlock()
	if secondHits != 0 {
		t.Fatalf("oversize body must not race, second lane hit %d times", secondHits)
	}
}

// TestHeaders_HostXFFAndStrip 逐上游回源 Host、XFF 追加、进程内控制头剥离。
func TestHeaders_HostXFFAndStrip(t *testing.T) {
	var gotHost, gotXFF, gotStripped string
	up := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotHost = r.Host
		gotXFF = r.Header.Get("X-Forwarded-For")
		gotStripped = r.Header.Get("X-LB-Rule-ID")
		w.WriteHeader(http.StatusOK)
	}))
	t.Cleanup(up.Close)

	h := newTestHandler([]ChainUpstream{
		{Dial: dialOf(up), Host: "origin.example.com"},
	}, 50, 9000, 0)
	h.StripRequestHeaders = []string{"X-LB-Rule-ID"}

	req := httptest.NewRequest(http.MethodGet, "http://panel.example.com/", nil)
	req.Header.Set("X-Forwarded-For", "203.0.113.7")
	req.Header.Set("X-LB-Rule-ID", "forged")
	req.RemoteAddr = "9.9.9.9:12345"
	rec := httptest.NewRecorder()
	if err := h.ServeHTTP(rec, req, nil); err != nil {
		t.Fatalf("ServeHTTP: %v", err)
	}
	if gotHost != "origin.example.com" {
		t.Fatalf("upstream Host = %q, want origin.example.com", gotHost)
	}
	if gotXFF != "203.0.113.7, 9.9.9.9" {
		t.Fatalf("XFF = %q, want appended client IP", gotXFF)
	}
	if gotStripped != "" {
		t.Fatalf("stripped header reached upstream: %q", gotStripped)
	}
}

// TestTunnel_UpgradeWithFallback websocket 类升级请求走隧道且 dial 失败
// 换下一上游，101 后双向透传。
func TestTunnel_UpgradeWithFallback(t *testing.T) {
	deadDial := "127.0.0.1:1" // 保留端口，必然拒连
	ws := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Upgrade") == "" {
			http.Error(w, "not an upgrade", http.StatusBadRequest)
			return
		}
		hj, ok := w.(http.Hijacker)
		if !ok {
			http.Error(w, "no hijack", http.StatusInternalServerError)
			return
		}
		conn, rw, _ := hj.Hijack()
		defer conn.Close()
		fmt.Fprint(conn, "HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n\r\n")
		buf := make([]byte, 16)
		n, _ := rw.Read(buf)
		fmt.Fprintf(conn, "echo:%s", buf[:n])
	}))
	t.Cleanup(ws.Close)

	h := newTestHandler([]ChainUpstream{
		{Dial: deadDial},
		{Dial: dialOf(ws)},
	}, 50, 9000, 0)

	proxy := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if err := h.ServeHTTP(w, r, nil); err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
		}
	}))
	t.Cleanup(proxy.Close)

	conn, err := net.Dial("tcp", dialOf(proxy))
	if err != nil {
		t.Fatalf("dial proxy: %v", err)
	}
	defer conn.Close()
	_, err = conn.Write([]byte("GET /ws HTTP/1.1\r\nHost: panel.example.com\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n\r\n"))
	if err != nil {
		t.Fatalf("write handshake: %v", err)
	}
	conn.SetReadDeadline(time.Now().Add(3 * time.Second))
	head := make([]byte, 0, 256)
	buf := make([]byte, 1)
	for !bytes.Contains(head, []byte("\r\n\r\n")) {
		n, err := conn.Read(buf)
		if err != nil {
			t.Fatalf("read handshake (got %q): %v", head, err)
		}
		head = append(head, buf[:n]...)
	}
	if !bytes.Contains(head, []byte("101")) {
		t.Fatalf("handshake = %q, want 101", head)
	}
	if _, err := conn.Write([]byte("ping")); err != nil {
		t.Fatalf("write frame: %v", err)
	}
	echo := make([]byte, 32)
	n, err := conn.Read(echo)
	if err != nil {
		t.Fatalf("read echo: %v", err)
	}
	if !strings.HasPrefix(string(echo[:n]), "echo:ping") {
		t.Fatalf("echo = %q", echo[:n])
	}
}

// TestSingleUpstream_DirectProxy 单上游退化直通。
func TestSingleUpstream_DirectProxy(t *testing.T) {
	up := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-Upstream", "yes")
		w.WriteHeader(http.StatusOK)
		fmt.Fprint(w, "direct")
	}))
	t.Cleanup(up.Close)
	h := newTestHandler([]ChainUpstream{{Dial: dialOf(up)}}, 50, 9000, 0)
	resp := do(t, h, http.MethodGet, "/", "")
	if resp.StatusCode != http.StatusOK || readAll(t, resp) != "direct" {
		t.Fatal("single upstream passthrough broken")
	}
	if resp.Header.Get("X-Upstream") != "yes" {
		t.Fatal("response headers not passed through")
	}
}
