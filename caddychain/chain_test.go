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

// TestAllBad_ReturnsClean404 全部落定为 bad：返回干净 404，不透传后端报文
// 与响应头（对象存储错误 XML 等不得作为资源内容展示给客户端）。
func TestAllBad_ReturnsClean404(t *testing.T) {
	notFound := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-Origin-Marker", "first-bad")
		w.WriteHeader(http.StatusNotFound)
		fmt.Fprint(w, "<Error><Code>NoSuchKey</Code></Error>")
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
		t.Fatalf("status = %d, want 404", resp.StatusCode)
	}
	body := readAll(t, resp)
	if strings.Contains(body, "NoSuchKey") || strings.Contains(body, "Error") {
		t.Fatalf("backend error body leaked: %q", body)
	}
	if got := resp.Header.Get("X-Origin-Marker"); got != "" {
		t.Fatalf("backend header leaked: X-Origin-Marker=%q", got)
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

// TestSingleUpstream_404Clean 单上游退化直通：上游 404 与全挂同口径，
// 返回干净 404 而非透传后端报文（对象存储错误 XML 不得展示给客户端）。
func TestSingleUpstream_404Clean(t *testing.T) {
	up := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-Origin-Marker", "yes")
		w.WriteHeader(http.StatusNotFound)
		fmt.Fprint(w, "<Error><Code>NoSuchKey</Code></Error>")
	}))
	t.Cleanup(up.Close)
	h := newTestHandler([]ChainUpstream{{Dial: dialOf(up)}}, 50, 9000, 0)
	resp := do(t, h, http.MethodGet, "/missing.jpg", "")
	if resp.StatusCode != http.StatusNotFound {
		t.Fatalf("status = %d, want 404", resp.StatusCode)
	}
	body := readAll(t, resp)
	if strings.Contains(body, "NoSuchKey") {
		t.Fatalf("backend error body leaked: %q", body)
	}
	if got := resp.Header.Get("X-Origin-Marker"); got != "" {
		t.Fatalf("backend header leaked: X-Origin-Marker=%q", got)
	}
}

// TestSingleUpstream_Non404Passthrough 单上游退化直通：非 404 的错误响应保持
// 透传（5xx 等语义错误不被误标为 404）。
func TestSingleUpstream_Non404Passthrough(t *testing.T) {
	up := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
		fmt.Fprint(w, "boom")
	}))
	t.Cleanup(up.Close)
	h := newTestHandler([]ChainUpstream{{Dial: dialOf(up)}}, 50, 9000, 0)
	resp := do(t, h, http.MethodGet, "/", "")
	if resp.StatusCode != http.StatusInternalServerError {
		t.Fatalf("status = %d, want 500 passthrough", resp.StatusCode)
	}
	if body := readAll(t, resp); body != "boom" {
		t.Fatalf("body = %q, want boom", body)
	}
}

// ===== S1 新增：wrr 模式 + 混布车道/隧道/SNI 缓存/多车道链序（JJC-20261118-002）=====

// newWRRHandler 构造 mode=wrr 的测试 handler。
func newWRRHandler(ups []ChainUpstream, raceIntervalMS, requestTimeoutMS int, replayLimit int) *ChainProxy {
	h := newTestHandler(ups, raceIntervalMS, requestTimeoutMS, replayLimit)
	h.Mode = modeWRR
	return h
}

// TestWRR_DistributionSequence smooth 加权轮询分布序列：权重 2/1/1 的确定性
// 序列为 0,1,2,0 循环（长程分布精确 2:1:1）。
func TestWRR_DistributionSequence(t *testing.T) {
	var mu sync.Mutex
	var seq []int
	ups := make([]*httptest.Server, 3)
	weights := []int{2, 1, 1}
	for i := 0; i < 3; i++ {
		idx := i
		ups[i] = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			mu.Lock()
			seq = append(seq, idx)
			mu.Unlock()
			w.WriteHeader(http.StatusOK)
			fmt.Fprintf(w, "lane%d", idx)
		}))
		t.Cleanup(ups[i].Close)
	}
	h := newWRRHandler([]ChainUpstream{
		{Dial: dialOf(ups[0]), Weight: weights[0]},
		{Dial: dialOf(ups[1]), Weight: weights[1]},
		{Dial: dialOf(ups[2]), Weight: weights[2]},
	}, 50, 9000, 0)

	want := []int{0, 1, 2, 0, 0, 1, 2, 0}
	for i := 0; i < len(want); i++ {
		resp := do(t, h, http.MethodGet, "/", "")
		if resp.StatusCode != http.StatusOK {
			t.Fatalf("request %d: status = %d", i, resp.StatusCode)
		}
		if body := readAll(t, resp); body != fmt.Sprintf("lane%d", want[i]) {
			t.Fatalf("request %d: body = %q, want lane%d (seq so far %v)", i, body, want[i], seq)
		}
	}
	mu.Lock()
	defer mu.Unlock()
	if len(seq) != len(want) {
		t.Fatalf("seq = %v, want %v", seq, want)
	}
}

// TestWRR_FailoverDeadLane 车道 0 建连失败：即刻按权重降序切下一车道。
func TestWRR_FailoverDeadLane(t *testing.T) {
	good := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		fmt.Fprint(w, "recovered")
	}))
	t.Cleanup(good.Close)
	h := newWRRHandler([]ChainUpstream{
		{Dial: "127.0.0.1:1"},
		{Dial: dialOf(good)},
	}, 30_000, 9000, 0)

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

// TestWRR_HeaderTimeoutFailsOver 响应头兜底超时也是网络错误：失败即切。
func TestWRR_HeaderTimeoutFailsOver(t *testing.T) {
	hang := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		<-r.Context().Done()
	}))
	t.Cleanup(hang.Close)
	good := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		fmt.Fprint(w, "after-timeout")
	}))
	t.Cleanup(good.Close)
	h := newWRRHandler([]ChainUpstream{
		{Dial: dialOf(hang)},
		{Dial: dialOf(good)},
	}, 30_000, 300, 0)

	resp := do(t, h, http.MethodGet, "/", "")
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d, want 200", resp.StatusCode)
	}
	if body := readAll(t, resp); body != "after-timeout" {
		t.Fatalf("body = %q", body)
	}
}

// TestWRR_AllDead502 车道全灭（建连失败）→ 502。
func TestWRR_AllDead502(t *testing.T) {
	h := newWRRHandler([]ChainUpstream{
		{Dial: "127.0.0.1:1"},
		{Dial: "127.0.0.1:1"},
	}, 50, 9000, 0)
	resp := do(t, h, http.MethodGet, "/", "")
	if resp.StatusCode != http.StatusBadGateway {
		t.Fatalf("status = %d, want 502", resp.StatusCode)
	}
	readAll(t, resp)
}

// TestWRR_AllTimeout504 全部车道兜底超时 → 504。
func TestWRR_AllTimeout504(t *testing.T) {
	hang := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		<-r.Context().Done()
	}))
	t.Cleanup(hang.Close)
	hang2 := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		<-r.Context().Done()
	}))
	t.Cleanup(hang2.Close)
	h := newWRRHandler([]ChainUpstream{
		{Dial: dialOf(hang)},
		{Dial: dialOf(hang2)},
	}, 50, 200, 0)
	resp := do(t, h, http.MethodGet, "/", "")
	if resp.StatusCode != http.StatusGatewayTimeout {
		t.Fatalf("status = %d, want 504", resp.StatusCode)
	}
	readAll(t, resp)
}

// TestWRR_BadStatusPassthrough 响应头已到（任意状态码）原样透传：上游 502
// 直达客户端，不触发失败即切（与原生 reverse_proxy 对齐）。
func TestWRR_BadStatusPassthrough(t *testing.T) {
	var secondHits int
	var mu sync.Mutex
	bad := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusBadGateway)
		fmt.Fprint(w, "origin-502")
	}))
	t.Cleanup(bad.Close)
	second := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		secondHits++
		mu.Unlock()
		w.WriteHeader(http.StatusOK)
	}))
	t.Cleanup(second.Close)
	h := newWRRHandler([]ChainUpstream{
		{Dial: dialOf(bad)},
		{Dial: dialOf(second)},
	}, 50, 9000, 0)

	resp := do(t, h, http.MethodGet, "/", "")
	if resp.StatusCode != http.StatusBadGateway {
		t.Fatalf("status = %d, want 502 passthrough", resp.StatusCode)
	}
	if body := readAll(t, resp); body != "origin-502" {
		t.Fatalf("body = %q, want origin-502", body)
	}
	mu.Lock()
	defer mu.Unlock()
	if secondHits != 0 {
		t.Fatalf("bad status must not fail over, second lane hit %d times", secondHits)
	}
}

// TestWRR_SingleUpstream_404Passthrough wrr 单上游退化直通：上游 404 原样
// 透传（与 race 的干净 404 刻意分叉，禁复用 serveSingleLane 分支）。
func TestWRR_SingleUpstream_404Passthrough(t *testing.T) {
	up := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-Origin-Marker", "yes")
		w.WriteHeader(http.StatusNotFound)
		fmt.Fprint(w, "<Error><Code>NoSuchKey</Code></Error>")
	}))
	t.Cleanup(up.Close)
	h := newWRRHandler([]ChainUpstream{{Dial: dialOf(up)}}, 50, 9000, 0)
	resp := do(t, h, http.MethodGet, "/missing.jpg", "")
	if resp.StatusCode != http.StatusNotFound {
		t.Fatalf("status = %d, want 404", resp.StatusCode)
	}
	body := readAll(t, resp)
	if !strings.Contains(body, "NoSuchKey") {
		t.Fatalf("wrr 404 must pass backend body through, got %q", body)
	}
	if got := resp.Header.Get("X-Origin-Marker"); got != "yes" {
		t.Fatalf("wrr 404 must pass backend headers through, got %q", got)
	}
}

// TestWRR_OversizeBody_404Passthrough wrr 体重放超限直通：404 透传而非
// 干净 404，前缀续传无丢失。
func TestWRR_OversizeBody_404Passthrough(t *testing.T) {
	want := strings.Repeat("x", 32)
	var gotBody string
	up := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b, _ := io.ReadAll(r.Body)
		gotBody = string(b)
		w.Header().Set("X-Origin-Marker", "yes")
		w.WriteHeader(http.StatusNotFound)
		fmt.Fprint(w, "<Error>origin</Error>")
	}))
	t.Cleanup(up.Close)
	h := newWRRHandler([]ChainUpstream{{Dial: dialOf(up)}}, 50, 9000, 8)

	resp := do(t, h, http.MethodPost, "/", want)
	if resp.StatusCode != http.StatusNotFound {
		t.Fatalf("status = %d, want 404 passthrough", resp.StatusCode)
	}
	body := readAll(t, resp)
	if !strings.Contains(body, "origin") {
		t.Fatalf("oversize direct path must pass 404 body through, got %q", body)
	}
	if got := resp.Header.Get("X-Origin-Marker"); got != "yes" {
		t.Fatalf("backend header leaked: %q", got)
	}
	if gotBody != want {
		t.Fatalf("upstream body = %d bytes, want full %d bytes", len(gotBody), len(want))
	}
}

// TestWRR_UpgradeTunnel wrr 模式升级请求复用 serveTunnel 按链序。
func TestWRR_UpgradeTunnel(t *testing.T) {
	ws := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
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

	h := newWRRHandler([]ChainUpstream{{Dial: dialOf(ws)}}, 50, 9000, 0)
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
	if _, err := conn.Write([]byte("GET /ws HTTP/1.1\r\nHost: panel.example.com\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n\r\n")); err != nil {
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

// TestWRR_MixedScheme wrr 混布车道：真 TLS httptest 上游 + 明文上游，
// 逐车道协议正确。
func TestWRR_MixedScheme(t *testing.T) {
	tlsUp := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.TLS == nil {
			t.Errorf("tls lane received plain request")
		}
		w.WriteHeader(http.StatusOK)
		fmt.Fprint(w, "tls-lane")
	}))
	t.Cleanup(tlsUp.Close)
	plainUp := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.TLS != nil {
			t.Errorf("plain lane received tls request")
		}
		w.WriteHeader(http.StatusOK)
		fmt.Fprint(w, "plain-lane")
	}))
	t.Cleanup(plainUp.Close)

	h := newWRRHandler([]ChainUpstream{
		{Dial: dialOf(tlsUp), Scheme: "https", Weight: 1},
		{Dial: dialOf(plainUp), Weight: 1},
	}, 50, 9000, 0)

	bodies := map[string]bool{}
	for i := 0; i < 2; i++ {
		resp := do(t, h, http.MethodGet, "/", "")
		if resp.StatusCode != http.StatusOK {
			t.Fatalf("request %d: status = %d", i, resp.StatusCode)
		}
		bodies[readAll(t, resp)] = true
	}
	if !bodies["tls-lane"] || !bodies["plain-lane"] {
		t.Fatalf("mixed scheme lanes not both served: %v", bodies)
	}
}

// TestRace_MixedSchemeHTTPS race 模式混布车道：https 上游竞速正常回源。
func TestRace_MixedSchemeHTTPS(t *testing.T) {
	tlsUp := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		fmt.Fprint(w, "tls-first")
	}))
	t.Cleanup(tlsUp.Close)
	plainUp := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		fmt.Fprint(w, "plain-second")
	}))
	t.Cleanup(plainUp.Close)

	h := newTestHandler([]ChainUpstream{
		{Dial: dialOf(tlsUp), Scheme: "https"},
		{Dial: dialOf(plainUp)},
	}, 10_000, 9000, 0)

	resp := do(t, h, http.MethodGet, "/", "")
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d", resp.StatusCode)
	}
	if body := readAll(t, resp); body != "tls-first" {
		t.Fatalf("body = %q, want tls-first (https lane broken)", body)
	}
}

// TestWRR_HostPerLaneThreeStates 逐车道回源 Host 三态：上游 Host > 空=用
// dial 地址（规则级回退由生成侧解析为 up.Host，模块侧两态+空兜底）。
func TestWRR_HostPerLaneThreeStates(t *testing.T) {
	var mu sync.Mutex
	gotHosts := map[string]string{}
	makeUp := func(marker string) *httptest.Server {
		return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			mu.Lock()
			gotHosts[marker] = r.Host
			mu.Unlock()
			w.WriteHeader(http.StatusOK)
			fmt.Fprint(w, marker)
		}))
	}
	upA := makeUp("origin-host")
	t.Cleanup(upA.Close)
	upB := makeUp("dial-host")
	t.Cleanup(upB.Close)
	upC := makeUp("rule-host")
	t.Cleanup(upC.Close)

	h := newWRRHandler([]ChainUpstream{
		{Dial: dialOf(upA), Host: "origin.example.com", Weight: 1},
		{Dial: dialOf(upB), Weight: 1},
		{Dial: dialOf(upC), Host: "rule.example.com", Weight: 1},
	}, 50, 9000, 0)

	for i := 0; i < 3; i++ {
		resp := do(t, h, http.MethodGet, "/", "")
		readAll(t, resp)
	}
	if gotHosts["origin-host"] != "origin.example.com" {
		t.Fatalf("lane A Host = %q, want origin.example.com", gotHosts["origin-host"])
	}
	if gotHosts["dial-host"] != dialOf(upB) {
		t.Fatalf("lane B Host = %q, want dial %q", gotHosts["dial-host"], dialOf(upB))
	}
	if gotHosts["rule-host"] != "rule.example.com" {
		t.Fatalf("lane C Host = %q, want rule.example.com", gotHosts["rule-host"])
	}
}

// TestSNITransportCache SNI 派生 transport 缓存三态 + Cleanup。
func TestSNITransportCache(t *testing.T) {
	h := newTestHandler([]ChainUpstream{}, 50, 9000, 0)
	derivedA := h.transportFor(ChainUpstream{Dial: "10.0.0.1:443", Scheme: "https", Host: "a.example.com"})
	if derivedA == h.baseTransport {
		t.Fatal("SNI != dial host must derive a dedicated transport")
	}
	cachedA := h.transportFor(ChainUpstream{Dial: "10.0.0.1:443", Scheme: "https", Host: "a.example.com"})
	if cachedA != derivedA {
		t.Fatal("same SNI must reuse cached transport")
	}
	derivedB := h.transportFor(ChainUpstream{Dial: "10.0.0.2:443", Scheme: "https", Host: "b.example.com"})
	if derivedB == derivedA {
		t.Fatal("different SNI must derive distinct transport")
	}
	sameAsDial := h.transportFor(ChainUpstream{Dial: "a.example.com:443", Scheme: "https", Host: "a.example.com"})
	if sameAsDial != h.baseTransport {
		t.Fatal("SNI == dial host must use base transport")
	}
	noHost := h.transportFor(ChainUpstream{Dial: "10.0.0.3:443", Scheme: "https"})
	if noHost != h.baseTransport {
		t.Fatal("empty Host must use base transport (dial fallback)")
	}
	plain := h.transportFor(ChainUpstream{Dial: "10.0.0.4:80", Host: "a.example.com"})
	if plain != h.baseTransport {
		t.Fatal("http scheme must use base transport")
	}
	if err := h.Cleanup(); err != nil {
		t.Fatalf("Cleanup: %v", err)
	}
}

// TestValidate_Mode Validate 拒绝非法 mode，合法值与空串放行。
func TestValidate_Mode(t *testing.T) {
	base := []ChainUpstream{{Dial: "127.0.0.1:8000"}}
	for _, mode := range []string{"", modeRace, modeWRR} {
		h := &ChainProxy{Upstreams: base, Mode: mode}
		if err := h.Validate(); err != nil {
			t.Fatalf("mode %q: unexpected error %v", mode, err)
		}
	}
	h := &ChainProxy{Upstreams: base, Mode: "bogus"}
	if err := h.Validate(); err == nil {
		t.Fatal("illegal mode must be rejected")
	}
}

// TestTunnel_HTTPSUpstreamWithFallback 隧道混布：https 车道 TLS 隧道 +
// dial 失败换道。
func TestTunnel_HTTPSUpstreamWithFallback(t *testing.T) {
	ws := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
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
		{Dial: "127.0.0.1:1"},
		{Dial: dialOf(ws), Scheme: "https"},
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
	if _, err := conn.Write([]byte("GET /ws HTTP/1.1\r\nHost: panel.example.com\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n\r\n")); err != nil {
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
		t.Fatalf("handshake = %q, want 101 via https lane", head)
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

// ===== S1 追加：HC 配置面 Validate 钉测（JJC-20261119-001）=====

// TestValidate_HealthCheck HC 配置面校验：expect_status 单值/闭区间/缺省
// 放行；min>max、非数字等非法形态拒绝；负值 interval/timeout/lag 拒绝。
func TestValidate_HealthCheck(t *testing.T) {
	base := []ChainUpstream{{Dial: "127.0.0.1:8000"}}
	for _, tc := range []struct {
		name string
		hc   ChainHealthCheck
		ok   bool
	}{
		{name: "nil", hc: ChainHealthCheck{}, ok: true}, // 缺省 expect_status=200-299
		{name: "single", hc: ChainHealthCheck{ExpectStatus: "204"}, ok: true},
		{name: "range", hc: ChainHealthCheck{ExpectStatus: "200-299"}, ok: true},
		{name: "min>max", hc: ChainHealthCheck{ExpectStatus: "500-400"}, ok: false},
		{name: "alpha", hc: ChainHealthCheck{ExpectStatus: "2xx"}, ok: false},
		{name: "open-range", hc: ChainHealthCheck{ExpectStatus: "200-"}, ok: false},
		{name: "neg-interval", hc: ChainHealthCheck{IntervalMS: -1}, ok: false},
		{name: "neg-timeout", hc: ChainHealthCheck{TimeoutMS: -1}, ok: false},
		{name: "neg-lag", hc: ChainHealthCheck{UnhealthyLag: -1}, ok: false},
	} {
		h := &ChainProxy{Upstreams: base}
		if tc.name != "nil" {
			hc := tc.hc
			h.HealthCheck = &hc
		}
		err := h.Validate()
		if tc.ok && err != nil {
			t.Fatalf("case %s: unexpected error %v", tc.name, err)
		}
		if !tc.ok && err == nil {
			t.Fatalf("case %s: must be rejected", tc.name)
		}
	}
}
