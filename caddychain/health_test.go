package caddychain

import (
	"bytes"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"
)

// ===== S1 新增：主动健康检查子系统（JJC-20261119-001）=====
//
// 用例总表（对应验收 A3/A4/A5/A6/A7）：
//   初始态两断言（首探前全车道放行 / 首探失败按 lag 收敛）、lag 阈值、
//   恢复回池、调度间隔、wrr 跳过、race 剔除、隧道联动、全灭放行、
//   Cleanup 停止、探测 Host-scheme 口径、expect_status 判定与解析、
//   body 子串、探测慢上游不拖慢并发业务请求。

// hcProbeServer 带探针路径的上游：/hc 按 probeRes 逐字应答（探针命中计数；
// <=0 表示挂起，探测按超时判败），其余路径视为业务请求（业务命中计数）。
type hcProbeServer struct {
	ts       *httptest.Server
	probes   atomic.Int64
	bizHits  atomic.Int64
	probeRes atomic.Int64
}

func newHCProbeServer(t *testing.T) *hcProbeServer {
	s := &hcProbeServer{}
	s.probeRes.Store(http.StatusOK)
	s.ts = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/hc" {
			s.probes.Add(1)
			res := int(s.probeRes.Load())
			if res <= 0 {
				<-r.Context().Done() // 挂起
				return
			}
			w.WriteHeader(res)
			if res == http.StatusOK {
				fmt.Fprint(w, "hc-ok")
			} else {
				fmt.Fprint(w, "down")
			}
			return
		}
		s.bizHits.Add(1)
		w.WriteHeader(http.StatusOK)
		fmt.Fprintf(w, "biz-%s", r.URL.Path)
	}))
	t.Cleanup(s.ts.Close)
	return s
}

// newHCUpstream 探针服务转车道上游（host 为回源 Host 覆写，可空）。
func newHCUpstream(s *hcProbeServer, host string, weight int) ChainUpstream {
	up := ChainUpstream{Dial: dialOf(s.ts), Host: host, Weight: weight}
	return up
}

// hcCfg 快捷 HC 配置（ms 级节奏 + lag=1 快收敛；探针路径统一 /hc）。
func hcCfg(intervalMS int) *ChainHealthCheck {
	return &ChainHealthCheck{
		IntervalMS:   intervalMS,
		TimeoutMS:    500,
		Path:         "/hc",
		UnhealthyLag: 1,
		HealthyLag:   1,
	}
}

// startHC 挂载并启动 HC，测试结束停止（无泄漏）。
func startHC(t *testing.T, h *ChainProxy, hc *ChainHealthCheck) *ChainProxy {
	t.Helper()
	h.HealthCheck = hc
	h.startHealthMonitor()
	if h.hcState == nil {
		t.Fatal("HC monitor did not start")
	}
	t.Cleanup(h.stopHealthMonitor)
	return h
}

// waitLaneHealthy 轮询等待车道健康态翻转到位。
func waitLaneHealthy(t *testing.T, h *ChainProxy, idx int, want bool) {
	t.Helper()
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		if h.hcState != nil && h.hcState.healthy(idx) == want {
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatalf("lane %d: healthy=%v want %v (timeout 3s)", idx, h.hcState.healthy(idx), want)
}

// waitProbesAtLeast 等待探针命中数到达下限。
func waitProbesAtLeast(t *testing.T, s *hcProbeServer, n int64) {
	t.Helper()
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		if s.probes.Load() >= n {
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatalf("probes = %d, want >= %d (timeout)", s.probes.Load(), n)
}

// TestHC_InitialState_AllLanesServeBeforeFirstProbe 初始态断言①：首个探测
// 前业务请求打到全部车道（初值全 healthy，先放行后探测收敛——裁决 3）。
func TestHC_InitialState_AllLanesServeBeforeFirstProbe(t *testing.T) {
	a := newHCProbeServer(t)
	b := newHCProbeServer(t)
	c := newHCProbeServer(t)
	h := startHC(t, newWRRHandler([]ChainUpstream{
		newHCUpstream(a, "", 1),
		newHCUpstream(b, "", 1),
		newHCUpstream(c, "", 1),
	}, 50, 9000, 0), &ChainHealthCheck{IntervalMS: 60_000, TimeoutMS: 500, Path: "/hc"}) // interval 巨大：测试窗口内无探测

	if !h.hcState.healthy(0) || !h.hcState.healthy(1) || !h.hcState.healthy(2) {
		t.Fatal("initial state must be all-healthy")
	}
	for i := 0; i < 3; i++ {
		resp := do(t, h, http.MethodGet, "/", "")
		if resp.StatusCode != http.StatusOK {
			t.Fatalf("request %d: status = %d", i, resp.StatusCode)
		}
		readAll(t, resp)
	}
	for idx, s := range []*hcProbeServer{a, b, c} {
		if s.bizHits.Load() < 1 {
			t.Fatalf("initial state: lane %d got no business traffic before first probe (hits=%d)", idx, s.bizHits.Load())
		}
		if s.probes.Load() != 0 {
			t.Fatalf("lane %d probed before first interval", idx)
		}
	}
}

// TestHC_FirstProbeFailure_ConvergesRemoval 初始态断言② + wrr 跳过：首探
// 失败按 lag 收敛摘除，摘除后业务流量全部落到健康车道。
func TestHC_FirstProbeFailure_ConvergesRemoval(t *testing.T) {
	down := newHCProbeServer(t)
	up := newHCProbeServer(t)
	down.probeRes.Store(http.StatusBadGateway) // /hc 恒 502
	h := startHC(t, newWRRHandler([]ChainUpstream{
		newHCUpstream(down, "", 1),
		newHCUpstream(up, "", 1),
	}, 50, 9000, 0), hcCfg(30))

	waitLaneHealthy(t, h, 0, false)
	waitLaneHealthy(t, h, 1, true)
	downBizBefore := down.bizHits.Load()
	for i := 0; i < 4; i++ {
		resp := do(t, h, http.MethodGet, "/", "")
		if resp.StatusCode != http.StatusOK {
			t.Fatalf("request %d: status = %d", i, resp.StatusCode)
		}
		readAll(t, resp)
	}
	if down.bizHits.Load() != downBizBefore {
		t.Fatalf("wrr did not skip unhealthy lane: down biz hits %d -> %d", downBizBefore, down.bizHits.Load())
	}
	if up.bizHits.Load() < 4 {
		t.Fatalf("healthy lane biz hits = %d, want >= 4", up.bizHits.Load())
	}
}

// TestHC_LagThreshold_TwoFailuresNeeded lag 阈值语义：UnhealthyLag=2 时
// 单次失败不摘除、连续两次才摘除。
func TestHC_LagThreshold_TwoFailuresNeeded(t *testing.T) {
	s := newHCProbeServer(t)
	s.probeRes.Store(http.StatusBadGateway)
	h := startHC(t, newWRRHandler([]ChainUpstream{newHCUpstream(s, "", 1)}, 50, 9000, 0),
		&ChainHealthCheck{IntervalMS: 150, TimeoutMS: 500, Path: "/hc", UnhealthyLag: 2, HealthyLag: 1})

	waitProbesAtLeast(t, s, 1)
	if !h.hcState.healthy(0) {
		t.Fatalf("single failure must not remove lane (probes=%d)", s.probes.Load())
	}
	waitLaneHealthy(t, h, 0, false)
	if s.probes.Load() < 2 {
		t.Fatalf("lane removed after %d probes, want >= 2 (UnhealthyLag=2)", s.probes.Load())
	}
}

// TestHC_Recovery_HealthyLag 恢复语义：unhealthy 后连续成功 HealthyLag 次
// 重新入池（wrr 观测回池）。
func TestHC_Recovery_HealthyLag(t *testing.T) {
	s := newHCProbeServer(t)
	s.probeRes.Store(http.StatusBadGateway)
	h := startHC(t, newWRRHandler([]ChainUpstream{newHCUpstream(s, "", 1)}, 50, 9000, 0), hcCfg(30))
	waitLaneHealthy(t, h, 0, false)

	s.probeRes.Store(http.StatusOK)
	waitLaneHealthy(t, h, 0, true)
	resp := do(t, h, http.MethodGet, "/", "")
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d", resp.StatusCode)
	}
	readAll(t, resp)
	if s.bizHits.Load() < 1 {
		t.Fatal("recovered lane did not re-enter the pool")
	}
}

// TestHC_Scheduler_IntervalCadence 调度间隔：探测按 interval 节奏触发
// （窗口内命中数落在 interval 推导区间内）。
func TestHC_Scheduler_IntervalCadence(t *testing.T) {
	s := newHCProbeServer(t)
	startHC(t, newWRRHandler([]ChainUpstream{newHCUpstream(s, "", 1)}, 50, 9000, 0), hcCfg(50))
	time.Sleep(220 * time.Millisecond)
	n := s.probes.Load()
	// 220ms / 50ms ≈ 4 轮；调度抖动放宽容差 [2, 7]。
	if n < 2 || n > 7 {
		t.Fatalf("probe count over 220ms with 50ms interval = %d, want in [2,7]", n)
	}
}

// TestHC_WRR_SkipsUnhealthy_WeightsPreserve wrr 跳过 unhealthy：摘除车道
// 权重视为缺席，其余车道权重比例仍生效（1:1）。
func TestHC_WRR_SkipsUnhealthy_WeightsPreserve(t *testing.T) {
	down := newHCProbeServer(t)
	a := newHCProbeServer(t)
	b := newHCProbeServer(t)
	down.probeRes.Store(http.StatusBadGateway)
	h := startHC(t, newWRRHandler([]ChainUpstream{
		newHCUpstream(down, "", 2),
		newHCUpstream(a, "", 1),
		newHCUpstream(b, "", 1),
	}, 50, 9000, 0), hcCfg(30))
	waitLaneHealthy(t, h, 0, false)

	for i := 0; i < 8; i++ {
		resp := do(t, h, http.MethodGet, "/", "")
		readAll(t, resp)
	}
	if down.bizHits.Load() != 0 {
		t.Fatalf("removed lane received %d business hits, want 0", down.bizHits.Load())
	}
	if a.bizHits.Load() == 0 || b.bizHits.Load() == 0 {
		t.Fatalf("healthy lanes distribution broken: a=%d b=%d", a.bizHits.Load(), b.bizHits.Load())
	}
	if diff := a.bizHits.Load() - b.bizHits.Load(); diff < -1 || diff > 1 {
		t.Fatalf("1:1 weights distorted after removal: a=%d b=%d", a.bizHits.Load(), b.bizHits.Load())
	}
}

// TestHC_Race_ExcludesUnhealthy race 扇出剔除：unhealthy 车道不发射
// （探测性请求为零），健康车道胜出。
func TestHC_Race_ExcludesUnhealthy(t *testing.T) {
	down := newHCProbeServer(t)
	up := newHCProbeServer(t)
	down.probeRes.Store(http.StatusBadGateway)
	h := startHC(t, newTestHandler([]ChainUpstream{
		newHCUpstream(down, "", 0),
		newHCUpstream(up, "", 0),
	}, 30_000, 9000, 0), hcCfg(30))
	waitLaneHealthy(t, h, 0, false)

	resp := do(t, h, http.MethodGet, "/", "")
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d", resp.StatusCode)
	}
	readAll(t, resp)
	time.Sleep(100 * time.Millisecond)
	if down.bizHits.Load() != 0 {
		t.Fatalf("race fanned out to unhealthy lane: %d hits, want 0", down.bizHits.Load())
	}
	if up.bizHits.Load() < 1 {
		t.Fatal("healthy lane did not serve")
	}
}

// TestHC_Tunnel_SkipsUnhealthy 隧道联动：unhealthy 车道按链序剔除，
// 升级请求直达健康车道完成 101 握手。
func TestHC_Tunnel_SkipsUnhealthy(t *testing.T) {
	down := newHCProbeServer(t)
	down.probeRes.Store(http.StatusBadGateway)
	// ws 车道：/hc 应答探针；升级请求 hijack 回显。
	ws := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/hc" {
			w.WriteHeader(http.StatusOK)
			fmt.Fprint(w, "hc-ok")
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

	h := startHC(t, newTestHandler([]ChainUpstream{
		newHCUpstream(down, "", 0),
		{Dial: dialOf(ws)},
	}, 50, 9000, 0), hcCfg(30))
	waitLaneHealthy(t, h, 0, false)

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
	head := readHeadUntilBlank(t, conn)
	if !bytes.HasPrefix(head, []byte("HTTP/1.1 101")) {
		t.Fatalf("handshake = %q, want 101 via healthy lane (unhealthy lane not skipped)", head)
	}
	if down.bizHits.Load() != 0 {
		t.Fatalf("tunnel reached unhealthy lane: %d biz hits", down.bizHits.Load())
	}
}

// readHeadUntilBlank 逐字节读到空行（响应头结束）。
func readHeadUntilBlank(t *testing.T, conn net.Conn) []byte {
	t.Helper()
	head := make([]byte, 0, 256)
	buf := make([]byte, 1)
	for !bytes.Contains(head, []byte("\r\n\r\n")) {
		n, err := conn.Read(buf)
		if err != nil {
			t.Fatalf("read handshake (got %q): %v", head, err)
		}
		head = append(head, buf[:n]...)
	}
	return head
}

// TestHC_AllUnhealthy_RequestsStillServed 全灭不专判：全部车道 unhealthy 时
// 真实请求照常放行（防探测器误判时全站 502）。
func TestHC_AllUnhealthy_RequestsStillServed(t *testing.T) {
	a := newHCProbeServer(t)
	b := newHCProbeServer(t)
	a.probeRes.Store(http.StatusBadGateway)
	b.probeRes.Store(http.StatusBadGateway)
	h := startHC(t, newWRRHandler([]ChainUpstream{
		newHCUpstream(a, "", 1),
		newHCUpstream(b, "", 1),
	}, 50, 9000, 0), hcCfg(30))
	waitLaneHealthy(t, h, 0, false)
	waitLaneHealthy(t, h, 1, false)

	resp := do(t, h, http.MethodGet, "/", "")
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("all-unhealthy must still serve, status = %d", resp.StatusCode)
	}
	readAll(t, resp)
	if a.bizHits.Load()+b.bizHits.Load() < 1 {
		t.Fatal("all-unhealthy fallback did not reach any upstream")
	}
}

// TestHC_Cleanup_StopsProbes Cleanup 停止探测协程：停止后探针命中数不再
// 增长（done 先等后放，-race 下无泄漏）。
func TestHC_Cleanup_StopsProbes(t *testing.T) {
	s := newHCProbeServer(t)
	h := startHC(t, newWRRHandler([]ChainUpstream{newHCUpstream(s, "", 1)}, 50, 9000, 0), hcCfg(30))
	waitProbesAtLeast(t, s, 2)

	h.stopHealthMonitor()
	if h.hcState != nil {
		t.Fatal("hcState must be nil after stop")
	}
	frozen := s.probes.Load()
	time.Sleep(150 * time.Millisecond)
	if s.probes.Load() != frozen {
		t.Fatalf("probes continued after Cleanup: %d -> %d", frozen, s.probes.Load())
	}
}

// TestHC_Probe_HostSchemePathUA 探测口径：Host=回源 Host 单源（host_header
// 覆写生效）、path=配置路径、UA 标识；https 车道探测真走 TLS（r.TLS 非 nil）。
func TestHC_Probe_HostSchemePathUA(t *testing.T) {
	var gotHost, gotUA, gotPath atomic.Value
	var plainTLS, tlsSeen atomic.Bool
	plain := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotHost.Store(r.Host)
		gotUA.Store(r.Header.Get("User-Agent"))
		gotPath.Store(r.URL.Path)
		plainTLS.Store(r.TLS != nil)
		w.WriteHeader(http.StatusOK)
	}))
	t.Cleanup(plain.Close)
	tlsRec := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		tlsSeen.Store(r.TLS != nil)
		w.WriteHeader(http.StatusOK)
	}))
	t.Cleanup(tlsRec.Close)

	h := startHC(t, newWRRHandler([]ChainUpstream{
		{Dial: dialOf(plain), Host: "origin.example.com"},
		{Dial: dialOf(tlsRec), Scheme: "https"},
	}, 50, 9000, 0), hcCfg(150))

	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		if gotPath.Load() != nil && tlsSeen.Load() {
			break
		}
		time.Sleep(10 * time.Millisecond)
	}
	if gotPath.Load() == nil {
		t.Fatal("plain lane was never probed")
	}
	if !tlsSeen.Load() {
		t.Fatal("https lane was never probed over TLS")
	}
	if gotHost.Load() != "origin.example.com" {
		t.Fatalf("probe Host = %v, want origin.example.com (回源 Host 单源)", gotHost.Load())
	}
	if gotUA.Load() != hcProbeUA {
		t.Fatalf("probe UA = %v, want %v", gotUA.Load(), hcProbeUA)
	}
	if gotPath.Load() != "/hc" {
		t.Fatalf("probe path = %v, want /hc", gotPath.Load())
	}
	if plainTLS.Load() {
		t.Fatal("plain lane probe must not use TLS")
	}
	_ = h
}

// TestHC_ExpectStatus_SingleValueAndRange expect_status 判定：单值期望下
// 2xx 不达标判败、达标判愈；区间期望按闭区间判定。
func TestHC_ExpectStatus_SingleValueAndRange(t *testing.T) {
	s := newHCProbeServer(t)
	// /hc 正常返回 200；期望 204 → 不达标判败。
	h := startHC(t, newWRRHandler([]ChainUpstream{newHCUpstream(s, "", 1)}, 50, 9000, 0),
		&ChainHealthCheck{IntervalMS: 30, TimeoutMS: 500, Path: "/hc", ExpectStatus: "204", UnhealthyLag: 1, HealthyLag: 1})
	waitLaneHealthy(t, h, 0, false)

	// 期望 200-299：204 落在闭区间内判愈（同配置改区间经新 handler 验证）。
	h2 := startHC(t, newWRRHandler([]ChainUpstream{newHCUpstream(s, "", 1)}, 50, 9000, 0),
		&ChainHealthCheck{IntervalMS: 30, TimeoutMS: 500, Path: "/hc", ExpectStatus: "200-299", UnhealthyLag: 1, HealthyLag: 1})
	s.probeRes.Store(http.StatusNoContent)
	waitLaneHealthy(t, h2, 0, true)
}

// TestHC_ParseExpectStatus expect_status 解析：单值/闭区间/缺省/非法形态。
func TestHC_ParseExpectStatus(t *testing.T) {
	cases := []struct {
		in   string
		low  int
		high int
		bad  bool
	}{
		{in: "", low: 200, high: 299},
		{in: "200", low: 200, high: 200},
		{in: "200-299", low: 200, high: 299},
		{in: "404-404", low: 404, high: 404},
		{in: "500-400", bad: true}, // min>max 拒
		{in: "abc", bad: true},
		{in: "200-", bad: true},
		{in: "-299", bad: true},
	}
	for _, c := range cases {
		low, high, err := parseExpectStatus(c.in)
		if c.bad {
			if err == nil {
				t.Fatalf("parseExpectStatus(%q) = %d-%d, want error", c.in, low, high)
			}
			continue
		}
		if err != nil {
			t.Fatalf("parseExpectStatus(%q): %v", c.in, err)
		}
		if low != c.low || high != c.high {
			t.Fatalf("parseExpectStatus(%q) = %d-%d, want %d-%d", c.in, low, high, c.low, c.high)
		}
	}
}

// TestHC_BodySubstring body 期望子串：子串缺失判败、命中判愈。
func TestHC_BodySubstring(t *testing.T) {
	var marker atomic.Bool
	marker.Store(false)
	rec := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		if marker.Load() {
			fmt.Fprint(w, "all-systems-ok-marker")
		} else {
			fmt.Fprint(w, "degraded")
		}
	}))
	t.Cleanup(rec.Close)
	h := startHC(t, newWRRHandler([]ChainUpstream{{Dial: dialOf(rec)}}, 50, 9000, 0),
		&ChainHealthCheck{IntervalMS: 30, TimeoutMS: 500, Path: "/", Body: "ok-marker", UnhealthyLag: 1, HealthyLag: 1})
	waitLaneHealthy(t, h, 0, false)

	marker.Store(true)
	waitLaneHealthy(t, h, 0, true)
}

// TestHC_SlowProbe_DoesNotSlowBusiness 探测慢上游不拖慢并发业务请求
// （探测连接承载缓释判据——方案裁决 1）。
func TestHC_SlowProbe_DoesNotSlowBusiness(t *testing.T) {
	s := newHCProbeServer(t)
	s.probeRes.Store(0) // /hc 挂起（客户端 150ms 超时判败）
	h := startHC(t, newWRRHandler([]ChainUpstream{newHCUpstream(s, "", 1)}, 50, 9000, 0),
		&ChainHealthCheck{IntervalMS: 50, TimeoutMS: 150, Path: "/hc", UnhealthyLag: 1, HealthyLag: 1})

	for i := 0; i < 3; i++ {
		start := time.Now()
		resp := do(t, h, http.MethodGet, "/biz", "")
		elapsed := time.Since(start)
		if resp.StatusCode != http.StatusOK {
			t.Fatalf("biz request %d: status = %d", i, resp.StatusCode)
		}
		readAll(t, resp)
		if elapsed > time.Second {
			t.Fatalf("biz request %d took %v: slow probes are stalling business traffic", i, elapsed)
		}
	}
	if s.bizHits.Load() < 3 {
		t.Fatalf("biz hits = %d, want >= 3", s.bizHits.Load())
	}
}
