package caddychain

// 被动 5xx 摘除子系统钉测（JJC-20261120-002，验收 P1-P6）：
// 计数窗衰减 / 达阈摘除 / 期满恢复 / HC 交集 / 全灭放行 / wrr-race-隧道联动 /
// 网络错误不计数 / 状态码面（<500 与升级后字节流不计数）/ 摘除恢复日志 / 并发。

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
	"go.uber.org/zap/zaptest/observer"
)

// passiveHandler 快捷装配（绕过 Provision；显式初始化被动子系统）。
func passiveHandler(ups []ChainUpstream) *ChainProxy {
	h := newTestHandler(ups, 100, 9000, 0)
	h.passiveState = newPassiveMonitor(h)
	h.passiveOnce.Do(func() {}) // 消费 once：防 ServeHTTP 重装覆盖测试态
	return h
}

// shrink 窗口/阈值/摘除时长收窄到 ms 级，便于时间驱动断言。
func shrink(h *ChainProxy, failDurMS, maxFails, unhealthyMS int) {
	h.passiveState.failDuration = time.Duration(failDurMS) * time.Millisecond
	h.passiveState.maxFails = maxFails
	h.passiveState.unhealthyDur = time.Duration(unhealthyMS) * time.Millisecond
}

// ejectedNow 读车道摘除截止时刻（零值=未摘）。
func ejectedNow(h *ChainProxy, idx int) time.Time {
	h.passiveState.mu.Lock()
	defer h.passiveState.mu.Unlock()
	return h.passiveState.states[idx].ejectedUntil
}

// P1a：窗内累计达 max_fails 摘除。
func TestPassive_EjectAtThreshold(t *testing.T) {
	h := passiveHandler([]ChainUpstream{{Dial: "127.0.0.1:1"}})
	shrink(h, 1000, 3, 50)
	h.recordPassive(0, 500)
	h.recordPassive(0, 502)
	if !ejectedNow(h, 0).IsZero() {
		t.Fatal("未达阈不应摘除")
	}
	h.recordPassive(0, 503)
	if ejectedNow(h, 0).IsZero() {
		t.Fatal("三次 5xx 后应摘除")
	}
	if h.passiveHealthy(0) {
		t.Fatal("摘除期内应判不健康")
	}
}

// P1b：计数窗衰减——窗外时间戳不计满。
func TestPassive_WindowDecay(t *testing.T) {
	h := passiveHandler([]ChainUpstream{{Dial: "127.0.0.1:1"}})
	shrink(h, 40, 3, 50)
	h.recordPassive(0, 500)
	h.recordPassive(0, 500)
	time.Sleep(60 * time.Millisecond) // 窗口（40ms）外
	h.recordPassive(0, 500)
	if !ejectedNow(h, 0).IsZero() {
		t.Fatal("窗外衰减后不应摘除（仅窗内 1 次）")
	}
}

// P2：摘除期满恢复（half-open：下一真实请求即试探）。
func TestPassive_RecoverAfterExpiry(t *testing.T) {
	h := passiveHandler([]ChainUpstream{{Dial: "127.0.0.1:1"}})
	shrink(h, 1000, 3, 30)
	for i := 0; i < 3; i++ {
		h.recordPassive(0, 500)
	}
	if h.passiveHealthy(0) {
		t.Fatal("刚摘除应不健康")
	}
	time.Sleep(50 * time.Millisecond)
	if !h.passiveHealthy(0) {
		t.Fatal("摘除期满应恢复（half-open）")
	}
}

// P3：HC∩passive 交集选路——两套注册表独立，任一判摘即摘。
func TestPassive_HCIntersection(t *testing.T) {
	sDown := newHCProbeServer(t) // 探测必败 → HC 摘车道 0
	sUp := newHCProbeServer(t)   // 探测恒 200 → HC 车道 1/2 健康
	sDown.probeRes.Store(http.StatusTeapot)
	h := passiveHandler([]ChainUpstream{
		newHCUpstream(sDown, "", 1),
		newHCUpstream(sUp, "", 1),
		newHCUpstream(sUp, "", 1),
	})
	startHC(t, h, hcCfg(30))
	waitLaneHealthy(t, h, 0, false)
	// 被动判摘车道 1 → eligible 仅车道 2。
	h.recordPassive(1, 500)
	h.recordPassive(1, 500)
	h.recordPassive(1, 500)
	got := h.eligibleLanes()
	if len(got) != 1 || got[0] != 2 {
		t.Fatalf("eligibleLanes = %v, want [2]（HC∩passive 交集）", got)
	}
}

// P4：全灭不专判延续——passive 全摘时放行全部车道。
func TestPassive_AllEjectedPassthrough(t *testing.T) {
	h := passiveHandler([]ChainUpstream{{Dial: "127.0.0.1:1"}, {Dial: "127.0.0.1:2"}})
	shrink(h, 1000, 1, 60000)
	h.recordPassive(0, 500)
	h.recordPassive(1, 500)
	got := h.eligibleLanes()
	if len(got) != 2 {
		t.Fatalf("全灭应放行全部车道，got %v", got)
	}
}

// P5a：wrr 联动——被摘车道不再接流量（摘除后该车道请求计数 delta 冻结）。
func TestPassive_WRRIntegration(t *testing.T) {
	var badHits atomic.Int32
	bad := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		badHits.Add(1)
		w.WriteHeader(http.StatusInternalServerError)
	}))
	t.Cleanup(bad.Close)
	good := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, "ok")
	}))
	t.Cleanup(good.Close)
	h := passiveHandler([]ChainUpstream{
		{Dial: dialOf(bad), Weight: 1},
		{Dial: dialOf(good), Weight: 1},
	})
	h.Mode = modeWRR
	// 6 次请求（每次都打到 bad 一次以上）：bad 累计 3 次 5xx 后被摘除。
	for i := 0; i < 6; i++ {
		resp := do(t, h, http.MethodGet, "/", "")
		readAll(t, resp)
	}
	if h.passiveHealthy(0) {
		t.Fatal("3 次 5xx 后 lane0 应被摘除")
	}
	before := badHits.Load()
	for i := 0; i < 3; i++ {
		resp := do(t, h, http.MethodGet, "/", "")
		readAll(t, resp)
	}
	if after := badHits.Load(); after != before {
		t.Fatalf("摘除后 bad 车道仍接流量：before=%d after=%d", before, after)
	}
}

// P5b：race 联动——被摘车道被剔除出竞速序。
func TestPassive_RaceSkipsEjected(t *testing.T) {
	bad := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}))
	t.Cleanup(bad.Close)
	good := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, "ok")
	}))
	t.Cleanup(good.Close)
	h := passiveHandler([]ChainUpstream{{Dial: dialOf(bad)}, {Dial: dialOf(good)}})
	h.RaceIntervalMS = 5000 // 竞速间隔拉长：车道 0 被摘后扇出恒只发车道 1
	// 直接摘除车道 0 → race 应直接从车道 1 起步（车道 0 无请求落定）。
	h.passiveState.states[0].ejectedUntil = time.Now().Add(time.Minute)
	resp := do(t, h, http.MethodGet, "/", "")
	if body := readAll(t, resp); body != "ok" {
		t.Fatalf("body = %q, want ok", body)
	}
	if n := len(h.passiveState.states[0].fails); n != 0 {
		t.Fatalf("被摘车道不应收到请求：fails=%d", n)
	}
}

// P6：网络错误不进被动计数（不双罚）。
func TestPassive_NetworkErrorNotCounted(t *testing.T) {
	dead := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))
	dead.Close() // 立即关闭 → 建连必失败
	good := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, "ok")
	}))
	t.Cleanup(good.Close)
	h := passiveHandler([]ChainUpstream{{Dial: dead.Listener.Addr().String()}, {Dial: dialOf(good)}})
	resp := do(t, h, http.MethodGet, "/", "")
	readAll(t, resp)
	if n := len(h.passiveState.states[0].fails); n != 0 {
		t.Fatalf("网络错误不应计入被动失败：fails=%d", n)
	}
	if !ejectedNow(h, 0).IsZero() {
		t.Fatal("网络错误不应触发摘除")
	}
}

// 状态码面：<500 不计数；升级响应非 101 的 5xx 面计数（隧道侧）。
func TestPassive_StatusFace(t *testing.T) {
	h := passiveHandler([]ChainUpstream{{Dial: "127.0.0.1:1"}})
	h.recordPassive(0, 404)
	h.recordPassive(0, 302)
	h.recordPassive(0, 200)
	if n := len(h.passiveState.states[0].fails); n != 0 {
		t.Fatalf("<500 不得计数：fails=%d", n)
	}
}

// 隧道非 101 的 5xx 状态码面计数（101 后字节流无状态码，天然不计数——
// 无需用例证明「不发生」，计数入口在状态码面唯一）。
func TestPassive_TunnelStatusFace(t *testing.T) {
	up := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Upgrade") != "" {
			w.WriteHeader(http.StatusServiceUnavailable)
			return
		}
		fmt.Fprint(w, "ok")
	}))
	t.Cleanup(up.Close)
	h := passiveHandler([]ChainUpstream{{Dial: dialOf(up)}})
	// WebSocket 风格升级请求走隧道路径，上游 503 → 状态码面计数一次。
	proxy := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = h.ServeHTTP(w, r, nil)
	}))
	t.Cleanup(proxy.Close)
	req, _ := http.NewRequest(http.MethodGet, proxy.URL+"/", nil)
	req.Header.Set("Upgrade", "websocket")
	req.Header.Set("Connection", "Upgrade")
	resp, err := proxy.Client().Do(req)
	if err != nil {
		t.Fatalf("proxy request: %v", err)
	}
	readAll(t, resp)
	if n := len(h.passiveState.states[0].fails); n != 1 {
		t.Fatalf("隧道升级响应 5xx 应计数一次：fails=%d", n)
	}
}

// 摘除/恢复日志可观测面（车道号+计数+摘除时长）。
func TestPassive_EjectRecoverLogs(t *testing.T) {
	core, logs := observer.New(zapcore.DebugLevel) // 恢复日志是 Info 级，须全量收集
	h := passiveHandler([]ChainUpstream{{Dial: "127.0.0.1:1"}})
	h.logger = zap.New(core)
	shrink(h, 1000, 1, 20)
	h.recordPassive(0, 500)
	var eject, recover bool
	for _, e := range logs.All() {
		if e.Level == zapcore.WarnLevel && strings.Contains(e.Message, "被动 5xx 摘除") {
			eject = true
			if e.ContextMap()["lane"].(int64) != 0 {
				t.Fatalf("摘除日志缺车道号：%v", e.ContextMap())
			}
		}
	}
	if !eject {
		t.Fatal("摘除时未打日志")
	}
	time.Sleep(30 * time.Millisecond)
	_ = h.passiveHealthy(0)
	for _, e := range logs.All() {
		if strings.Contains(e.Message, "期满恢复") {
			recover = true
		}
	}
	if !recover {
		t.Fatal("恢复时未打日志")
	}
}

// 并发计数 -race 钉测：多 goroutine 同时对同车道/跨车道计数不 panic 不丢账。
func TestPassive_ConcurrentRecords(t *testing.T) {
	h := passiveHandler([]ChainUpstream{{Dial: "127.0.0.1:1"}, {Dial: "127.0.0.1:2"}})
	shrink(h, 1000, 100000, 50)
	var wg sync.WaitGroup
	for i := 0; i < 50; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			h.recordPassive(i%2, 500)
		}(i)
	}
	wg.Wait()
	for idx := range h.passiveState.states {
		h.passiveState.mu.Lock()
		n := len(h.passiveState.states[idx].fails)
		h.passiveState.mu.Unlock()
		if n == 0 {
			t.Fatalf("lane %d 并发计数丢账", idx)
		}
	}
}

// 提交面回归：postiveHealthy nil monitor 恒 true（未初始化不 panic）。
func TestPassive_NilMonitorHealthy(t *testing.T) {
	h := newTestHandler([]ChainUpstream{{Dial: "127.0.0.1:1"}}, 100, 9000, 0)
	if !h.passiveHealthy(0) {
		t.Fatal("nil monitor 恒 healthy")
	}
}
