package caddygeoip

import (
	"net/http"
	"net/http/httptest"
	"strconv"
	"testing"
	"time"

	"github.com/caddyserver/caddy/v2/modules/caddyhttp"
)

// 计时注册表契约测试（第 76 轮：侧车退役，耗时写入进程内
// 注册表，由审计写插件注入审计行——写侧三写点的行为钉）。

// useTestTimingRegistry 隔离全局注册表并收窄等待参数到测试量级。
func useTestTimingRegistry(t *testing.T) {
	t.Helper()
	origWait, origPoll := auditTimingWaitLimit, auditTimingPollStep
	auditTimingWaitLimit = 200 * time.Millisecond
	auditTimingPollStep = time.Millisecond
	auditTimingMu.Lock()
	auditTimingEntries = make(map[string]*auditTimingEntry)
	auditTimingMu.Unlock()
	t.Cleanup(func() {
		auditTimingWaitLimit, auditTimingPollStep = origWait, origPoll
		auditTimingMu.Lock()
		auditTimingEntries = make(map[string]*auditTimingEntry)
		auditTimingMu.Unlock()
	})
}

// auditTimingLookup 测试取值 helper。
func auditTimingLookupForTest(t *testing.T, id string) auditTimingSnapshot {
	t.Helper()
	auditTimingMu.Lock()
	e := auditTimingEntries[id]
	auditTimingMu.Unlock()
	if e == nil {
		return auditTimingSnapshot{}
	}
	e.mu.Lock()
	defer e.mu.Unlock()
	return auditTimingSnapshot{preUs: e.preUs, preSet: e.preSet, endUs: e.endUs, endSet: e.endSet, closed: e.closed}
}

// Given: 正常调用
// When: securityTimingID
// Then: 16 字符 hex(8 字节;F62-29 扩容后)
func TestSecurityTimingID_length(t *testing.T) {
	id := securityTimingID()
	if len(id) != 16 {
		t.Errorf("len=%d; want 16 (8 bytes hex)", len(id))
	}
	for _, c := range id {
		if !(c >= '0' && c <= '9' || c >= 'a' && c <= 'f') {
			t.Errorf("non-hex char %q in %q", c, id)
		}
	}
}

// PLUG-R1（第 69 轮 P4）：security_timing_pre/end 两 ServeHTTP 逐字重复收敛为
// recordSecurityTiming helper——钉 helper 契约：合法头对写一段注册表耗时，
// 缺头对零写入（静默降级语义不变）。
func TestRecordSecurityTiming_writesRegistrySegment(t *testing.T) {
	useTestTimingRegistry(t)

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.Header.Set(securityTimingHeader, "abcdef0123456789")
	req.Header.Set(securityTimingStartHeader, strconv.FormatInt(time.Now().UnixNano()-12345000, 10))

	// When
	recordSecurityTiming(req, timingSegmentPre)

	// Then：注册表出现 pre 段且耗时为正整数（12ms 前起算）
	snap := auditTimingLookupForTest(t, "abcdef0123456789")
	if !snap.preSet || snap.preUs <= 0 {
		t.Fatalf("snapshot = %+v; want positive pre segment", snap)
	}

	// And 畸形形状：缺头对的请求零写入
	recordSecurityTiming(httptest.NewRequest(http.MethodGet, "/", nil), timingSegmentEnd)
	snapAfter := auditTimingLookupForTest(t, "abcdef0123456789")
	if snapAfter.endSet {
		t.Fatalf("missing headers must write nothing: %+v", snapAfter)
	}

	// And 降级形态：计时 ID 生成失败（空头值）零写入
	req2 := httptest.NewRequest(http.MethodGet, "/", nil)
	req2.Header.Set(securityTimingHeader, "")
	recordSecurityTiming(req2, timingSegmentPre)
	if got := auditTimingLookupForTest(t, ""); got.preSet {
		t.Fatal("empty id must short-circuit")
	}
}

// 第 75 轮（预检拦耗时口径）：分段锚点交接契约——timing_pre 放行路径在记录
// pre 后，把起始纳秒头重写为「预检完成」锚点。下游 SecurityTimingEnd 的 end
// 自此从预检后起算（WAF 段值）；blocked_counter 以「起始头是否仍等于注入原值」
// 判定拦截出处（原值=预检段拦，头未动 → 写 pre 决策耗时；已重写=WAF/限流段
// 拦 → 写 end 全链）。放行形态：pre 段落注册表 + 头已重写为更大纳秒值。
func TestSecurityTimingPre_passAnchorsSegmentViaHeaderRewrite(t *testing.T) {
	useTestTimingRegistry(t)
	h := &SecurityTimingPre{}
	const id = "abcdef0123456789"
	startNs := time.Now().UnixNano()
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.Header.Set(securityTimingHeader, id)
	req.Header.Set(securityTimingStartHeader, strconv.FormatInt(startNs, 10))
	next := caddyhttp.HandlerFunc(func(http.ResponseWriter, *http.Request) error { return nil })

	// When
	if err := h.ServeHTTP(httptest.NewRecorder(), req, next); err != nil {
		t.Fatalf("ServeHTTP: %v", err)
	}

	// Then：pre 段落注册表（放行口径不变）
	snap := auditTimingLookupForTest(t, id)
	if !snap.preSet || snap.preUs <= 0 {
		t.Fatalf("snapshot = %+v; want positive pre segment", snap)
	}
	// And：起始头重写为分段锚点（严格晚于注入值；下游 end/WAF 段由此起算）
	rewritten, perr := strconv.ParseInt(req.Header.Get(securityTimingStartHeader), 10, 64)
	if perr != nil || rewritten <= startNs {
		t.Fatalf("start header = %q; want rewritten to ns > %d (segment anchor)",
			req.Header.Get(securityTimingStartHeader), startNs)
	}
	// And：ID 头保持（审计写插件的注册表关联键不受锚点交接影响）
	if req.Header.Get(securityTimingHeader) != id {
		t.Fatalf("timing id header = %q; want %q (audit correlation)", req.Header.Get(securityTimingHeader), id)
	}
}

// 第 75 轮：畸形形态——缺关联头对的请求零写入、零改写、不 panic（静默降级）。
func TestSecurityTimingPre_missingHeadersNoop(t *testing.T) {
	useTestTimingRegistry(t)
	h := &SecurityTimingPre{}
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	next := caddyhttp.HandlerFunc(func(http.ResponseWriter, *http.Request) error { return nil })

	if err := h.ServeHTTP(httptest.NewRecorder(), req, next); err != nil {
		t.Fatalf("ServeHTTP: %v", err)
	}

	if len(auditTimingEntriesSnapshotForTest(t)) != 0 {
		t.Error("missing headers must not write registry entries")
	}
	if req.Header.Get(securityTimingStartHeader) != "" {
		t.Error("missing headers must not set segment anchor header")
	}
}

// logged 事件链末收点：timing_end 读重写后的锚点计算 end 段（自锚点起算=WAF
// 段值），原样透传下游。
func TestSecurityTimingEnd_recordsEndSegmentFromAnchor(t *testing.T) {
	useTestTimingRegistry(t)
	h := &SecurityTimingEnd{}
	const id = "0123456789abcdef"
	anchor := time.Now().UnixNano() - 5_000_000 // 锚点 5ms 前（timing_pre 已交接）
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.Header.Set(securityTimingHeader, id)
	req.Header.Set(securityTimingStartHeader, strconv.FormatInt(anchor, 10))
	passed := false
	next := caddyhttp.HandlerFunc(func(http.ResponseWriter, *http.Request) error { passed = true; return nil })

	if err := h.ServeHTTP(httptest.NewRecorder(), req, next); err != nil {
		t.Fatalf("ServeHTTP: %v", err)
	}
	if !passed {
		t.Fatal("next must be invoked (pass-through)")
	}
	snap := auditTimingLookupForTest(t, id)
	if !snap.endSet || snap.endUs < 5 {
		t.Fatalf("snapshot = %+v; want end segment ≥5ms (from anchor)", snap)
	}
	if snap.closed {
		t.Fatal("timing_end must not close the entry (terminal marker owned by blocked_counter)")
	}
}

func auditTimingEntriesSnapshotForTest(t *testing.T) map[string]*auditTimingEntry {
	t.Helper()
	auditTimingMu.Lock()
	defer auditTimingMu.Unlock()
	out := make(map[string]*auditTimingEntry, len(auditTimingEntries))
	for id, e := range auditTimingEntries {
		out[id] = e
	}
	return out
}
