package caddygeoip

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/corazawaf/coraza/v3"
	"github.com/corazawaf/coraza/v3/experimental/plugins/plugintypes"
)

// plugintypesConfigFor 构造指向 path 的审计写插件配置（JSON 格式）。
func plugintypesConfigFor(t *testing.T, path string) plugintypes.AuditLogConfig {
	t.Helper()
	return plugintypes.AuditLogConfig{Target: path, FileMode: 0o644, Formatter: jsonFormatterForTest{}}
}

// jsonFormatterForTest 复用 coraza 内置 JSON 格式化器形态（顶层单行 JSON 对象）。
type jsonFormatterForTest struct{}

func (jsonFormatterForTest) Format(al plugintypes.AuditLog) ([]byte, error) {
	type wire struct {
		Transaction struct {
			ID string `json:"id"`
		} `json:"transaction"`
	}
	var w wire
	if al.Transaction() != nil {
		w.Transaction.ID = al.Transaction().ID()
	}
	return json.Marshal(w)
}

func (jsonFormatterForTest) MIME() string { return "application/json" }

// 审计写插件（lbfile）测试：入队/刷盘/轮转重开兼容/阻塞零丢/timing 注入。
// 写侧契约（历史）：决策→计时（请求路径，纯评估口径）→终态标记；审计
// Write 只格式化+入队（阻塞式有界队列，零丢弃）；专职 drain goroutine 等待
// per-tx 计时终态后注入 lb_timing 顶层字段并 bufio 批量刷盘。

// useTestAuditPipeline 把默认管线参数收窄到测试量级并隔离全局注册表。
func useTestAuditPipeline(t *testing.T) {
	t.Helper()
	releaseAllAuditPipelines(t)
	origQueue, origThreshold, origInterval := auditQueueSize, auditFlushThreshold, auditFlushInterval
	origWait, origPoll, origTTL := auditTimingWaitLimit, auditTimingPollStep, auditTimingEntryTTL
	auditQueueSize = 64
	auditFlushThreshold = 1
	auditFlushInterval = 5 * time.Millisecond
	auditTimingWaitLimit = 200 * time.Millisecond
	auditTimingPollStep = time.Millisecond
	auditTimingEntryTTL = 50 * time.Millisecond
	auditTimingMu.Lock()
	auditTimingEntries = make(map[string]*auditTimingEntry)
	auditTimingMu.Unlock()
	t.Cleanup(func() {
		auditQueueSize, auditFlushThreshold, auditFlushInterval = origQueue, origThreshold, origInterval
		auditTimingWaitLimit, auditTimingPollStep, auditTimingEntryTTL = origWait, origPoll, origTTL
		auditTimingMu.Lock()
		auditTimingEntries = make(map[string]*auditTimingEntry)
		auditTimingMu.Unlock()
	})
}

// waitAuditLine 轮询等待临时审计文件出现一行可解析 JSON（上限 2s）。
func waitAuditLine(t *testing.T, path string) string {
	t.Helper()
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		data, err := os.ReadFile(path)
		if err == nil {
			for _, line := range strings.Split(strings.TrimSpace(string(data)), "\n") {
				line = strings.TrimSpace(line)
				if line == "" {
					continue
				}
				if json.Valid([]byte(line)) {
					return line
				}
			}
		}
		time.Sleep(2 * time.Millisecond)
	}
	t.Fatalf("audit line did not appear in %s within 2s", path)
	return ""
}

// Given: SecAuditLogType lbfile + phase:1 deny 的 coraza WAF，请求携带 timing ID 头
// When: 事务中断 + ProcessLogging（audit Write 入队）之后才 record+close timing
//
//	——复刻生产时序（coraza-caddy 在 WAF handler 退出时 defer ProcessLogging，
//	blocked_counter 在其之后才写分段）
//
// Then: 审计行含 lb_timing.end_us=42（写 goroutine 等待迟到分段后注入，零丢弃）
func TestAuditWriter_registeredAndInjectsLateTiming(t *testing.T) {
	useTestAuditPipeline(t)
	dir := t.TempDir()
	logPath := filepath.Join(dir, "audit.log")

	waf, err := coraza.NewWAF(coraza.NewWAFConfig().WithDirectives(strings.Join([]string{
		"SecRuleEngine On",
		"SecAuditEngine RelevantOnly",
		"SecAuditLog " + logPath,
		"SecAuditLogFormat JSON",
		"SecAuditLogType lbfile",
		"SecAuditLogParts ABIJDEFHKZ",
		"SecRule REQUEST_HEADERS:X-Probe \"@streq hit\" \"id:990001,phase:1,deny,status:403,log,msg:'probe'\"",
	}, "\n")))
	if err != nil {
		t.Fatalf("coraza must accept lbfile audit writer: %v", err)
	}

	const id = "abcdef0123456789"
	tx := waf.NewTransaction()
	defer tx.Close()
	req := httptest.NewRequest(http.MethodGet, "/probe", nil)
	req.Header.Set(securityTimingHeader, id)
	req.Header.Set("X-Probe", "hit")
	tx.ProcessConnection(req.RemoteAddr, 0, "127.0.0.1", 8080)
	tx.ProcessURI(req.URL.String(), req.Method, "HTTP/1.1")
	for k, v := range req.Header {
		for _, val := range v {
			tx.AddRequestHeader(k, val)
		}
	}
	tx.ProcessRequestHeaders()
	if !tx.IsInterrupted() {
		t.Fatal("rule must interrupt")
	}
	// 生产时序：ProcessLogging（audit Write 先入队）先于计时写点。
	tx.ProcessLogging()
	// blocked_counter 同位写点：决策已出，纯评估耗时入注册表，随后终态标记。
	auditTimingRecord(id, "end", 42)
	auditTimingClose(id)

	line := waitAuditLine(t, logPath)
	var doc map[string]json.RawMessage
	if err := json.Unmarshal([]byte(line), &doc); err != nil {
		t.Fatalf("audit line not JSON: %v", err)
	}
	lb, ok := doc["lb_timing"]
	if !ok {
		t.Fatalf("lb_timing missing from audit line: %s", line)
	}
	var timing struct {
		PreUs *int64 `json:"pre_us"`
		EndUs *int64 `json:"end_us"`
	}
	if err := json.Unmarshal(lb, &timing); err != nil {
		t.Fatalf("lb_timing malformed: %v (%s)", err, lb)
	}
	if timing.EndUs == nil || *timing.EndUs != 42 {
		t.Fatalf("lb_timing.end_us = %v; want 42", timing.EndUs)
	}
	if timing.PreUs != nil {
		t.Fatalf("lb_timing.pre_us = %v; want absent", *timing.PreUs)
	}
}

// useTestAuditPipeline 追加：用例结束时排空全部测试管线（drain 退出、fd 关闭）。
func releaseAllAuditPipelines(t *testing.T) {
	t.Helper()
	t.Cleanup(func() {
		auditPipelinesMu.Lock()
		pipelines := make([]*auditPipeline, 0, len(auditPipelines))
		for _, p := range auditPipelines {
			pipelines = append(pipelines, p)
		}
		auditPipelinesMu.Unlock()
		for _, p := range pipelines {
			p.release()
		}
	})
}

// Given: 无 timing ID 头的审计事务
// Then: 审计行不含 lb_timing 字段（耗时报「—」的旧语义），且写路径不等待
func TestAuditWriter_noTimingHeaderOmitsField(t *testing.T) {
	useTestAuditPipeline(t)
	dir := t.TempDir()
	logPath := filepath.Join(dir, "audit.log")

	waf, err := coraza.NewWAF(coraza.NewWAFConfig().WithDirectives(strings.Join([]string{
		"SecRuleEngine On",
		"SecAuditEngine RelevantOnly",
		"SecAuditLog " + logPath,
		"SecAuditLogFormat JSON",
		"SecAuditLogType lbfile",
		"SecRule REQUEST_HEADERS:X-Probe \"@streq hit\" \"id:990002,phase:1,deny,status:403,log,msg:'probe'\"",
	}, "\n")))
	if err != nil {
		t.Fatalf("NewWAF: %v", err)
	}
	tx := waf.NewTransaction()
	defer tx.Close()
	req := httptest.NewRequest(http.MethodGet, "/probe", nil)
	tx.ProcessConnection(req.RemoteAddr, 0, "127.0.0.1", 8080)
	tx.ProcessURI(req.URL.String(), req.Method, "HTTP/1.1")
	tx.AddRequestHeader("X-Probe", "hit")
	tx.ProcessRequestHeaders()
	if !tx.IsInterrupted() {
		t.Fatal("rule must interrupt")
	}
	start := time.Now()
	tx.ProcessLogging()
	if time.Since(start) > 100*time.Millisecond {
		t.Fatalf("ProcessLogging waited %v without timing header; must skip wait", time.Since(start))
	}

	line := waitAuditLine(t, logPath)
	if strings.Contains(line, "lb_timing") {
		t.Fatalf("lb_timing must be omitted without timing header: %s", line)
	}
}

// Given: 有界队列（容量 2）且 drain 未消费
// When: 先同步填满 2 条，再异步入队第 3 条
// Then: 第 3 条阻塞等待（零丢弃），drain 启动后完成——退化价=现状同步写
func TestAuditPipeline_enqueueBlocksWhenFullZeroDrop(t *testing.T) {
	useTestAuditPipeline(t)
	p := &auditPipeline{
		target: filepath.Join(t.TempDir(), "audit.log"),
		queue:  make(chan lbAuditItem, 2),
		done:   make(chan struct{}),
	}
	if err := p.openFile(0o644); err != nil {
		t.Fatalf("open: %v", err)
	}

	// 同步填满队列（无 drain 消费）
	p.enqueue(lbAuditItem{body: []byte(`{"a":1}`)})
	p.enqueue(lbAuditItem{body: []byte(`{"b":2}`)})

	// 第 3 条异步入队：队列满必须阻塞（而非丢弃/报错）
	thirdDone := make(chan struct{})
	go func() {
		p.enqueue(lbAuditItem{body: []byte(`{"c":3}`)})
		close(thirdDone)
	}()
	select {
	case <-thirdDone:
		t.Fatal("third enqueue completed while queue full; must block (zero-drop backpressure)")
	case <-time.After(50 * time.Millisecond):
	}

	// drain 启动消化 → 阻塞的第三条最终入队成功（零丢弃）
	go p.drain()
	select {
	case <-thirdDone:
	case <-time.After(2 * time.Second):
		t.Fatal("blocked enqueue never completed after drain started")
	}
	p.release()
}

// Given: 管线持有长生命周期 fd
// When: 轮转侧 copytruncate（文件被截断，inode 不变）后再写
// Then: 新行落在截断后的文件头（O_APPEND 语义），无需重开 fd——与
//
//	internal/services rotateAuditLogIfNeeded 的 copytruncate 契约配对
func TestAuditPipeline_copytruncateCompatible(t *testing.T) {
	useTestAuditPipeline(t)
	dir := t.TempDir()
	logPath := filepath.Join(dir, "audit.log")
	w := &lbAuditWriter{}
	if err := w.Init(plugintypesConfigFor(t, logPath)); err != nil {
		t.Fatalf("Init: %v", err)
	}
	// 直接 enqueue 无 tid 条目（不注入），验证纯刷盘链路
	w.pipeline.enqueue(lbAuditItem{body: []byte(`{"n":1}`)})
	line1 := waitAuditLine(t, logPath)
	if !strings.Contains(line1, `"n":1`) {
		t.Fatalf("first line = %s", line1)
	}
	if err := os.Truncate(logPath, 0); err != nil {
		t.Fatal(err)
	}
	w.pipeline.enqueue(lbAuditItem{body: []byte(`{"n":2}`)})
	deadline := time.Now().Add(2 * time.Second)
	var data []byte
	for time.Now().Before(deadline) {
		data, _ = os.ReadFile(logPath)
		if strings.Contains(string(data), `"n":2`) {
			break
		}
		time.Sleep(2 * time.Millisecond)
	}
	if !strings.Contains(string(data), `"n":2`) {
		t.Fatalf("post-truncate write lost: %q", data)
	}
	if strings.Contains(string(data), `"n":1`) {
		t.Fatal("pre-truncate content must not reappear after copytruncate")
	}
	if err := w.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
}

// Given: 目标路径目录缺失
// When: Init
// Then: 返回错误（/load 拒收，与 serial writer 同 fail-fast 语义），后续 Write 零 panic
func TestAuditWriter_initFailureFailsFast(t *testing.T) {
	useTestAuditPipeline(t)
	w := &lbAuditWriter{}
	err := w.Init(plugintypesConfigFor(t, filepath.Join(t.TempDir(), "missing-dir", "audit.log")))
	if err == nil {
		t.Fatal("Init must fail on unwritable target (fail-fast /load rejection)")
	}
	if wErr := w.Write(nil); wErr != nil {
		t.Fatalf("Write after failed Init must be silent no-op, got %v", wErr)
	}
}

// injectAuditTiming 单元钉：pre/end 独立注入、缺席省略、0 值保留、畸形 JSON 原样返回。
func TestInjectAuditTiming(t *testing.T) {
	// 双段注入
	out := injectAuditTiming([]byte(`{"transaction":{"id":"a"}}`), auditTimingSnapshot{preUs: 7, preSet: true, endUs: 42, endSet: true})
	var doc map[string]json.RawMessage
	if err := json.Unmarshal(out, &doc); err != nil {
		t.Fatal(err)
	}
	var timing struct {
		PreUs *int64 `json:"pre_us"`
		EndUs *int64 `json:"end_us"`
	}
	if err := json.Unmarshal(doc["lb_timing"], &timing); err != nil {
		t.Fatal(err)
	}
	if timing.PreUs == nil || *timing.PreUs != 7 || timing.EndUs == nil || *timing.EndUs != 42 {
		t.Fatalf("timing = %+v; want pre=7 end=42", timing)
	}

	// 单段注入（pre 缺席）
	out = injectAuditTiming([]byte(`{"k":1}`), auditTimingSnapshot{endUs: 5, endSet: true})
	doc = nil
	_ = json.Unmarshal(out, &doc)
	timing = struct {
		PreUs *int64 `json:"pre_us"`
		EndUs *int64 `json:"end_us"`
	}{}
	_ = json.Unmarshal(doc["lb_timing"], &timing)
	if timing.PreUs != nil || timing.EndUs == nil || *timing.EndUs != 5 {
		t.Fatalf("single-segment injection wrong: %s", out)
	}

	// 0 值必须保留（0µs 是合法计时）
	out = injectAuditTiming([]byte(`{}`), auditTimingSnapshot{preUs: 0, preSet: true})
	if !strings.Contains(string(out), `"pre_us":0`) {
		t.Fatalf("zero timing dropped: %s", out)
	}

	// 空 snapshot 不注入
	out = injectAuditTiming([]byte(`{"k":1}`), auditTimingSnapshot{})
	if string(out) != `{"k":1}` {
		t.Fatalf("empty snapshot must return body unchanged, got %s", out)
	}

	// 畸形 JSON 原样返回（不注入不 panic）
	bad := []byte(`not-json`)
	if out := injectAuditTiming(bad, auditTimingSnapshot{preUs: 1, preSet: true}); string(out) != string(bad) {
		t.Fatalf("malformed JSON must be returned unchanged, got %s", out)
	}
}

// 注册表钉：record→wait（未终态，超时返回部分快照）→close→wait 立即返回完整快照。
func TestAuditTimingRegistry_recordWaitClose(t *testing.T) {
	useTestAuditPipeline(t)
	const id = "0123456789abcdef"

	// 未创建条目时 wait 超时返回空快照（不阻塞超限）
	start := time.Now()
	snap := auditTimingWait(id, 30*time.Millisecond)
	if time.Since(start) < 25*time.Millisecond {
		t.Fatal("wait for unknown entry must honor timeout")
	}
	if snap.preSet || snap.endSet {
		t.Fatalf("unknown entry must yield empty snapshot: %+v", snap)
	}

	auditTimingRecord(id, "pre", 11)
	// 未终态：wait 走满超时并返回部分快照（pre 在场）
	snap = auditTimingWait(id, 30*time.Millisecond)
	if !snap.preSet || snap.preUs != 11 || snap.closed {
		t.Fatalf("partial snapshot = %+v; want pre=11 unclosed", snap)
	}

	auditTimingRecord(id, "end", 22)
	auditTimingClose(id)
	start = time.Now()
	snap = auditTimingWait(id, time.Second)
	if time.Since(start) > 100*time.Millisecond {
		t.Fatal("closed entry must return immediately")
	}
	if !snap.closed || snap.preUs != 11 || snap.endUs != 22 || !snap.preSet || !snap.endSet {
		t.Fatalf("final snapshot = %+v; want closed pre=11 end=22", snap)
	}

	// 空 ID 短路
	if snap := auditTimingWait("", time.Millisecond); snap.preSet || snap.endSet {
		t.Fatal("empty id must short-circuit")
	}
	auditTimingRecord("", "pre", 1)
	auditTimingClose("")
}

// 注册表清理钉：TTL 过期条目在批量写入点被清扫，新条目保留（无界增长防线）。
func TestAuditTimingRegistry_sweep(t *testing.T) {
	useTestAuditPipeline(t)
	const stale = "aaaaaaaaaaaaaaaa"
	auditTimingRecord(stale, "pre", 1)
	// 强制 stale 条目超龄
	auditTimingMu.Lock()
	auditTimingEntries[stale].created = time.Now().Add(-time.Hour)
	auditTimingMu.Unlock()

	for i := range 128 { // 跨过 sweep 周期（64）多批
		auditTimingRecord(fmt.Sprintf("bbbbbbbbbbbbbb%03d", i), "pre", int64(i))
	}

	auditTimingMu.Lock()
	_, staleExists := auditTimingEntries[stale]
	count := len(auditTimingEntries)
	auditTimingMu.Unlock()
	if staleExists {
		t.Fatal("expired entry must be swept")
	}
	if count < 100 {
		t.Fatalf("recent entries must survive sweep, got %d", count)
	}
}

// timing ID 提取钉：大小写不敏感、多值取首、缺失空串。
func TestSecurityTimingIDFromHeaders(t *testing.T) {
	got := securityTimingIDFromHeaders(map[string][]string{
		"X-Lb-Security-Timing-Id": {"abc123"},
		"Other":                   {"x"},
	})
	if got != "abc123" {
		t.Fatalf("got %q", got)
	}
	if got := securityTimingIDFromHeaders(map[string][]string{"x-lb-security-timing-id": {"low"}}); got != "low" {
		t.Fatalf("case-insensitive lookup failed: %q", got)
	}
	if got := securityTimingIDFromHeaders(map[string][]string{"Other": {"x"}}); got != "" {
		t.Fatalf("missing header must be empty, got %q", got)
	}
}
