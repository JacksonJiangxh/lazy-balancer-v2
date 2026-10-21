package caddygeoip

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/corazawaf/coraza/v3"
	"github.com/corazawaf/coraza/v3/experimental/plugins"
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

// fullJSONFormatter 与 coraza 内置 JSON 格式化器同形（json.Marshal 直出完整
// 信封）——用于核对快照→drain 链路的完整字段面（transaction/messages/headers/
// body 全部经快照消费）。
type fullJSONFormatter struct{}

func (fullJSONFormatter) Format(al plugintypes.AuditLog) ([]byte, error) {
	return json.Marshal(al)
}

func (fullJSONFormatter) MIME() string { return "application/json" }

// blockingFormatter 首次 Format 阻塞至 release 关闭——钉「格式化已移出请求
// 路径」：若 Write 仍在请求路径同步格式化，ProcessLogging 将无法在超时内返回。
// 经 plugins.RegisterAuditLogFormatter 装入被测 WAF 的 SecAuditLogFormat（同
// lbfence 模式）——只有挂进 coraza 真实写路径，栅栏与调用计数才有意义
// （历史问题：挂在手工创建、WAF 从不使用的 writer 上时栅栏失效）。
// calls 计数钉「栅栏确在写路径」——formatter 未被调用即布线失效，确定性红。
type blockingFormatter struct {
	release chan struct{}
	calls   atomic.Int32
}

func (f *blockingFormatter) Format(al plugintypes.AuditLog) ([]byte, error) {
	f.calls.Add(1)
	<-f.release
	return json.Marshal(al)
}

func (*blockingFormatter) MIME() string { return "application/json" }

// lbfenceFormatter 历史修复（历史）测试同步栅栏：Format 阻塞至 release 关闭，
// 放行后按 json.Marshal 直出（信封与内置 JSON 格式化器一致，见 auditSnapshot
// 注释）。经 plugins.RegisterAuditLogFormatter 注册为专用格式名 lbfence、由
// 被测指令 SecAuditLogFormat lbfence 装入 coraza 写路径——drain 侧 process
// 先 Format 后查计时注册表，栅栏把「主 goroutine 完成 record+close」定序在
// drain 查表之前，消除迟到注入钉测对 goroutine 调度序的依赖（修复前：drain
// 抢先完成格式化+首轮查表未命中 → auditTimingWait 未知 tid 即返 → lb_timing
// 缺失 → 断言随机红）。
type lbfenceFormatter struct {
	release chan struct{}
}

func (f *lbfenceFormatter) Format(al plugintypes.AuditLog) ([]byte, error) {
	<-f.release
	return json.Marshal(al)
}

func (*lbfenceFormatter) MIME() string { return "application/json" }

// cannedFormatter 忽略审计内容返回固定正文——管线级测试（阻塞/轮转）无需构造
// 完整 AuditLog（plugintypes 接口的 Args 返回类型是 coraza 内部类型，测试无法
// 合成），只验证入队/刷盘语义。
type cannedFormatter struct{ body []byte }

func (f cannedFormatter) Format(plugintypes.AuditLog) ([]byte, error) { return f.body, nil }

func (cannedFormatter) MIME() string { return "application/json" }

// 审计写插件（lbfile）测试：入队/刷盘/轮转重开兼容/阻塞零丢/timing 注入。
// 写侧契约（历史）：决策→计时（请求路径，纯评估口径）→终态标记；审计
// Write 只格式化+入队（阻塞式有界队列，零丢弃）；专职 drain goroutine 等待
// per-tx 计时终态后注入 lb_timing 顶层字段并 bufio 批量刷盘。

// useTestAuditPipeline 把默认管线参数收窄到测试量级并隔离全局注册表。
// 清理顺序（t.Cleanup LIFO）：先注册「恢复全局参数」，后注册「收尾全部
// 管线」——执行时 drain 先退出（closeTestAuditPipelines 等 p.done），再恢复
// auditFlushThreshold/auditTiming* 全局值；逆序会在 drain 仍读这些变量时
// 写入（-race 实测：cleanup 恢复 vs appendLine/process 读，历史验证期暴露）。
func useTestAuditPipeline(t *testing.T) {
	t.Helper()
	origQueue, origThreshold, origInterval := auditQueueSize, auditFlushThreshold, auditFlushInterval
	origWait, origPoll := auditTimingWaitLimit, auditTimingPollStep
	origTTL := auditTimingEntryTTLNs.Load()
	auditQueueSize = 64
	auditFlushThreshold = 1
	auditFlushInterval = 5 * time.Millisecond
	auditTimingWaitLimit = 200 * time.Millisecond
	auditTimingPollStep = time.Millisecond
	auditTimingEntryTTLNs.Store(int64(50 * time.Millisecond))
	auditTimingMu.Lock()
	resetAuditTimingRegistryLockedForTest()
	auditTimingMu.Unlock()
	t.Cleanup(func() {
		auditQueueSize, auditFlushThreshold, auditFlushInterval = origQueue, origThreshold, origInterval
		auditTimingWaitLimit, auditTimingPollStep = origWait, origPoll
		auditTimingEntryTTLNs.Store(origTTL)
		auditTimingMu.Lock()
		resetAuditTimingRegistryLockedForTest()
		auditTimingMu.Unlock()
	})
	closeTestAuditPipelines(t)
}

// resetAuditTimingRegistryLockedForTest 清空计时注册表全部状态（调用方持
// auditTimingMu）——条目/建条 FIFO/游标/清扫计数一并复位，避免测试间串扰。
func resetAuditTimingRegistryLockedForTest() {
	auditTimingEntries = make(map[string]*auditTimingEntry)
	auditTimingOrder = nil
	auditTimingHead = 0
	auditTimingCreateCount = 0
	auditTimingPollCountForTest.Store(0)
	auditTimingSweepVisitsForTest.Store(0)
}

// seedAuditTimingEntryForTest 以指定建条时刻直接种入条目（含 FIFO 项——
// 与生产建条路径同形，保证清扫不变量成立）。
func seedAuditTimingEntryForTest(id string, created time.Time) {
	auditTimingMu.Lock()
	auditTimingEntries[id] = &auditTimingEntry{created: created}
	auditTimingOrder = append(auditTimingOrder, auditTimingQueueEntry{id: id, created: created})
	auditTimingMu.Unlock()
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

	// 历史修复（历史）同步栅栏：drain 侧 Format 点阻塞至主 goroutine 完成
	// 「迟到分段 record+close」后放行——生产时序（Write 入队严格早于计时写点，
	// coraza defer ProcessLogging 契约）原样保持，drain 查表被定序在写点之后，
	// 断言不再依赖调度序。已知取舍窗口（与 auditTimingWait 的 历史修复 注释同源，
	// 此处钉明）：生产中 drain 抢先完成格式化并首轮查表的极小竞态窗内的行不
	// 注入 lb_timing（耗时属增强信息，展示层报「—」，可接受）；本钉测锚定的
	// 契约是「行到 drain 时终态已置位 → 必注入」，栅栏使该契约确定性成立。
	fence := &lbfenceFormatter{release: make(chan struct{})}
	plugins.RegisterAuditLogFormatter("lbfence", fence)

	waf, err := coraza.NewWAF(coraza.NewWAFConfig().WithDirectives(strings.Join([]string{
		"SecRuleEngine On",
		"SecAuditEngine RelevantOnly",
		"SecAuditLog " + logPath,
		"SecAuditLogFormat lbfence",
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
	// 栅栏放行：drain 此刻才执行 Format→查表，必见已终态条目（保序，零调度依赖）。
	close(fence.release)

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

// useTestAuditPipeline 追加：用例结束时收尾全部测试管线（drain 退出、fd 关闭）。
// 生产路径没有这条通道（管线是进程级单例，见 acquireAuditPipeline）；测试侧
// 先把管线摘出注册表再关队列，保证收尾之后不再有新生产者（writer.Close 只刷盘
// 不拆管线）。
func closeTestAuditPipelines(t *testing.T) {
	t.Helper()
	t.Cleanup(func() {
		auditPipelinesMu.Lock()
		pipelines := make([]*auditPipeline, 0, len(auditPipelines))
		for _, p := range auditPipelines {
			pipelines = append(pipelines, p)
		}
		auditPipelines = map[string]*auditPipeline{}
		auditPipelinesMu.Unlock()
		for _, p := range pipelines {
			close(p.queue)
			<-p.done
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
	auditTimingPollCountForTest.Store(0)
	tx.ProcessLogging()

	line := waitAuditLine(t, logPath)
	// 历史修复 零轮询钉替代挂钟阈值——无计时头行 id 为空，auditTimingWait
	// 短路返回，drain 全程零轮询（旧轮询实现此处恒 >0）。
	if n := auditTimingPollCountForTest.Load(); n != 0 {
		t.Fatalf("no timing header must skip wait entirely: drain polled %d times", n)
	}
	if strings.Contains(line, "lb_timing") {
		t.Fatalf("lb_timing must be omitted without timing header: %s", line)
	}
}

// Given: 审计行携带 timing ID 头但注册表无该条目（未知 tid：陈旧行积压超 TTL
//
//	被清扫/写点缺失异常行），等待上限收窄到可观测量级（200ms，useTestAuditPipeline）
//
// When: 事务入队（ProcessLogging）→ drain 侧处理
// Then: 行落盘且 drain 全程零轮询（旧行为轮询满上限 200ms/步 1ms 恒约 200 次，
//
//	零轮询钉对其必红），且不注入 lb_timing——历史修复 钉：未知 tid 不阻塞单
//	drain goroutine（积压行批量到场时逐行满等=无背压阀下的 drain 沉陷，
//	请求路径被入队阻塞拖住）
func TestAuditPipeline_unknownTidDoesNotBlockDrain(t *testing.T) {
	useTestAuditPipeline(t)
	dir := t.TempDir()
	logPath := filepath.Join(dir, "audit.log")

	waf, err := coraza.NewWAF(coraza.NewWAFConfig().WithDirectives(strings.Join([]string{
		"SecRuleEngine On",
		"SecAuditEngine RelevantOnly",
		"SecAuditLog " + logPath,
		"SecAuditLogFormat JSON",
		"SecAuditLogType lbfile",
		"SecRule REQUEST_HEADERS:X-Probe \"@streq hit\" \"id:990003,phase:1,deny,status:403,log,msg:'probe'\"",
	}, "\n")))
	if err != nil {
		t.Fatalf("NewWAF: %v", err)
	}

	// timing ID 头在场（16 字符生产形态）但注册表无条目——不 record 不 close
	const orphanTID = "0000000000000000"
	auditTimingPollCountForTest.Store(0)
	driveProbeTx(t, waf, orphanTID)
	line := waitAuditLine(t, logPath)
	// 历史修复 零轮询钉替代挂钟阈值——行落盘时 drain 的等待已完成，
	// 未知 tid 首轮查表未命中即返（零轮询）；旧行为轮询满 200ms 上限
	// （poll step 1ms → 恒约 200 次），本断言对旧实现必红。
	if n := auditTimingPollCountForTest.Load(); n != 0 {
		t.Fatalf("unknown tid must not block drain (AUD-1): drain polled %d times, want 0", n)
	}
	if strings.Contains(line, "lb_timing") {
		t.Fatalf("unknown tid must inject nothing: %s", line)
	}
}

// waitAuditLines 轮询等待临时审计文件出现至少 n 行可解析 JSON（上限 2s）。
func waitAuditLines(t *testing.T, path string, n int) []string {
	t.Helper()
	deadline := time.Now().Add(2 * time.Second)
	var lines []string
	for time.Now().Before(deadline) {
		data, err := os.ReadFile(path)
		if err == nil {
			lines = lines[:0]
			for _, line := range strings.Split(strings.TrimSpace(string(data)), "\n") {
				line = strings.TrimSpace(line)
				if line != "" && json.Valid([]byte(line)) {
					lines = append(lines, line)
				}
			}
			if len(lines) >= n {
				return lines
			}
		}
		time.Sleep(2 * time.Millisecond)
	}
	t.Fatalf("expected %d audit lines in %s within 2s, got %d", n, path, len(lines))
	return nil
}

// driveProbeTx 驱动一次 phase:1 deny 事务（X-Probe=hit 规则），复刻生产时序：
// ProcessLogging（审计 Write）先于调用方计时写点。返回事务 ID。
func driveProbeTx(t *testing.T, waf coraza.WAF, timingID string) string {
	t.Helper()
	tx := waf.NewTransaction()
	defer tx.Close()
	req := httptest.NewRequest(http.MethodGet, "/probe", nil)
	if timingID != "" {
		req.Header.Set(securityTimingHeader, timingID)
	}
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
	tx.ProcessLogging()
	return tx.ID()
}

// Given: 快照化写侧（Write 只构建快照入队，drain 侧格式化）+ phase:2 body 规则
// When: ProcessLogging（入队）→ tx.Close（变量集合 reset+事务归还池——live 引用
//
//	污染源）→ 计时终态 → 才放行 drain 侧格式化
//
// Then: 审计行完整（transaction.id/unix_timestamp/client_ip/server_id/method/
//
//	uri/headers/body/messages.data.id 全部为 Close 前的值）且含 lb_timing——
//	入队后改原（Close reset）不影响输出；且 ProcessLogging 未被格式化阻塞。
func TestAuditWriter_snapshotSurvivesTxCycle(t *testing.T) {
	useTestAuditPipeline(t)
	dir := t.TempDir()
	logPath := filepath.Join(dir, "audit.log")

	// 历史问题：栅栏 formatter 必须经注册名装入被测 WAF 的
	// SecAuditLogFormat（lbfence 同模式）——旧实现把它挂在手工创建、WAF
	// 从不使用的 writer 上（WAF 自建 lbfile writer 用 JSON 格式化器），
	// 栅栏永不触发，「ProcessLogging 未被格式化阻塞」恒真、计时注入依赖
	// 调度序偶发红。calls 计数把布线失效变成确定性红。
	fmtr := &blockingFormatter{release: make(chan struct{})}
	plugins.RegisterAuditLogFormatter("lbsnapfmt", fmtr)

	waf, err := coraza.NewWAF(coraza.NewWAFConfig().WithDirectives(strings.Join([]string{
		"SecRuleEngine On",
		"SecRequestBodyAccess On",
		"SecAuditEngine RelevantOnly",
		"SecAuditLog " + logPath,
		"SecAuditLogFormat lbsnapfmt",
		"SecAuditLogType lbfile",
		"SecAuditLogParts ABCIJDEFHKZ",
		"SecRule ARGS:payload \"@streq hit\" \"id:990003,phase:2,deny,status:403,log,msg:'probe-body'\"",
	}, "\n")))
	if err != nil {
		t.Fatalf("NewWAF: %v", err)
	}

	const id = "abcdef0123456789"
	tx := waf.NewTransaction()
	defer tx.Close()
	tx.SetServerName("example.com")
	req := httptest.NewRequest(http.MethodPost, "/probe", nil)
	req.Header.Set(securityTimingHeader, id)
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	tx.ProcessConnection(req.RemoteAddr, 0, "127.0.0.1", 8080)
	tx.ProcessURI(req.URL.String(), req.Method, "HTTP/1.1")
	for k, v := range req.Header {
		for _, val := range v {
			tx.AddRequestHeader(k, val)
		}
	}
	tx.ProcessRequestHeaders()
	if _, n, err := tx.WriteRequestBody([]byte("payload=hit")); err != nil || n != len("payload=hit") {
		t.Fatalf("WriteRequestBody: n=%d err=%v", n, err)
	}
	if intr, err := tx.ProcessRequestBody(); err != nil || intr == nil {
		t.Fatalf("rule must interrupt body phase: intr=%v err=%v", intr, err)
	}
	txID := tx.ID()

	// 生产时序：ProcessLogging（审计 Write 入队）不能被格式化阻塞——格式化
	// 已移出请求路径。
	logged := make(chan struct{})
	go func() {
		tx.ProcessLogging()
		close(logged)
	}()
	select {
	case <-logged:
	case <-time.After(2 * time.Second):
		t.Fatal("ProcessLogging blocked in formatter.Format — formatting still on request path")
	}

	// 改原：tx.Close reset 变量集合（headers/body 归零、事务归还 sync.Pool），
	// 随后计时终态，最后才放行 drain 侧格式化。
	tx.Close()
	auditTimingRecord(id, "end", 77)
	auditTimingClose(id)
	close(fmtr.release)

	line := waitAuditLine(t, logPath)
	var doc struct {
		Transaction struct {
			ID            string `json:"id"`
			UnixTimestamp int64  `json:"unix_timestamp"`
			ClientIP      string `json:"client_ip"`
			ServerID      string `json:"server_id"`
			IsInterrupted bool   `json:"is_interrupted"`
			Request       struct {
				Method  string              `json:"method"`
				URI     string              `json:"uri"`
				Headers map[string][]string `json:"headers"`
				Body    string              `json:"body"`
			} `json:"request"`
		} `json:"transaction"`
		Messages []struct {
			Message string `json:"message"`
			Data    struct {
				ID  int    `json:"id"`
				Raw string `json:"raw"`
			} `json:"data"`
		} `json:"messages"`
		LbTiming struct {
			Pre *int64 `json:"pre_us"`
			End *int64 `json:"end_us"`
		} `json:"lb_timing"`
	}
	if err := json.Unmarshal([]byte(line), &doc); err != nil {
		t.Fatalf("audit line not JSON: %v (%s)", err, line)
	}
	if doc.Transaction.ID != txID {
		t.Fatalf("transaction.id = %q; want %q", doc.Transaction.ID, txID)
	}
	if doc.Transaction.UnixTimestamp == 0 {
		t.Fatal("transaction.unix_timestamp missing")
	}
	if doc.Transaction.ClientIP == "" || doc.Transaction.ServerID == "" {
		t.Fatalf("client_ip/server_id missing: %+v", doc.Transaction)
	}
	if !doc.Transaction.IsInterrupted {
		t.Fatal("transaction.is_interrupted must be true (deny)")
	}
	if doc.Transaction.Request.Method != http.MethodPost || doc.Transaction.Request.URI != "/probe" {
		t.Fatalf("request line = %s %s", doc.Transaction.Request.Method, doc.Transaction.Request.URI)
	}
	if got := securityTimingIDFromHeaders(doc.Transaction.Request.Headers); got != id {
		t.Fatalf("timing header missing from snapshot headers: %v (got %q)", doc.Transaction.Request.Headers, got)
	}
	if doc.Transaction.Request.Body != "payload=hit" {
		t.Fatalf("request body polluted by tx.Close: %q", doc.Transaction.Request.Body)
	}
	if len(doc.Messages) == 0 || doc.Messages[0].Data.ID != 990003 || !strings.Contains(doc.Messages[0].Data.Raw, "ARGS:payload") {
		t.Fatalf("messages incomplete: %+v", doc.Messages)
	}
	if doc.LbTiming.End == nil || *doc.LbTiming.End != 77 {
		t.Fatalf("lb_timing.end_us = %v; want 77", doc.LbTiming.End)
	}
	// 栅栏确实挂在 WAF 写路径（drain 侧格式化恰好一次）：0=布线失效
	// （历史问题 旧形态，上述阻塞/计时断言全部形同虚设）。
	if n := fmtr.calls.Load(); n != 1 {
		t.Fatalf("fence formatter invocations = %d; want exactly 1 on the WAF write path", n)
	}
}

// captureFormatter 捕获 coraza 交给写路径的审计对象（快照）并按 JSON 直出。
type captureFormatter struct{ ch chan plugintypes.AuditLog }

func (f *captureFormatter) Format(al plugintypes.AuditLog) ([]byte, error) {
	select {
	case f.ch <- al:
	default:
	}
	return json.Marshal(al)
}

func (*captureFormatter) MIME() string { return "application/json" }

func TestSnapshotAuditBody_capAndBoundaries(t *testing.T) {
	tests := []struct {
		name      string
		body      string
		wantLen   int
		truncated bool
		marker    bool
	}{
		{name: "small body unchanged", body: "payload=hit", wantLen: len("payload=hit")},
		{name: "exact limit unchanged", body: strings.Repeat("x", auditBodyMaxBytes), wantLen: auditBodyMaxBytes},
		// 目标形状：超限文本 = 前缀 64KiB + 显式截断标记（写侧与读侧上限相等，
		// 读侧无法凭长度判断截断——历史问题 契约，标记 15 字节超出上限部分）。
		{name: "over limit truncated", body: strings.Repeat("x", auditBodyMaxBytes+1), wantLen: auditBodyMaxBytes + len("\n...[TRUNCATED]"), truncated: true, marker: true},
		// 畸形形状：前缀含非法 UTF-8 时不追加标记（会破坏读侧 base64 判定），
		// 只保留 64KiB 前缀。
		{name: "over limit binary no marker", body: strings.Repeat("x", 100) + "\xff" + strings.Repeat("y", auditBodyMaxBytes), wantLen: auditBodyMaxBytes, truncated: true},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got, truncated := snapshotAuditBody(tc.body)
			if len(got) != tc.wantLen || truncated != tc.truncated {
				t.Fatalf("len=%d truncated=%v, want len=%d truncated=%v", len(got), truncated, tc.wantLen, tc.truncated)
			}
			prefix := got
			if tc.marker {
				if !strings.HasSuffix(got, "\n...[TRUNCATED]") {
					t.Fatalf("truncated text body must carry the explicit marker: ...%q", got[len(got)-24:])
				}
				prefix = strings.TrimSuffix(got, "\n...[TRUNCATED]")
			}
			if prefix != tc.body[:len(prefix)] {
				t.Fatal("captured body must preserve the original prefix")
			}
		})
	}
}

// 大请求体经真实 coraza phase:2 命中后，快照与 JSON 行只能保留有界前缀，
// 并显式携带截断标记；不能把工作区/队列/格式化链放大到原始 body 大小。
func TestAuditWriter_requestBodyCapAndTruncationMarker(t *testing.T) {
	useTestAuditPipeline(t)
	capture := &captureFormatter{ch: make(chan plugintypes.AuditLog, 1)}
	plugins.RegisterAuditLogFormatter("lbcap", capture)
	logPath := filepath.Join(t.TempDir(), "audit.log")
	waf, err := coraza.NewWAF(coraza.NewWAFConfig().WithDirectives(strings.Join([]string{
		"SecRuleEngine On",
		"SecRequestBodyAccess On",
		"SecAuditEngine RelevantOnly",
		"SecAuditLog " + logPath,
		"SecAuditLogFormat lbcap",
		"SecAuditLogType lbfile",
		"SecAuditLogParts ABCIJDEFHKZ",
		"SecRule ARGS:payload \"@streq hit\" \"id:990005,phase:2,deny,status:403,log,msg:'probe-large-body'\"",
	}, "\n")))
	if err != nil {
		t.Fatalf("NewWAF: %v", err)
	}

	body := "payload=hit&pad=" + strings.Repeat("x", auditBodyMaxBytes+32)
	tx := waf.NewTransaction()
	defer tx.Close()
	req := httptest.NewRequest(http.MethodPost, "/probe-large", nil)
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	tx.ProcessConnection(req.RemoteAddr, 0, "127.0.0.1", 8080)
	tx.ProcessURI(req.URL.String(), req.Method, "HTTP/1.1")
	for k, v := range req.Header {
		for _, val := range v {
			tx.AddRequestHeader(k, val)
		}
	}
	tx.ProcessRequestHeaders()
	if _, n, err := tx.WriteRequestBody([]byte(body)); err != nil || n != len(body) {
		t.Fatalf("WriteRequestBody: n=%d err=%v", n, err)
	}
	if intr, err := tx.ProcessRequestBody(); err != nil || intr == nil {
		t.Fatalf("rule must interrupt large body phase: intr=%v err=%v", intr, err)
	}
	tx.ProcessLogging()

	var al plugintypes.AuditLog
	select {
	case al = <-capture.ch:
	case <-time.After(2 * time.Second):
		t.Fatal("large-body audit snapshot was not captured")
	}
	sr, ok := al.Transaction().Request().(*auditSnapshotRequest)
	if !ok {
		t.Fatalf("snapshot request type = %T", al.Transaction().Request())
	}
	// 契约（历史问题）：快照体 = 原始前缀 64KiB + 显式标记 \n...[TRUNCATED]。
	wantPrefix := body[:auditBodyMaxBytes]
	if got := sr.Body(); got != wantPrefix+"\n...[TRUNCATED]" {
		t.Fatalf("snapshot body must be the %d-byte prefix plus truncation marker (len=%d)", auditBodyMaxBytes, len(got))
	}
	if !sr.BodyTruncated_ {
		t.Fatal("oversized snapshot body must carry the truncation marker")
	}
	line, err := json.Marshal(al)
	if err != nil {
		t.Fatalf("marshal capped audit snapshot: %v", err)
	}
	var wire struct {
		Transaction struct {
			Request struct {
				Body          string `json:"body"`
				BodyTruncated bool   `json:"body_truncated"`
			} `json:"request"`
		} `json:"transaction"`
	}
	if err := json.Unmarshal(line, &wire); err != nil {
		t.Fatalf("audit line not JSON: %v", err)
	}
	if wire.Transaction.Request.Body != wantPrefix+"\n...[TRUNCATED]" || !wire.Transaction.Request.BodyTruncated {
		t.Fatalf("serialized body len=%d truncated=%v", len(wire.Transaction.Request.Body), wire.Transaction.Request.BodyTruncated)
	}
}

// 历史问题：审计响应体快照与请求体同上限（64KiB 前缀 + 显式截断标记 +
// body_truncated 标记位，JSON 契约对称）。check-response 策略形态
// （SecResponseBodyAccess On + SecAuditLogParts 恒含 E）下 coraza 默认
// SecResponseBodyLimit=512KiB，无快照侧硬限时单条审计行可携带约 512KiB
// 响应体——2048 深队列内存放大 + 落盘放大。真实 coraza phase:4 命中验证。
func TestAuditWriter_responseBodyCapAndTruncationMarker(t *testing.T) {
	useTestAuditPipeline(t)
	capture := &captureFormatter{ch: make(chan plugintypes.AuditLog, 1)}
	plugins.RegisterAuditLogFormatter("lbrespcap", capture)
	logPath := filepath.Join(t.TempDir(), "audit.log")
	waf, err := coraza.NewWAF(coraza.NewWAFConfig().WithDirectives(strings.Join([]string{
		"SecRuleEngine On",
		"SecResponseBodyAccess On",
		"SecResponseBodyMimeType text/plain",
		"SecAuditEngine RelevantOnly",
		"SecAuditLog " + logPath,
		"SecAuditLogFormat lbrespcap",
		"SecAuditLogType lbfile",
		"SecAuditLogParts ABIJDEFHKZ",
		"SecRule RESPONSE_BODY \"@rx leak\" \"id:990006,phase:4,deny,status:403,log,msg:'probe-resp-body'\"",
	}, "\n")))
	if err != nil {
		t.Fatalf("NewWAF: %v", err)
	}

	body := "leak:" + strings.Repeat("y", auditBodyMaxBytes+64)
	tx := waf.NewTransaction()
	defer tx.Close()
	req := httptest.NewRequest(http.MethodGet, "/probe-resp", nil)
	tx.ProcessConnection(req.RemoteAddr, 0, "127.0.0.1", 8080)
	tx.ProcessURI(req.URL.String(), req.Method, "HTTP/1.1")
	tx.ProcessRequestHeaders()
	tx.AddResponseHeader("Content-Type", "text/plain")
	tx.ProcessResponseHeaders(200, "HTTP/1.1")
	if _, n, err := tx.WriteResponseBody([]byte(body)); err != nil || n != len(body) {
		t.Fatalf("WriteResponseBody: n=%d err=%v", n, err)
	}
	if intr, err := tx.ProcessResponseBody(); err != nil || intr == nil {
		t.Fatalf("rule must interrupt response phase: intr=%v err=%v", intr, err)
	}
	tx.ProcessLogging()

	var al plugintypes.AuditLog
	select {
	case al = <-capture.ch:
	case <-time.After(2 * time.Second):
		t.Fatal("response-body audit snapshot was not captured")
	}
	sresp, ok := al.Transaction().Response().(*auditSnapshotResponse)
	if !ok {
		t.Fatalf("snapshot response type = %T", al.Transaction().Response())
	}
	wantPrefix := body[:auditBodyMaxBytes]
	if got := sresp.Body(); got != wantPrefix+"\n...[TRUNCATED]" {
		t.Fatalf("response snapshot body must be the %d-byte prefix plus truncation marker (len=%d)", auditBodyMaxBytes, len(got))
	}
	line, err := json.Marshal(al)
	if err != nil {
		t.Fatalf("marshal capped response snapshot: %v", err)
	}
	var wire struct {
		Transaction struct {
			Response struct {
				Body          string `json:"body"`
				BodyTruncated bool   `json:"body_truncated"`
			} `json:"response"`
		} `json:"transaction"`
	}
	if err := json.Unmarshal(line, &wire); err != nil {
		t.Fatalf("audit line not JSON: %v", err)
	}
	if wire.Transaction.Response.Body != wantPrefix+"\n...[TRUNCATED]" || !wire.Transaction.Response.BodyTruncated {
		t.Fatalf("serialized response body len=%d truncated=%v", len(wire.Transaction.Response.Body), wire.Transaction.Response.BodyTruncated)
	}

	// 回归形状：未超限响应体原样保留、无截断标记位（同测试第二事务）。
	tx2 := waf.NewTransaction()
	defer tx2.Close()
	tx2.ProcessConnection(req.RemoteAddr, 0, "127.0.0.1", 8080)
	tx2.ProcessURI(req.URL.String(), req.Method, "HTTP/1.1")
	tx2.ProcessRequestHeaders()
	tx2.AddResponseHeader("Content-Type", "text/plain")
	tx2.ProcessResponseHeaders(200, "HTTP/1.1")
	if _, _, err := tx2.WriteResponseBody([]byte("leak:small")); err != nil {
		t.Fatalf("WriteResponseBody small: %v", err)
	}
	if intr, err := tx2.ProcessResponseBody(); err != nil || intr == nil {
		t.Fatalf("small response must interrupt: intr=%v err=%v", intr, err)
	}
	tx2.ProcessLogging()
	select {
	case al = <-capture.ch:
	case <-time.After(2 * time.Second):
		t.Fatal("small response audit snapshot was not captured")
	}
	sresp2, ok := al.Transaction().Response().(*auditSnapshotResponse)
	if !ok {
		t.Fatalf("snapshot response type = %T", al.Transaction().Response())
	}
	if got := sresp2.Body(); got != "leak:small" {
		t.Fatalf("small response body must pass through unchanged, got len=%d", len(got))
	}
}

// 历史问题：审计快照的 Args() 提升源必须是「冻结」接口值（同动态类型
// typed-nil），不得引用 coraza 事务活对象——drain 侧格式化恒晚于 tx.Close，
// 活引用在事务回池复用后会读到下一请求的参数。冻结后 Args() 返回空集合。
func TestAuditSnapshotRequest_argsFrozen(t *testing.T) {
	useTestAuditPipeline(t)
	dir := t.TempDir()
	logPath := filepath.Join(dir, "audit.log")

	capture := &captureFormatter{ch: make(chan plugintypes.AuditLog, 4)}
	plugins.RegisterAuditLogFormatter("lbcapture", capture)

	waf, err := coraza.NewWAF(coraza.NewWAFConfig().WithDirectives(strings.Join([]string{
		"SecRuleEngine On",
		"SecRequestBodyAccess On",
		"SecAuditEngine RelevantOnly",
		"SecAuditLog " + logPath,
		"SecAuditLogFormat lbcapture",
		"SecAuditLogType lbfile",
		"SecAuditLogParts ABCIJDEFHKZ",
		"SecRule ARGS:payload \"@streq hit\" \"id:990004,phase:2,deny,status:403,log,msg:'probe-body'\"",
	}, "\n")))
	if err != nil {
		t.Fatalf("NewWAF: %v", err)
	}

	tx := waf.NewTransaction()
	defer tx.Close()
	req := httptest.NewRequest(http.MethodPost, "/probe", nil)
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	tx.ProcessConnection(req.RemoteAddr, 0, "127.0.0.1", 8080)
	tx.ProcessURI(req.URL.String(), req.Method, "HTTP/1.1")
	for k, v := range req.Header {
		for _, val := range v {
			tx.AddRequestHeader(k, val)
		}
	}
	tx.ProcessRequestHeaders()
	if _, n, err := tx.WriteRequestBody([]byte("payload=hit")); err != nil || n != len("payload=hit") {
		t.Fatalf("WriteRequestBody: n=%d err=%v", n, err)
	}
	if intr, err := tx.ProcessRequestBody(); err != nil || intr == nil {
		t.Fatalf("rule must interrupt body phase: intr=%v err=%v", intr, err)
	}
	tx.ProcessLogging()

	var al plugintypes.AuditLog
	select {
	case al = <-capture.ch:
	case <-time.After(2 * time.Second):
		t.Fatal("audit snapshot was not captured")
	}
	// 快照已在 tx 存活时构建：此刻冻结形态已生效（不是等 tx.Close 后才成立）。
	snapshotReq := al.Transaction().Request()
	sr, ok := snapshotReq.(*auditSnapshotRequest)
	if !ok {
		t.Fatalf("snapshot request type = %T", snapshotReq)
	}
	embedded := sr.AuditLogTransactionRequest
	if embedded == nil {
		t.Fatal("embedded args source must be present for interface promotion")
	}
	if rv := reflect.ValueOf(embedded); !rv.IsNil() {
		t.Fatalf("embedded request must be a typed-nil freeze, got live %T", embedded)
	}
	args := snapshotReq.Args()
	if args == nil {
		t.Fatal("frozen Args() must return an empty collection (coraza nil-receiver branch)")
	}
	if got := args.Get("payload"); len(got) != 0 {
		t.Fatalf("frozen Args() leaked request arguments: %v", got)
	}
	// 回归形状：其余字段仍来自自持快照。
	if snapshotReq.Body() != "payload=hit" || snapshotReq.Method() != http.MethodPost {
		t.Fatalf("snapshot body/method drifted: %q %q", snapshotReq.Body(), snapshotReq.Method())
	}
}

// Given: writer.Close() 被调用（coraza v3.8.1 实际从不调用它）
// When: 之后继续 Write
// Then: 管线不拆——同 target 仍返回同一实例、drain 仍在跑，行照常经 drain
// 注入计时后落盘（审计事件不因收尾语义丢失，也不退化为同步直写）。
func TestAuditWriter_closeKeepsProcessSingletonPipeline(t *testing.T) {
	useTestAuditPipeline(t)
	dir := t.TempDir()
	logPath := filepath.Join(dir, "audit.log")

	cfg := plugintypesConfigFor(t, logPath)
	cfg.Formatter = fullJSONFormatter{}
	w := &lbAuditWriter{}
	if err := w.Init(cfg); err != nil {
		t.Fatalf("Init: %v", err)
	}
	pipeline := w.pipeline
	waf, err := coraza.NewWAF(coraza.NewWAFConfig().WithDirectives(strings.Join([]string{
		"SecRuleEngine On",
		"SecAuditEngine RelevantOnly",
		"SecAuditLog " + logPath,
		"SecAuditLogFormat JSON",
		"SecAuditLogType lbfile",
		"SecRule REQUEST_HEADERS:X-Probe \"@streq hit\" \"id:990004,phase:1,deny,status:403,log,msg:'probe'\"",
	}, "\n")))
	if err != nil {
		t.Fatalf("NewWAF: %v", err)
	}

	const id1 = "1111111111111111"
	const id2 = "2222222222222222"
	id1Tx := driveProbeTx(t, waf, id1)
	auditTimingRecord(id1, "end", 42)
	auditTimingClose(id1)
	lines := waitAuditLines(t, logPath, 1)
	if !strings.Contains(lines[0], id1Tx) {
		t.Fatalf("first row = %s", lines[0])
	}

	if err := w.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}

	// Then：同 target 再取仍是同一实例，drain 未退出（进程级单例）。
	again, err := acquireAuditPipeline(logPath, cfg.FileMode)
	if err != nil {
		t.Fatalf("acquire after Close: %v", err)
	}
	if again != pipeline {
		t.Fatal("Close must not tear down the process-level pipeline")
	}
	select {
	case <-pipeline.done:
		t.Fatal("drain goroutine exited after Close")
	default:
	}

	// 关闭后写入：仍由活 drain 消费并注入计时（注入在 drain 侧等待终态）。
	auditTimingRecord(id2, "end", 7)
	auditTimingClose(id2)
	id2Tx := driveProbeTx(t, waf, id2)
	if err := w.Write(nil); err != nil {
		t.Fatalf("Write(nil) must be no-op, got %v", err)
	}

	lines = waitAuditLines(t, logPath, 2)
	var sawID2Timing bool
	for _, line := range lines {
		if strings.Contains(line, id2Tx) {
			if !strings.Contains(line, `"end_us":7`) {
				t.Fatalf("row after Close missing injected timing: %s", line)
			}
			sawID2Timing = true
		}
	}
	if !sawID2Timing {
		t.Fatalf("row written after Close was dropped: %v", lines)
	}
}

// Given: 有界队列（容量 2）且 drain 未消费
// When: 先同步填满 2 条，再异步入队第 3 条
// Then: 第 3 条阻塞等待（零丢弃），drain 启动后完成——退化价=退役前 serial 同步写
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
	p.enqueue(lbAuditItem{snap: &auditSnapshot{}, formatter: cannedFormatter{body: []byte(`{"a":1}`)}})
	p.enqueue(lbAuditItem{snap: &auditSnapshot{}, formatter: cannedFormatter{body: []byte(`{"b":2}`)}})

	// 第 3 条异步入队：队列满必须阻塞（而非丢弃/报错）
	thirdDone := make(chan struct{})
	go func() {
		p.enqueue(lbAuditItem{snap: &auditSnapshot{}, formatter: cannedFormatter{body: []byte(`{"c":3}`)}})
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
	// 测试收尾：关闭队列让 drain 排空后退出（生产路径无此通道）。
	close(p.queue)
	<-p.done
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
	w.pipeline.enqueue(lbAuditItem{snap: &auditSnapshot{}, formatter: cannedFormatter{body: []byte(`{"n":1}`)}})
	line1 := waitAuditLine(t, logPath)
	if !strings.Contains(line1, `"n":1`) {
		t.Fatalf("first line = %s", line1)
	}
	if err := os.Truncate(logPath, 0); err != nil {
		t.Fatal(err)
	}
	w.pipeline.enqueue(lbAuditItem{snap: &auditSnapshot{}, formatter: cannedFormatter{body: []byte(`{"n":2}`)}})
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

	// 历史修复（历史）：未知 tid（注册表无条目）首轮即返空快照——不轮询到超时
	// （旧行为本断言必红：轮询走满超时）。条目稍后创建也不追加等待（预检拦行
	// 的微秒级建条窗口由 drain 侧格式化先行吸收，见 auditTimingWait 注释）。
	// 历史修复 零轮询钉替代挂钟阈值（CI 负载抖动下挂钟断言会假红）。
	auditTimingPollCountForTest.Store(0)
	snap := auditTimingWait(id, 30*time.Millisecond)
	if n := auditTimingPollCountForTest.Load(); n != 0 {
		t.Fatalf("unknown entry must return immediately without polling (AUD-1), polls=%d", n)
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
	auditTimingPollCountForTest.Store(0)
	snap = auditTimingWait(id, time.Second)
	if n := auditTimingPollCountForTest.Load(); n != 0 {
		t.Fatalf("closed entry must return on first read without polling, polls=%d", n)
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
	seedAuditTimingEntryForTest(stale, time.Now().Add(-time.Hour))

	for i := range 128 { // 跨过 sweep 周期（64）多批
		auditTimingRecord(fmt.Sprintf("bbbbbbbbbbbb%04x", i), "pre", int64(i))
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

func TestAuditTimingRegistry_sweepClosesWaitedEntry(t *testing.T) {
	useTestAuditPipeline(t)
	const id = "cccccccccccccccc"
	seedAuditTimingEntryForTest(id, time.Now().Add(-time.Hour))

	result := make(chan auditTimingSnapshot, 1)
	go func() {
		result <- auditTimingWait(id, 30*time.Millisecond)
	}()
	// 等到 wait 已取出条目指针并完成首轮未终态读取，再从注册表清扫；
	// 旧实现只 delete 不置 closed，wait 只能轮询到超时并返回未终态快照。
	deadline := time.Now().Add(time.Second)
	for auditTimingPollCountForTest.Load() == 0 && time.Now().Before(deadline) {
		time.Sleep(time.Millisecond)
	}
	if auditTimingPollCountForTest.Load() == 0 {
		t.Fatal("wait did not observe the seeded unclosed entry")
	}
	auditTimingMu.Lock()
	auditTimingSweepLocked(time.Now())
	_, exists := auditTimingEntries[id]
	auditTimingMu.Unlock()
	if exists {
		t.Fatal("expired entry must still be removed from the registry")
	}

	select {
	case snap := <-result:
		if !snap.closed {
			t.Fatalf("swept entry returned unclosed after wait timeout: %+v", snap)
		}
	case <-time.After(time.Second):
		t.Fatal("wait did not finish after its entry was swept")
	}
}

// 历史问题：清扫成本必须随「过期条目数」增长，而不是注册表规模——旧实现
// 每 64 次建条全表 map 扫描（O(n)，n≈TTL×RPS ⇒ CPU 随 RPS² 增长）。
func TestAuditTimingRegistry_sweepCostIsIncremental(t *testing.T) {
	useTestAuditPipeline(t)
	auditTimingEntryTTLNs.Store(int64(time.Hour)) // 焦点在清扫检查量，不让新条目过期

	const expired = 100
	base := time.Now().Add(-2 * time.Hour)
	for i := range expired {
		seedAuditTimingEntryForTest(fmt.Sprintf("%016x", i), base)
	}
	const fresh = 5000
	for i := range fresh {
		auditTimingRecord(fmt.Sprintf("%016x", 0x10000+i), "pre", 0)
	}

	auditTimingMu.Lock()
	entries := len(auditTimingEntries)
	auditTimingMu.Unlock()
	if entries < fresh {
		t.Fatalf("fresh entries must survive, got %d", entries)
	}
	// 期间触发约 fresh/64≈78 次清扫：检查量 ≈ 过期条目数 + 每次一条未过期队首。
	// 旧实现每次全表扫描 ⇒ 约 Σn/64 ≈ 19 万次检查。
	if visits := auditTimingSweepVisitsForTest.Load(); visits > expired+2*(fresh/64) {
		t.Fatalf("sweep visited %d queue entries; want O(expired) not O(registry)", visits)
	}
}

// 历史问题：close 不再建条（未知 tid 的 drain 首轮即返，close 建条只占 TTL
// 条目）；已有条目照常置终态。
func TestAuditTimingClose_requiresExistingEntry(t *testing.T) {
	useTestAuditPipeline(t)
	auditTimingClose("dddddddddddddddd")

	auditTimingMu.Lock()
	_, created := auditTimingEntries["dddddddddddddddd"]
	count := len(auditTimingEntries)
	auditTimingMu.Unlock()
	if created || count != 0 {
		t.Fatalf("close must not create entries, got %d entries", count)
	}

	auditTimingRecord("eeeeeeeeeeeeeeee", "pre", 5)
	auditTimingClose("eeeeeeeeeeeeeeee")
	if snap := auditTimingLookupForTest(t, "eeeeeeeeeeeeeeee"); !snap.closed {
		t.Fatal("close must mark an existing entry as terminal")
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

type failingFormatter struct{}

func (failingFormatter) Format(plugintypes.AuditLog) ([]byte, error) {
	return nil, fmt.Errorf("injected format failure")
}
func (failingFormatter) MIME() string { return "application/json" }

func TestAuditDrain_ioErrorSurfacedAndReopens(t *testing.T) {
	var mu sync.Mutex
	var logs []string
	oldLog := auditIOLogf
	auditIOLogf = func(format string, args ...any) {
		mu.Lock()
		logs = append(logs, fmt.Sprintf(format, args...))
		mu.Unlock()
	}
	t.Cleanup(func() { auditIOLogf = oldLog })

	target := filepath.Join(t.TempDir(), "audit.log")
	p := &auditPipeline{target: target, mode: 0o644}
	if err := p.openFile(p.mode); err != nil {
		t.Fatal(err)
	}
	// 模拟粘性 IO 错误：先入缓冲（空 bufio 刷盘不触 fd），再关闭 fd 后刷盘必须
	// 报错并重建。
	p.ioMu.Lock()
	p.appendLine([]byte("buffered-before-error"))
	_ = p.fd.Close()
	p.flushLocked()
	p.ioMu.Unlock()

	mu.Lock()
	if len(logs) == 0 {
		mu.Unlock()
		t.Fatal("io error must be surfaced via auditIOLogf")
	}
	mu.Unlock()

	p.ioMu.Lock()
	p.appendLine([]byte("line-after-reopen"))
	p.flushLocked()
	p.ioMu.Unlock()
	data, err := os.ReadFile(target)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(data), "line-after-reopen") {
		t.Fatalf("write must continue after fd reopen, got %q", data)
	}

	// 格式化失败：单条跳过、后续行继续落盘（process 自行取 ioMu，不得在
	// 测试侧持锁调用——否则自死锁）。
	p.process(lbAuditItem{snap: &auditSnapshot{}, formatter: failingFormatter{}})
	p.process(lbAuditItem{snap: &auditSnapshot{}, formatter: jsonFormatterForTest{}})
	p.ioMu.Lock()
	p.flushLocked()
	p.ioMu.Unlock()
	data, err = os.ReadFile(target)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(data), `{"transaction"`) {
		t.Fatalf("line after a format failure must still be written, got %q", data)
	}
	p.closeFile()
}

// 管线是进程级单例：同 target 的并发 acquire 恒返回同一实例（不重建 fd/
// drain，也不做引用计数—上游从不调 AuditLogWriter.Close，refs 计数无消费方）。
func TestAcquireAuditPipeline_processSingleton(t *testing.T) {
	useTestAuditPipeline(t)
	target := filepath.Join(t.TempDir(), "audit.log")
	first, err := acquireAuditPipeline(target, 0o644)
	if err != nil {
		t.Fatalf("acquire: %v", err)
	}

	const workers = 16
	results := make([]*auditPipeline, workers)
	var wg sync.WaitGroup
	for i := range workers {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			p, err := acquireAuditPipeline(target, 0o644)
			if err != nil {
				return
			}
			results[i] = p
		}(i)
	}
	wg.Wait()
	for i, p := range results {
		if p == nil {
			t.Fatalf("worker %d acquire failed", i)
		}
		if p != first {
			t.Fatalf("worker %d got a distinct pipeline for the same target (fd/drain rebuild)", i)
		}
	}
}

// 历史问题（历史）：注册表条目硬上限——无 counter 路由时代理层校验
// 之外的纵深（任何新 key 生产路径都不得让注册表无界增长）。满时拒绝新键，
// 既有键的分段写入不受影响。
func TestAuditTimingRegistry_entryCap(t *testing.T) {
	useTestTimingRegistry(t)
	origCap := auditTimingMaxEntries
	auditTimingMaxEntries = 4
	t.Cleanup(func() { auditTimingMaxEntries = origCap })

	ids := []string{"0000000000000001", "0000000000000002", "0000000000000003", "0000000000000004"}
	for _, id := range ids {
		auditTimingRecord(id, timingSegmentPre, 1)
	}
	if got := len(auditTimingEntriesSnapshotForTest(t)); got != 4 {
		t.Fatalf("cap=4 must admit 4 entries, got %d", got)
	}

	// 第 5 个新键被拒绝（注册表不增长）；既有键照常更新。
	auditTimingRecord("0000000000000005", timingSegmentPre, 1)
	if got := len(auditTimingEntriesSnapshotForTest(t)); got != 4 {
		t.Fatalf("new key beyond cap must be dropped, got %d entries", got)
	}
	auditTimingRecord("0000000000000001", timingSegmentEnd, 2)
	if snap := auditTimingLookupForTest(t, "0000000000000001"); !snap.endSet {
		t.Fatal("existing entry must still accept segments at cap")
	}

	// 畸形形状：非 16-hex key 连单条都不得建（auditTimingRecord 自身纵深）。
	auditTimingRecord("not-a-valid-id", timingSegmentPre, 1)
	if snap := auditTimingLookupForTest(t, "not-a-valid-id"); snap.preSet {
		t.Fatal("malformed id must be rejected at registry write")
	}
}

// 历史问题：周期清扫——旧实现清扫仅由建条驱动（停流后过期条目永久驻留）。
// 后台 sweeper 按周期弹出 TTL 过期条目，零建条流量下注册表也必须收敛。
func TestAuditTimingRegistry_periodicSweep(t *testing.T) {
	useTestTimingRegistry(t)
	origInterval := auditTimingSweepIntervalNs.Load()
	auditTimingSweepIntervalNs.Store(int64(5 * time.Millisecond))
	t.Cleanup(func() { auditTimingSweepIntervalNs.Store(origInterval) })

	// 种入已过期条目（不经建条路径——建条驱动的清扫不触发）。
	seedAuditTimingEntryForTest("00000000000000aa", time.Now().Add(-2*time.Duration(auditTimingEntryTTLNs.Load())))
	startAuditTimingSweeperForTest()

	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		if got := len(auditTimingEntriesSnapshotForTest(t)); got == 0 {
			return
		}
		time.Sleep(5 * time.Millisecond)
	}
	t.Fatal("expired entry must be reaped by the periodic sweeper without new traffic")
}
