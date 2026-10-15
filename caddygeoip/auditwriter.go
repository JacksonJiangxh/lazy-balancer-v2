package caddygeoip

// 审计写插件（历史，架构改进：耗时侧车文件退役 → 审计行内嵌 timing）。
//
// coraza 以 `SecAuditLogType lbfile` 选用本插件（security.go 渲染层发射）。
// 与退役的 serial 直写相比的两个职责：
//
//  1. timing 注入：进程内 per-request 计时注册表（auditTiming*，写点=
//     blocked_counter / SecurityTimingPre / SecurityTimingEnd，键=blocked_counter
//     注入的 X-Lb-Security-Timing-Id 头值——审计 JSON 的 request.headers 天然
//     收录该头，Write 无需解析正文即可取得关联键）在刷盘前注入审计 JSON 顶层
//     lb_timing 字段：{"pre_us":N,"end_us":M}（缺席分段省略）。读侧
//     （internal/services/securityevents.go）直接从审计行取值，
//     侧车文件与读侧 tick 级查表已整体退役。
//
//  2. 异步批量落盘：有界队列 + 阻塞式入队（零丢弃；队列满时请求路径阻塞等
//     drain 消化，退化价=退役前 serial 同步写）。专职 drain goroutine 以
//     bufio 批量刷盘（阈值/周期双触发）。
//
// 时序契约（为什么注入在 drain 侧而非 Write 侧）：coraza-caddy 在 WAF 中间件
// 退出时 defer tx.ProcessLogging()——审计 Write 严格早于 blocked_counter（外层
// 包装）恢复执行与 SecurityTimingEnd（下游收点）执行，此刻该请求的分段耗时
// 尚未产生。drain goroutine 对每条审计行限时等待注册表终态（closed），等待
// 发生在请求路径之外；耗时数值在决策点测得（time.Since 决策瞬间），入队/
// 队列等待/刷盘延迟永不进入数值——「决策→计时→入队」的顺序保证降级模式下
// 耗时数字不受污染。
//
// 轮转兼容（auditlog_rotation.go 核对）：轮转 = copytruncate（复制后截断，
// 长生命周期 fd 恒有效，O_APPEND 恒写当前 EOF），本插件不做 rename 重开；
// bufio 中暂存的字节在截断后落盘会出现在新文件头部，摄取按行解码+transaction_id
// 幂等去重，乱序无影响、零丢失。

import (
	"bufio"
	"encoding/json"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/corazawaf/coraza/v3/experimental/plugins"
	"github.com/corazawaf/coraza/v3/experimental/plugins/plugintypes"
)

// auditWriterName 是插件注册名——渲染层以 `SecAuditLogType lbfile` 选用
// （coraza GetWriter 大小写不敏感）。
const auditWriterName = "lbfile"

func init() {
	plugins.RegisterAuditLogWriter(auditWriterName, func() plugintypes.AuditLogWriter {
		return &lbAuditWriter{}
	})
}

// 管线参数（var 供测试收窄）。
var (
	// auditQueueSize 有界队列容量：2048 条 × 典型 2-8KB ≈ 上限 16MB 内存，
	// 打满即请求路径阻塞（零丢弃的退化价，与退役前 serial 同步写同价）。
	auditQueueSize = 2048
	// auditFlushThreshold bufio 批量刷盘字节数阈值；auditFlushInterval 周期
	// 兜底（低流量下 bufio 滞留行不超周期）。
	auditFlushThreshold = 32 * 1024
	auditFlushInterval  = 500 * time.Millisecond
	// auditTimingWaitLimit drain 对迟到分段的限时等待：正常形态（blocked_counter
	// 是链最外层收点，紧随 coraza 中间件 defer）等待 <1ms；上限仅兜底异常
	// 形态（计时写点缺失），超时按已到场分段注入。
	auditTimingWaitLimit = 2 * time.Second
	auditTimingPollStep  = 200 * time.Microsecond
	// auditTimingEntryTTL 注册表条目存活上限：条目由周期性清扫回收（消费不删——
	// 同一请求可产多条审计行[预检+策略引擎]，共享同一注册表条目）。
	auditTimingEntryTTL = 30 * time.Second
)

// —— per-request 计时注册表 ——
// 写点：SecurityTimingPre(:pre)/SecurityTimingEnd(:end)/blocked_counter(:pre 或
// :end + 终态 close)。读点：audit drain goroutine（限时等待终态后注入）。
// 键=X-Lb-Security-Timing-Id 头值（16 字符随机 hex，进程内唯一；coraza tx ID
// 每引擎独立生成，一个请求多个引擎多个 tx ID，不能作请求级键）。

type auditTimingEntry struct {
	mu     sync.Mutex
	preUs  int64
	endUs  int64
	preSet bool
	endSet bool
	// closed 终态标记：链最外层收点（blocked_counter post-next）在全部分段
	// 写点完成后的空值写法（guard）下置位——drain 见 closed 即注入并停止等待。
	closed  bool
	created time.Time
}

// auditTimingSnapshot 是 wait 的只读快照；preSet/endSet 区分「未记录」与
// 「记录为 0」（0µs 是合法计时值）。
type auditTimingSnapshot struct {
	preUs  int64
	preSet bool
	endUs  int64
	endSet bool
	closed bool
}

func (s auditTimingSnapshot) hasAny() bool { return s.preSet || s.endSet }

var (
	auditTimingMu      sync.Mutex
	auditTimingEntries = map[string]*auditTimingEntry{}
	// auditTimingCreateCount 记录创建次数——每 64 次创建触发一次过期清扫
	// （摊销 O(1)；size 超限时立即清扫兜底突发）。
	auditTimingCreateCount int
	auditTimingSweepMin    = 4096
)

// auditTimingRecord 写入一个分段计时（µs）。id 为空（计时 ID 生成失败的降级
// 形态）静默忽略——耗时是增强信息，不产生请求路径错误。
func auditTimingRecord(id, segment string, us int64) {
	if id == "" {
		return
	}
	now := time.Now()
	auditTimingMu.Lock()
	e := auditTimingEntries[id]
	if e == nil {
		e = &auditTimingEntry{created: now}
		auditTimingEntries[id] = e
		auditTimingCreateCount++
		if auditTimingCreateCount%64 == 0 || len(auditTimingEntries) > auditTimingSweepMin {
			auditTimingSweepLocked(now)
		}
	}
	auditTimingMu.Unlock()
	e.mu.Lock()
	switch segment {
	case "pre":
		e.preUs, e.preSet = us, true
	case "end":
		e.endUs, e.endSet = us, true
	}
	e.mu.Unlock()
}

// auditTimingClose 标记该请求的全部分段已写完（终态）。由链最外层收点
// （blocked_counter post-next）调用——此刻整个安全链已返回，不会再有分段写点。
// 条目不存在（极形态：链上无任何分段写点执行）时创建空终态条目——审计 drain
// 见终态立即注入空快照（无 lb_timing 字段），不等满超时。
func auditTimingClose(id string) {
	if id == "" {
		return
	}
	now := time.Now()
	auditTimingMu.Lock()
	e := auditTimingEntries[id]
	if e == nil {
		e = &auditTimingEntry{created: now}
		auditTimingEntries[id] = e
	}
	auditTimingMu.Unlock()
	e.mu.Lock()
	e.closed = true
	e.mu.Unlock()
}

// auditTimingWait 限时等待该请求的计时终态并返回快照。正常形态下 blocked_counter
// 在 coraza 中间件 defer 之后数微秒内置位终态，等待≈一个调度间隙；上限只兜底
// 计时写点缺失的异常形态（超时返回已到场分段，行不丢、缺段省略）。未知 id
// （无 timing 头的审计行）立即返回空快照。
func auditTimingWait(id string, timeout time.Duration) auditTimingSnapshot {
	if id == "" {
		return auditTimingSnapshot{}
	}
	deadline := time.Now().Add(timeout)
	var lastSeen auditTimingSnapshot
	for {
		auditTimingMu.Lock()
		e := auditTimingEntries[id]
		auditTimingMu.Unlock()
		if e != nil {
			e.mu.Lock()
			snap := auditTimingSnapshot{preUs: e.preUs, preSet: e.preSet, endUs: e.endUs, endSet: e.endSet, closed: e.closed}
			e.mu.Unlock()
			if snap.closed {
				return snap
			}
			lastSeen = snap
		}
		if time.Now().After(deadline) {
			// 超时：有部分分段就带部分分段（与退役前读侧「按到场键选值」同形）
			return lastSeen
		}
		time.Sleep(auditTimingPollStep)
	}
}

// auditTimingSweepLocked 清扫超龄条目（调用方持 auditTimingMu）。
func auditTimingSweepLocked(now time.Time) {
	for id, e := range auditTimingEntries {
		if now.Sub(e.created) > auditTimingEntryTTL {
			delete(auditTimingEntries, id)
		}
	}
}

// securityTimingIDFromHeaders 从审计事务的请求头提取计时关联键（大小写不敏感；
// coraza 按收到形态收录 canonical 键，容错非常规形态）。缺失返回空串=不注入。
func securityTimingIDFromHeaders(headers map[string][]string) string {
	for key, values := range headers {
		if strings.EqualFold(key, securityTimingHeader) && len(values) > 0 {
			return values[0]
		}
	}
	return ""
}

// injectAuditTiming 把计时快照注入审计 JSON 顶层 lb_timing 字段。缺席分段省略
// （preSet/endSet 区分「未记录」与 0——0µs 是合法计时值）。解析失败原样返回
// （畸形行不因注入丢失，摄取侧自行跳过）。在 drain goroutine 内执行，不在
// 请求路径。
func injectAuditTiming(body []byte, snap auditTimingSnapshot) []byte {
	if !snap.hasAny() {
		return body
	}
	var doc map[string]json.RawMessage
	if err := json.Unmarshal(body, &doc); err != nil {
		return body
	}
	payload := make([]byte, 0, 64)
	payload = append(payload, '{')
	if snap.preSet {
		payload = append(payload, `"pre_us":`...)
		payload = strconv.AppendInt(payload, snap.preUs, 10)
		if snap.endSet {
			payload = append(payload, ',')
		}
	}
	if snap.endSet {
		payload = append(payload, `"end_us":`...)
		payload = strconv.AppendInt(payload, snap.endUs, 10)
	}
	payload = append(payload, '}')
	doc["lb_timing"] = payload
	out, err := json.Marshal(doc)
	if err != nil {
		return body
	}
	return out
}

// —— 审计写插件与共享管线 ——

// lbAuditItem 是队列元素：格式化后的审计行正文 + 计时关联键（空=无计时）。
type lbAuditItem struct {
	body []byte
	tid  string
}

// auditPipeline 是按目标路径共享的落盘管线（单 drain goroutine + 单 fd +
// bufio）。多个 coraza WAF 实例（预检+各策略引擎，各自 NewWAF→独立 writer
// 实例）追加同一审计文件时共享一条管线，避免 reload 池换血累积 goroutine/fd。
type auditPipeline struct {
	// mu 保护生命周期字段（queue/done/refs/closed）：enqueue 持 RLock 发送，
	// release 持 Lock 关闭队列——与退役前 securityTimingWriter 同款互斥形态，
	// 不会 send-on-closed。
	mu     sync.RWMutex
	target string
	queue  chan lbAuditItem
	done   chan struct{}
	refs   int
	closed bool
	// ioMu 保护 fd/bufio（仅 drain goroutine 触碰，独立于 mu 防止请求路径
	// enqueue 的 RLock 与刷盘互斥）。
	ioMu sync.Mutex
	fd   *os.File
	bw   *bufio.Writer
}

var (
	auditPipelinesMu sync.Mutex
	auditPipelines   = map[string]*auditPipeline{}
)

// acquireAuditPipeline 取目标路径的共享管线（不存在则创建：打开 fd + 启动
// drain）。fd 打开失败返回错误——coraza NewWAF 会把 Init 错误上抛为配置拒绝
// （/load fail-fast，与退役前 serial writer 同语义）。
func acquireAuditPipeline(target string, mode os.FileMode) (*auditPipeline, error) {
	auditPipelinesMu.Lock()
	defer auditPipelinesMu.Unlock()
	if p, ok := auditPipelines[target]; ok && !p.isClosed() {
		p.mu.Lock()
		p.refs++
		p.mu.Unlock()
		return p, nil
	}
	p := &auditPipeline{
		target: target,
		queue:  make(chan lbAuditItem, auditQueueSize),
		done:   make(chan struct{}),
	}
	if err := p.openFile(mode); err != nil {
		return nil, err
	}
	p.refs = 1
	auditPipelines[target] = p
	go p.drain()
	return p, nil
}

func (p *auditPipeline) isClosed() bool {
	p.mu.RLock()
	defer p.mu.RUnlock()
	return p.closed
}

// openFile 打开目标文件（O_APPEND——copytruncate 轮转下 fd 恒有效）。
func (p *auditPipeline) openFile(mode os.FileMode) error {
	fd, err := os.OpenFile(p.target, os.O_CREATE|os.O_WRONLY|os.O_APPEND, mode)
	if err != nil {
		return err
	}
	p.ioMu.Lock()
	p.fd = fd
	p.bw = bufio.NewWriterSize(fd, 64*1024)
	p.ioMu.Unlock()
	return nil
}

// enqueue 阻塞式入队（零丢弃）：队列满时等待 drain 消化——退化价=退役前
// serial 同步写。管线已关（refs 归零后的尾部写入）静默丢弃。
func (p *auditPipeline) enqueue(item lbAuditItem) {
	p.mu.RLock()
	q, done := p.queue, p.done
	p.mu.RUnlock()
	if q == nil {
		return
	}
	select {
	case q <- item:
	case <-done:
	}
}

// release 递减引用；最后一个引用释放时关闭队列——drain 排空余量、刷盘、关
// fd 后退出（close 与 enqueue 的互斥见 mu 注释）。
func (p *auditPipeline) release() {
	auditPipelinesMu.Lock()
	defer auditPipelinesMu.Unlock()
	p.mu.Lock()
	if p.refs > 0 {
		p.refs--
	}
	if p.refs != 0 || p.closed {
		p.mu.Unlock()
		return
	}
	p.closed = true
	q := p.queue
	p.queue = nil
	p.mu.Unlock()
	delete(auditPipelines, p.target)
	close(q)
	<-p.done
}

// drain 专职落盘 goroutine：注入 timing → bufio 批量写 → 阈值/周期双触发刷盘。
// 队列关闭后排空余量再退出（零丢弃语义覆盖 teardown 路径）。队列句柄在启动时
// 捕获一次——release 会把 p.queue 置 nil（防后续 enqueue），select 若每轮重读
// 字段会读到 nil channel（永不完全就绪的 case），ticker 分支将使本 goroutine
// 永不退出（实测 livelock）。
func (p *auditPipeline) drain() {
	defer close(p.done)
	p.mu.RLock()
	q := p.queue
	p.mu.RUnlock()
	if q == nil {
		return
	}
	ticker := time.NewTicker(auditFlushInterval)
	defer ticker.Stop()
	for {
		select {
		case item, ok := <-q:
			if !ok {
				p.flushPending()
				p.closeFile()
				return
			}
			p.process(item)
		case <-ticker.C:
			p.flushPending()
		}
	}
}

// process 处理单条审计行：限时等待计时终态 → 注入 → bufio 写（阈值刷盘）。
// 计时等待在请求路径之外（见文件头时序契约注释）。
func (p *auditPipeline) process(item lbAuditItem) {
	body := item.body
	if item.tid != "" {
		snap := auditTimingWait(item.tid, auditTimingWaitLimit)
		body = injectAuditTiming(body, snap)
	}
	p.ioMu.Lock()
	if p.bw == nil {
		p.ioMu.Unlock()
		return
	}
	_, _ = p.bw.Write(body)
	_, _ = p.bw.WriteString("\n")
	if p.bw.Buffered() >= auditFlushThreshold {
		_ = p.bw.Flush()
	}
	p.ioMu.Unlock()
}

func (p *auditPipeline) flushPending() {
	p.ioMu.Lock()
	if p.bw != nil && p.bw.Buffered() > 0 {
		_ = p.bw.Flush()
	}
	p.ioMu.Unlock()
}

func (p *auditPipeline) closeFile() {
	p.ioMu.Lock()
	if p.bw != nil {
		_ = p.bw.Flush()
		p.bw = nil
	}
	if p.fd != nil {
		_ = p.fd.Close()
		p.fd = nil
	}
	p.ioMu.Unlock()
}

// lbAuditWriter 是 coraza 审计写插件实例（每个 coraza WAF 一个；多实例共享
// 按路径的落盘管线）。Write 与退役前 serial writer 同步语义的差异仅在「格式化
// 后入队」——格式化仍在请求路径（与 serial 相同成本），批量落盘在 drain。
type lbAuditWriter struct {
	formatter plugintypes.AuditLogFormatter
	pipeline  *auditPipeline
	// failed 标记 Init 失败（fd 打不开）：后续 Write 静默 no-op——与 coraza
	// serial writer Init 失败后 Write 短路同形态（coraza 已在 Init 错误点
	// 上抛/记日志，配置加载被拒）。
	failed bool
}

func (w *lbAuditWriter) Init(c plugintypes.AuditLogConfig) error {
	w.formatter = c.Formatter
	if c.Target == "" {
		return nil
	}
	p, err := acquireAuditPipeline(c.Target, c.FileMode)
	if err != nil {
		w.failed = true
		return err
	}
	w.pipeline = p
	return nil
}

func (w *lbAuditWriter) Write(al plugintypes.AuditLog) error {
	if w.failed || w.pipeline == nil || w.formatter == nil || al == nil {
		return nil
	}
	bts, err := w.formatter.Format(al)
	if err != nil {
		return err
	}
	if len(bts) == 0 {
		return nil
	}
	tid := ""
	if al.Transaction() != nil && al.Transaction().HasRequest() {
		tid = securityTimingIDFromHeaders(al.Transaction().Request().Headers())
	}
	w.pipeline.enqueue(lbAuditItem{body: bts, tid: tid})
	return nil
}

func (w *lbAuditWriter) Close() error {
	if w.pipeline != nil {
		w.pipeline.release()
		w.pipeline = nil
	}
	return nil
}
