// Package taskengine 是统一任务引擎（lazy-task-engine，v2.3.4 M1）：
// 单一注册表管理全部任务族的调度、单飞执行、取消、启停、状态快照与
// task_runs 历史落库。引擎只管生命周期——业务硬化语义（两层哈希/任务内
// 重试/回滚编舞/demote 守卫等）原样保留在各族 Run 体内。
//
// M1 为纯增量：无消费方，行为契约由 engine_test.go 钉死。M2+ 逐族迁移。
package taskengine

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"time"

	"lazy-balancer-v2/internal/db"
)

// Kind 任务形态。
type Kind string

const (
	KindScheduled  Kind = "scheduled"  // 排程槽驱动
	KindContinuous Kind = "continuous" // 常驻间隔循环
	KindQueue      Kind = "queue"      // 队列驱动（引擎只镜像状态）
	KindOneshot    Kind = "oneshot"    // 单次触发（启动阶段等——无循环无排程）
	KindInfo       Kind = "info"       // 引擎外信息行（只读展示）
)

// Role 角色门。
type Role string

const (
	RoleAny        Role = "any"
	RoleMasterOnly Role = "master-only"
	RoleSlaveOnly  Role = "slave-only"
)

// RunContext 交给任务体的执行上下文。
type RunContext struct {
	Ctx      context.Context
	Trigger  string
	RunID    int64
	Progress func(stage, msg string)
	Logger   func(level, msg string)
}

// Descriptor 任务声明（注册即接入 UI/API/MCP/审计/历史）。
type Descriptor struct {
	ID          string
	Family      string
	Name        string
	Description string
	Category    string
	Kind        Kind

	// 调度声明（终态统一）：IntervalFn 动态间隔（常驻/高频/探测轮）；
	// NextSlotFn 返回下一排程槽（排程族展示用——调度仍由探测轮体内
	// due 逻辑驱动）。二者均空=OnDemand。
	IntervalFn func() time.Duration
	// NextSlotFn 下一排程槽（本地时区展示串；空=无）。
	NextSlotFn func() string
	// EnabledFn 调度开关（族配置：总闸/auto_update 等——引擎统一读取，
	// 监控统一展示；nil=恒开）。
	EnabledFn func() bool
	// StatusFn 运行态镜像（更新族→manager 快照/队列族→业务表）；
	// 返回空串=用引擎默认态。探针族在运行间隙返回空闲。
	StatusFn func() string

	Run                func(RunContext) error
	CancelHook         func() bool // 可选：取消委托（如更新族 manager.CancelRunning——引擎内部 ctx 只覆盖单轮探测体）
	SilentProbes       bool        // 探测型 Run（如 1min due 探测）不落 task_runs——真实运行由族侧 RecordRun 记录
	RecordFailuresOnly bool        // 高频真实工作轮（摄取/看门狗）：成功静默，仅失败/取消留痕
	Singleton          bool
	Cancelable         bool
	MasterOnly         bool // Trigger/排程仅主节点（Run 侧门）
	RunsOn             Role // 循环角色门（默认 any）
	// AsKind 任务性质（展示口径——区别于驱动节拍 Kind：排程族由引擎 1min
	// 探测轮驱动但性质是「定时」而非「常驻」；空=同 Kind）。
	AsKind Kind
	// ManualRun Run 体支持 manual 触发语义（排程族 Run 内分支处理/清理与
	// 循环族 Run 即单轮工作；探测-only 族走专属端点）。
	ManualRun bool
}

// RunRecord task_runs 行视图。
type RunRecord struct {
	ID         int64  `json:"id"`
	TaskID     string `json:"task_id"`
	Family     string `json:"family"`
	Trigger    string `json:"trigger"`
	Status     string `json:"status"`
	StartedAt  string `json:"started_at"`
	FinishedAt string `json:"finished_at"`
	DurationMs int64  `json:"duration_ms"`
	Stage      string `json:"stage,omitempty"`
	Message    string `json:"message,omitempty"`
	EntryCount int    `json:"entry_count,omitempty"`
}

// ErrAlreadyRunning 单飞冲突（API 409 语义）。
var ErrAlreadyRunning = errors.New("taskengine: 任务运行中")

// ErrNotFound 未注册。
var ErrNotFound = errors.New("taskengine: 任务未注册")

// registration 运行态注册项。
type registration struct {
	desc Descriptor

	mu          sync.Mutex
	running     bool
	cancel      context.CancelFunc
	runID       int64
	stage       string
	lastMsg     string
	lastCheck   time.Time // 最近调度到期判定基准
	loopEnabled bool      // 常驻循环启停开关（StartLoop/StopLoop）
}

// Engine 统一任务引擎。
type Engine struct {
	opts Options
	mu   sync.RWMutex
	regs map[string]*registration

	roleMu sync.RWMutex
	role   bool // 当前是否主节点

	schedStop chan struct{}
	schedDone chan struct{}
	stopped   bool
}

// Options 引擎选项。
type Options struct {
	TickInterval time.Duration // 调度粒度（默认 1s；测试可缩短）
}

// NewEngine 建引擎并启动调度循环。
func NewEngine(opts Options) *Engine {
	if opts.TickInterval <= 0 {
		opts.TickInterval = time.Second
	}
	e := &Engine{opts: opts, regs: map[string]*registration{}, role: true, schedStop: make(chan struct{}), schedDone: make(chan struct{})}
	go e.scheduleLoop()
	return e
}

// Stop 终止调度循环（进程退出用）。
func (e *Engine) Stop() {
	e.mu.Lock()
	if e.stopped {
		e.mu.Unlock()
		return
	}
	e.stopped = true
	close(e.schedStop)
	// 取消全部运行中任务
	for _, r := range e.regs {
		r.mu.Lock()
		if r.cancel != nil {
			r.cancel()
		}
		r.mu.Unlock()
	}
	e.mu.Unlock()
	<-e.schedDone
}

// SetRole 更新节点角色（集群 promote/demote 钩子调用）。
func (e *Engine) SetRole(isMaster bool) {
	e.roleMu.Lock()
	e.role = isMaster
	e.roleMu.Unlock()
}

func (e *Engine) isMaster() bool {
	e.roleMu.RLock()
	defer e.roleMu.RUnlock()
	return e.role
}

// Register 注册/覆盖任务声明。
func (e *Engine) Register(d Descriptor) error {
	if d.ID == "" || d.Family == "" {
		return errors.New("taskengine: ID/Family 必填")
	}
	e.mu.Lock()
	defer e.mu.Unlock()
	e.regs[d.ID] = &registration{desc: d}
	return nil
}

// SetAsKind 补设任务性质（注册后统一批量标定——绕开结构体字面量对齐问题）。
func (e *Engine) SetAsKind(id string, as Kind) {
	e.mu.Lock()
	defer e.mu.Unlock()
	if r, ok := e.regs[id]; ok {
		r.desc.AsKind = as
	}
}

// Unregister 摘除注册。
func (e *Engine) Unregister(id string) {
	e.mu.Lock()
	delete(e.regs, id)
	e.mu.Unlock()
}

// Reschedule 通知引擎重读动态间隔（配置变更热生效）。
func (e *Engine) Reschedule(id string) {
	e.mu.RLock()
	r := e.regs[id]
	e.mu.RUnlock()
	if r != nil {
		r.mu.Lock()
		r.lastCheck = time.Time{} // 清零触发立即重算
		r.mu.Unlock()
	}
}

// Trigger 手动触发（单飞门 + 主节点门）。
func (e *Engine) Trigger(id, trigger string) error {
	e.mu.RLock()
	r := e.regs[id]
	e.mu.RUnlock()
	if r == nil {
		return ErrNotFound
	}
	if r.desc.MasterOnly && !e.isMaster() {
		return errors.New("taskengine: 该操作仅允许在主节点执行")
	}
	return e.runNow(id, trigger)
}

// Cancel 取消运行中任务（仅 Cancelable 声明的族生效）。
func (e *Engine) Cancel(id string) bool {
	e.mu.RLock()
	r := e.regs[id]
	e.mu.RUnlock()
	if r == nil || !r.desc.Cancelable {
		return false
	}
	if r.desc.CancelHook != nil {
		return r.desc.CancelHook()
	}
	r.mu.Lock()
	c := r.cancel
	running := r.running
	r.mu.Unlock()
	if c == nil || !running {
		return false
	}
	c()
	return true
}

// StartLoop 启动常驻循环（角色门内按 IntervalFn 周期执行）。
func (e *Engine) StartLoop(id string) {
	e.mu.RLock()
	r := e.regs[id]
	e.mu.RUnlock()
	if r == nil {
		return
	}
	r.mu.Lock()
	r.loopEnabled = true
	r.lastCheck = time.Time{}
	r.mu.Unlock()
}

// StopLoop 停止常驻循环。
func (e *Engine) StopLoop(id string) {
	e.mu.RLock()
	r := e.regs[id]
	e.mu.RUnlock()
	if r == nil {
		return
	}
	r.mu.Lock()
	r.loopEnabled = false
	r.lastCheck = time.Time{}
	r.mu.Unlock()
}

// IsRunning 任务是否处于运行态：执行中（in-flight）或常驻循环已启用
// （连续任务两拍之间空隙也视为运行——用户语义「循环活着」）。
func (e *Engine) IsRunning(id string) bool {
	e.mu.RLock()
	r := e.regs[id]
	e.mu.RUnlock()
	if r == nil {
		return false
	}
	r.mu.Lock()
	running, loopOn := r.running, r.loopEnabled
	r.mu.Unlock()
	if running {
		return true
	}
	if r.desc.Kind == KindContinuous {
		return loopOn && e.roleAllows(r.desc.RunsOn)
	}
	return false
}

// History 查询 task_runs（时间倒序）。
func (e *Engine) History(id string, limit int) []RunRecord {
	if limit <= 0 {
		limit = 20
	}
	rows, err := db.DB.Query(`SELECT id, task_id, family, COALESCE(trigger,''), status, started_at, COALESCE(finished_at,''), duration_ms, COALESCE(stage,''), COALESCE(message,''), entry_count FROM task_runs WHERE task_id=? ORDER BY id DESC LIMIT ?`, id, limit)
	if err != nil {
		return nil
	}
	defer rows.Close()
	var out []RunRecord
	for rows.Next() {
		var r RunRecord
		if err := rows.Scan(&r.ID, &r.TaskID, &r.Family, &r.Trigger, &r.Status, &r.StartedAt, &r.FinishedAt, &r.DurationMs, &r.Stage, &r.Message, &r.EntryCount); err != nil {
			continue
		}
		out = append(out, r)
	}
	return out
}

// RecoverOrphans 崩溃恢复：把残留 running 行改标 interrupted，返回行数。
func (e *Engine) RecoverOrphans() int64 {
	res, err := db.DB.Exec(`UPDATE task_runs SET status='interrupted', finished_at=?, message=COALESCE(message,'')||'（进程重启回收）' WHERE status='running'`, engineNowStr())
	if err != nil {
		return 0
	}
	n, _ := res.RowsAffected()
	return n
}

// ---- 内部：执行与调度 ----

// runNow 同步执行一次（带单飞门/历史落库/终态回收）。测试直调入口。
func (e *Engine) runNow(id, trigger string) error {
	e.mu.RLock()
	r := e.regs[id]
	e.mu.RUnlock()
	if r == nil {
		return ErrNotFound
	}
	r.mu.Lock()
	if r.running && r.desc.Singleton {
		r.mu.Unlock()
		return ErrAlreadyRunning
	}
	r.running = true
	ctx, cancel := context.WithCancel(context.Background())
	r.cancel = cancel
	r.mu.Unlock()

	runID := int64(0)
	// 落库策略：探测族(SilentProbes)与失败留痕族(RecordFailuresOnly)
	// 不预插——后者仅非 success 终态时补插。
	if !r.desc.SilentProbes && !r.desc.RecordFailuresOnly {
		runID = globalInsertRun(id, r.desc.Family, trigger)
	}
	rc := RunContext{Ctx: ctx, Trigger: trigger, RunID: runID,
		Progress: func(stage, msg string) {
			r.mu.Lock()
			r.stage, r.lastMsg = stage, msg
			r.mu.Unlock()
			if runID > 0 {
				_, _ = db.DB.Exec(`UPDATE task_runs SET stage=?, message=? WHERE id=?`, stage, msg, runID)
			}
		},
		Logger: func(level, msg string) { /* M1 结构化日志直通应用日志 */ },
	}

	start := time.Now()
	runErr := r.desc.Run(rc)
	status := terminalStatus(ctx, runErr)
	dur := time.Since(start).Milliseconds()
	// 高频工作轮失败才补落库（成功轮静默——2s 摄取/60s 看门狗每轮落库
	// 即每天 4.3 万/1440 行噪音）
	if runID == 0 && r.desc.RecordFailuresOnly && status != "success" {
		runID = globalInsertRun(id, r.desc.Family, trigger)
	}

	r.mu.Lock()
	r.running = false
	r.cancel = nil
	r.mu.Unlock()
	cancel()

	e.finishRun(runID, status, dur)
	return runErr
}

func terminalStatus(ctx context.Context, err error) string {
	if ctx.Err() != nil {
		return "cancelled"
	}
	if err != nil {
		return "failed"
	}
	return "success"
}

func globalInsertRun(taskID, family, trigger string) int64 {
	if db.DB == nil {
		return 0
	}
	res, err := db.DB.Exec(`INSERT INTO task_runs (task_id, family, trigger, status, started_at) VALUES (?,?,?,'running',?)`, taskID, family, trigger, engineNowStr())
	if err != nil {
		return 0
	}
	id, _ := res.LastInsertId()
	return id
}

func (e *Engine) finishRun(runID int64, status string, durMs int64) {
	if runID <= 0 || db.DB == nil {
		return
	}
	_, _ = db.DB.Exec(`UPDATE task_runs SET status=?, finished_at=datetime('now'), duration_ms=? WHERE id=?`, status, durMs, runID)
}

// scheduleLoop 1s 粒度调度：常驻循环按 IntervalFn 到期投递（角色门+启停门）。
func (e *Engine) scheduleLoop() {
	defer close(e.schedDone)
	ticker := time.NewTicker(e.opts.TickInterval)
	defer ticker.Stop()
	for {
		select {
		case <-e.schedStop:
			return
		case <-ticker.C:
			e.tick()
		}
	}
}

func (e *Engine) tick() {
	now := time.Now()
	e.mu.RLock()
	ids := make([]string, 0, len(e.regs))
	for id := range e.regs {
		ids = append(ids, id)
	}
	e.mu.RUnlock()
	for _, id := range ids {
		e.mu.RLock()
		r := e.regs[id]
		e.mu.RUnlock()
		if r == nil || r.desc.Kind != KindContinuous || r.desc.IntervalFn == nil || r.desc.Run == nil {
			continue
		}
		r.mu.Lock()
		enabled := r.loopEnabled
		due := enabled && (r.lastCheck.IsZero() || now.Sub(r.lastCheck) >= r.desc.IntervalFn())
		if due {
			r.lastCheck = now
		}
		r.mu.Unlock()
		if !due {
			continue
		}
		// 角色门
		if !e.roleAllows(r.desc.RunsOn) {
			continue
		}
		go func(rid string) { _ = e.runNow(rid, "auto") }(id)
	}
}

func (e *Engine) roleAllows(role Role) bool {
	switch role {
	case RoleMasterOnly:
		return e.isMaster()
	case RoleSlaveOnly:
		return !e.isMaster()
	default:
		return true
	}
}

var _ = fmt.Sprintf // 保留 fmt（M3 排程槽使用）

// location 引擎写库时区（配置时区——services 启动/变更时 SetLocation 注入；
// 未注入回退本地）。所有 task_runs 时间字符串按此时区格式化。
var engineLoc = time.Local

// SetLocation 注入配置时区（基础设置 timezone 项）。
func SetLocation(loc *time.Location) {
	if loc != nil {
		engineLoc = loc
	}
}

func engineNowStr() string { return time.Now().In(engineLoc).Format("2006-01-02 15:04:05") }

// RecordRunStart 族侧真实运行开跑落库（返回 run ID；0=跳过）。
// 引擎探测 SilentProbes 的族（更新族等），真实任务体由族 manager 在
// run() 首尾调用 RecordRunStart/RecordRunFinish——历史与引擎同表同口径。
func RecordRunStart(taskID, family, trigger string) int64 {
	return globalInsertRun(taskID, family, trigger)
}

// RecordRunFinish 族侧终态落库。
func RecordRunFinish(runID int64, status string, durMs int64, message string) {
	if runID <= 0 {
		return
	}
	if message != "" {
		_, _ = db.DB.Exec(`UPDATE task_runs SET status=?, finished_at=datetime('now'), duration_ms=?, message=? WHERE id=?`, status, durMs, message, runID)
		return
	}
	_, _ = db.DB.Exec(`UPDATE task_runs SET status=?, finished_at=datetime('now'), duration_ms=? WHERE id=?`, status, durMs, runID)
}

// TaskMeta 引擎注册面元数据（任务监控统一数据源）。
type TaskMeta struct {
	ID           string `json:"id"`
	Family       string `json:"family"`
	Name         string `json:"name"`
	Description  string `json:"description"`
	Category     string `json:"category"`
	Kind         Kind   `json:"kind"`
	AsKind       Kind   `json:"as_kind"`       // 任务性质（展示口径；探测驱动≠常驻）
	IntervalSec  int    `json:"interval_sec"`  // IntervalFn 秒值（0=无固定间隔）
	NextSlot     string `json:"next_slot"`     // NextSlotFn 结果（展示串）
	Enabled      bool   `json:"enabled"`       // EnabledFn 结果（nil=恒开）
	StatusMirror string `json:"status_mirror"` // StatusFn 结果（空=引擎默认态）
	Controllable bool   `json:"controllable"`
	Cancelable   bool   `json:"cancelable"`
	LoopOn       bool   `json:"loop_on"`     // 常驻循环当前启用态
	CanTrigger   bool   `json:"can_trigger"` // 支持手动触发（ManualRun）
}

// DescribeAll 导出全部注册任务元数据（含循环启停态）。
func (e *Engine) DescribeAll() []TaskMeta {
	e.mu.RLock()
	defer e.mu.RUnlock()
	out := make([]TaskMeta, 0, len(e.regs))
	for id, r := range e.regs {
		asKind := r.desc.AsKind
		if asKind == "" {
			asKind = r.desc.Kind
		}
		m := TaskMeta{ID: id, Family: r.desc.Family, Name: r.desc.Name,
			Description: r.desc.Description, Category: r.desc.Category, Kind: r.desc.Kind,
			AsKind:       asKind,
			CanTrigger:   r.desc.ManualRun,
			Controllable: r.desc.AsKind == KindContinuous || (r.desc.AsKind == "" && r.desc.Kind == KindContinuous),
			Cancelable:   r.desc.Cancelable,
			Enabled:      true}
		if r.desc.IntervalFn != nil {
			m.IntervalSec = int(r.desc.IntervalFn().Seconds())
		}
		if r.desc.NextSlotFn != nil {
			m.NextSlot = r.desc.NextSlotFn()
		}
		if r.desc.EnabledFn != nil {
			m.Enabled = r.desc.EnabledFn()
		}
		if r.desc.StatusFn != nil {
			m.StatusMirror = r.desc.StatusFn()
		}
		r.mu.Lock()
		m.LoopOn = r.loopEnabled
		r.mu.Unlock()
		_ = id
		out = append(out, m)
	}
	return out
}

// TaskRunsStats 24h 统计（成功/失败/总数）。
type TaskRunsStats struct{ Runs, Success, Fail int }

// Stats24h 按任务统计近 24h task_runs（真实执行）。
func (e *Engine) Stats24h(taskID string) TaskRunsStats {
	var st TaskRunsStats
	if db.DB == nil {
		return st
	}
	_ = db.DB.QueryRow(`SELECT COUNT(*),
		COALESCE(SUM(CASE WHEN status='success' THEN 1 ELSE 0 END),0),
		COALESCE(SUM(CASE WHEN status='failed' THEN 1 ELSE 0 END),0)
		FROM task_runs WHERE task_id=? AND started_at > datetime(?, '-1 day')`, taskID, engineNowStr()).Scan(&st.Runs, &st.Success, &st.Fail)
	return st
}

// LatestRun 最近一次真实运行。
func (e *Engine) LatestRun(taskID string) *RunRecord {
	runs := e.History(taskID, 1)
	if len(runs) == 0 {
		return nil
	}
	return &runs[0]
}

// PurgeTaskRuns 清理 N 天前的任务运行历史（每日清理族调用——防无界增长；
// 静默策略已抑制成功轮落库，此为终态兜底）。
func PurgeTaskRuns(days int) {
	if db.DB == nil || days <= 0 {
		return
	}
	if _, err := db.DB.Exec(`DELETE FROM task_runs WHERE started_at < datetime('now', ?)`, fmt.Sprintf("-%d days", days)); err != nil {
		return
	}
	_ = days
}
