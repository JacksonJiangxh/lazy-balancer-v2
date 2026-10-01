// Package taskengine 是统一任务引擎（v2.0 四类型标准）：
// 定时(Scheduled)=排程槽驱动 | 常驻(Daemon)=自管理循环 | 循环(Periodic)=固定间隔
// 触发(Oneshot)=手动/代码触发。
// 引擎按 Kind 分流调度/记录/日志——零 flag 零补丁。
package taskengine

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"sync/atomic"
	"time"

	"lazy-balancer-v2/internal/db"
)

// ---- Kind：四类型 ----

type Kind string

const (
	KindScheduled Kind = "scheduled" // 定时：用户配置排程槽，引擎到点执行
	KindDaemon    Kind = "daemon"    // 常驻：自管理循环，引擎仅管生命周期
	KindPeriodic  Kind = "periodic"  // 循环：固定间隔，每轮独立执行
	KindOneshot   Kind = "oneshot"   // 触发：仅手动/代码触发
)

// Role 角色门。
type Role string

const (
	RoleAny        Role = "any"
	RoleMasterOnly Role = "master-only"
	RoleSlaveOnly  Role = "slave-only" // 仅测试注册使用（U1 P5 备注）
)

// RunContext 交给任务体的执行上下文。
type RunContext struct {
	Ctx      context.Context
	Trigger  string // manual | auto | startup
	Operator string // 手动操作者（审计归人）
	RunID    int64  // 引擎预插行 ID
}

// ---- Descriptor：任务声明 ----

type Descriptor struct {
	ID          string
	Family      string
	Name        string
	Description string
	Category    string
	Kind        Kind

	// Scheduled：返回下一次执行时间（引擎 sleep 到点；zero=无配置）
	NextSlotFn func() time.Time
	// Periodic：返回固定间隔
	IntervalFn func() time.Duration

	// 所有类型：Run 执行业务逻辑
	// Daemon: Run 应阻塞直到 ctx.Done()（自管理循环）
	// 其他: Run 执行一次后返回
	Run func(RunContext) error

	CancelHook func() bool
	EnabledFn  func() bool // false=暂停（引擎不调度）
	// BootSync：Oneshot 任务在引擎初始化尾部同步执行一次（trigger=startup）
	// ——启动型任务的唯一执行通道（曾 main.go 直调+legacy 记录旁路）。
	BootSync bool
	// PassiveCarrier：被动守护 daemon（Run=<-ctx.Done() 仅承载状态，真实服务
	// 由 lifecycle 独立管理）——控制面（重启按钮/调度开关）不适用于此类任务，
	// 展示为「仅状态视图」（L1-1 第 65 轮：曾假控制面——「停止集群同步」
	// 实际停不掉 SyncService）。仅 KindDaemon 有效。
	PassiveCarrier bool
	StatusFn       func() string    // 状态镜像
	ToggleFn       func(bool) error // 调度开关 setter
	ToggleName     string
	ManualRun      bool
	Cancelable     bool
	RunsOn         Role
	MasterOnly     bool
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

var ErrAlreadyRunning = errors.New("taskengine: 任务运行中")
var ErrNotFound = errors.New("taskengine: 任务未注册")

// ---- registration ----

type registration struct {
	desc Descriptor

	mu                 sync.Mutex
	running            bool
	cancel             context.CancelFunc
	lastCheck          time.Time // Periodic：最近到期判定基准
	nextScheduledTime  time.Time // Scheduled：下一槽（每 tick 重读——µs 级 SELECT）
	nextSlotComputedAt time.Time // 已弃用（保留字段零成本——U1 P5 备注可随下次触碰删）
	loopEnabled        bool      // 循环/调度开关
	pendingRestart     bool      // daemon restart 意图：旧 Run 退出后自动拉起新代（U1-P2-3）
}

// ---- Engine ----

type Engine struct {
	opts Options
	mu   sync.RWMutex
	regs map[string]*registration

	roleMu sync.RWMutex
	role   bool

	schedStop    chan struct{}
	bootSyncDone atomic.Bool
	schedDone    chan struct{}
	stopped      bool
	startedAt    time.Time
}

type Options struct {
	TickInterval time.Duration
}

func NewEngine(opts Options) *Engine {
	if opts.TickInterval <= 0 {
		opts.TickInterval = time.Second
	}
	e := &Engine{
		opts: opts, regs: map[string]*registration{}, role: true,
		schedStop: make(chan struct{}), schedDone: make(chan struct{}),
		startedAt: time.Now(),
	}
	go e.scheduleLoop()
	return e
}

func (e *Engine) StartedAt() time.Time { return e.startedAt }

func (e *Engine) Stop() {
	e.mu.Lock()
	if e.stopped {
		e.mu.Unlock()
		return
	}
	e.stopped = true
	close(e.schedStop)
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

func (e *Engine) SetRole(isMaster bool) {
	e.roleMu.Lock()
	e.role = isMaster
	e.roleMu.Unlock()
	// Daemon 生命周期随角色翻转：master-only daemon 在 demote 时停止、
	// promote 时拉起（loopEnabled 保持用户调度开关语义——重新启用即恢复）
	e.mu.RLock()
	daemons := make([]*registration, 0, len(e.regs))
	for id, r := range e.regs {
		_ = id
		if r.desc.Kind == KindDaemon {
			daemons = append(daemons, r)
		}
	}
	e.mu.RUnlock()
	for _, r := range daemons {
		if e.roleAllows(r.desc.RunsOn) {
			e.tryStartDaemon(r) // 内含 loopOn&&!running CAS——空闲且调度开才启动
			// L2-F2（第 65 轮）：promote 后 Periodic 即时首轮——曾 interval
			// 时钟在从节点照常推进，cert-renewal-scan/reconcile 首轮要等残余
			// 间隔（最坏 ~6h）。置零 lastCheck 使下一 tick 即到期。
			if r.desc.Kind == KindPeriodic {
				r.mu.Lock()
				r.lastCheck = time.Time{}
				r.mu.Unlock()
			}
			continue
		}
		// 角色不符：仅取消 Run（loopEnabled 保留——promote 后自动拉起，
		// 用户调度开关语义不被角色翻转隐式改写）
		r.mu.Lock()
		c := r.cancel
		r.mu.Unlock()
		if c != nil {
			c()
		}
	}
}

// IsTaskInFlight 任务 Run 是否在途（handler 同步单飞预检——L1-3）。
func (e *Engine) IsTaskInFlight(id string) bool {
	e.mu.RLock()
	r := e.regs[id]
	e.mu.RUnlock()
	if r == nil {
		return false
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.running
}

func (e *Engine) isMaster() bool {
	e.roleMu.RLock()
	defer e.roleMu.RUnlock()
	return e.role
}

// tryStartDaemon daemon 空闲且调度开时原子启动（锁内 CAS——并发调用方
// 只有一个胜出；U1-P2-4 统一入口）。
func (e *Engine) tryStartDaemon(r *registration) {
	r.mu.Lock()
	if !r.loopEnabled {
		r.mu.Unlock()
		return
	}
	if r.running {
		// U1-P2-3：在跑但已请求停止（restart 的 Stop 半程）——记意图，
		// 旧 Run goroutine 退出清理时自动拉起新代
		if r.cancel != nil {
			r.pendingRestart = true
		}
		r.mu.Unlock()
		return
	}
	r.running = true // 占位：并发者此处被拒
	r.mu.Unlock()
	e.startDaemon(r.desc.ID, r)
}

func (e *Engine) Register(d Descriptor) error {
	if d.ID == "" || d.Family == "" {
		return errors.New("taskengine: ID/Family 必填")
	}
	e.mu.Lock()
	defer e.mu.Unlock()
	e.regs[d.ID] = &registration{desc: d}
	return nil
}

// SetManualRun 补设手动触发语义。
func (e *Engine) SetManualRun(id string, ok bool) {
	e.mu.Lock()
	defer e.mu.Unlock()
	if r, exist := e.regs[id]; exist {
		r.desc.ManualRun = ok
	}
}

func (e *Engine) Trigger(id, trigger, operator string) error {
	e.mu.RLock()
	r := e.regs[id]
	e.mu.RUnlock()
	if r == nil {
		return ErrNotFound
	}
	if r.desc.MasterOnly && !e.isMaster() {
		return errors.New("taskengine: 该操作仅允许在主节点执行")
	}
	_, err := e.runNow(id, trigger, operator)
	return err
}

// RunSync 同步执行一次并返回 runID（handler 直调入口——响应需要行视图）。
func (e *Engine) RunSync(id, trigger, operator string) (int64, error) {
	return e.runNow(id, trigger, operator)
}

// RunBootSyncTasks 同步执行全部 BootSync Oneshot（InitTaskEngine 尾部调用
// ——面板监听前完成，保持「载入完成前系统不可达」不变量）。幂等：仅首轮
// 生效（重复调用零动作——启动执行全局恰一次）。
func (e *Engine) RunBootSyncTasks() {
	if !e.bootSyncDone.CompareAndSwap(false, true) {
		return
	}
	e.mu.RLock()
	type item struct {
		id string
		r  *registration
	}
	items := make([]item, 0, 4)
	for id, r := range e.regs {
		if r.desc.BootSync && r.desc.Kind == KindOneshot {
			items = append(items, item{id, r})
		}
	}
	e.mu.RUnlock()
	for _, it := range items {
		_, _ = e.runNow(it.id, "startup", "")
	}
}

func (e *Engine) Cancel(id string) bool {
	e.mu.RLock()
	r := e.regs[id]
	e.mu.RUnlock()
	if r == nil || !r.desc.Cancelable {
		return false
	}
	r.mu.Lock()
	c := r.cancel
	running := r.running
	r.mu.Unlock()
	hook := r.desc.CancelHook
	if hook != nil {
		ok := hook()
		// L1-6（第 65 轮）：manager 侧取消成功后同步取消引擎 ctx——Run 返回
		// 时 terminalStatus 判 cancelled（曾 manager 取消路径引擎 ctx 不动，
		// 终态落 failed，历史无法区分「用户取消」与「真失败」）
		if ok && c != nil && running {
			c()
		}
		return ok
	}
	if c == nil || !running {
		return false
	}
	c()
	return true
}

// ---- StartLoop/StopLoop：循环启停 ----
// Periodic/Scheduled: 设 loopEnabled（引擎按间隔/槽调度）
// Daemon: 启动/停止自管理循环

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
	// Daemon：CAS 启动（U1-P2-4：曾锁外读 running=并发双启动窗口；
	// SetRole/StartLoop 统一走 tryStartDaemon 单一入口）
	if r.desc.Kind == KindDaemon && e.roleAllows(r.desc.RunsOn) {
		e.tryStartDaemon(r)
	}
}

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
	c := r.cancel
	r.mu.Unlock()

	// Daemon：取消 Run 的 ctx
	if r.desc.Kind == KindDaemon && c != nil {
		c()
	}
}

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
	return loopOn && e.roleAllows(r.desc.RunsOn)
}

// ---- Daemon 生命周期 ----

func (e *Engine) startDaemon(id string, r *registration) {
	// 调用方已在锁内置 r.running=true（占位）；此处补 cancel 登记。
	runID := globalInsertRun(id, r.desc.Family, "auto")
	taskLogAppend(id, "[start] 常驻启动")
	// 2026-10-01 用户裁定：启动即记 success（启动是既成事实——成功列体现
	// 启动计数；原实现落 running 终态随停止更新，运行期成功列恒 0）
	e.finishRun(runID, "success", 0)

	ctx, cancel := context.WithCancel(context.Background())
	r.mu.Lock()
	r.cancel = cancel
	r.mu.Unlock()

	start := time.Now()
	go func() {
		err := r.desc.Run(RunContext{Ctx: ctx, Trigger: "auto", RunID: runID})
		dur := time.Since(start).Milliseconds()

		restart := false
		r.mu.Lock()
		r.running = false
		r.cancel = nil
		if r.pendingRestart {
			r.pendingRestart = false
			r.running = true // 立即占位防并发窗口
			restart = true
		}
		r.mu.Unlock()

		if err != nil && ctx.Err() == nil {
			// 异常退出（非取消）：补记 failed 行（真实时长与错误）
			failID := globalInsertRunAt(id, r.desc.Family, "auto", start.In(engineLocPtr()).Format("2006-01-02 15:04:05"))
			e.finishRun(failID, "failed", dur)
			taskLogAppend(id, fmt.Sprintf("[done] failed 耗时=%dms 触发=auto 错误=%s", dur, err.Error()))
		} else {
			taskLogAppend(id, fmt.Sprintf("[done] stopped 耗时=%dms 触发=auto（取消/正常退出）", dur))
		}
		if restart {
			e.startDaemon(id, r) // U1-P2-3：restart 意图落地——新代接续
		}
	}()
}

// ---- 历史与统计 ----

func (e *Engine) History(id string, limit int) []RunRecord {
	if limit <= 0 {
		limit = 20
	}
	if db.DB == nil {
		return nil
	}
	rows, err := db.DB.Query(
		`SELECT id, task_id, family, trigger, status, started_at,
		COALESCE(finished_at,''), COALESCE(duration_ms,0),
		COALESCE(stage,''), COALESCE(message,''), COALESCE(entry_count,0)
		FROM task_runs WHERE task_id=? ORDER BY id DESC LIMIT ?`, id, limit)
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

func (e *Engine) RecoverOrphans() int64 {
	res, err := db.DB.Exec(`UPDATE task_runs SET status='interrupted', finished_at=?, message=COALESCE(message,'')||'（进程重启回收）' WHERE status='running'`, engineNowStr())
	if err != nil {
		return 0
	}
	n, _ := res.RowsAffected()
	return n
}

// ---- 执行 ----

func (e *Engine) runNow(id, trigger, operator string) (int64, error) {
	e.mu.RLock()
	r := e.regs[id]
	e.mu.RUnlock()
	if r == nil {
		return 0, ErrNotFound
	}
	// 单飞 CAS：全部 Kind 统一拒绝并发（Daemon 无此路径——Trigger 不暴露）
	r.mu.Lock()
	if r.running {
		r.mu.Unlock()
		return 0, ErrAlreadyRunning
	}
	r.running = true
	ctx, cancel := context.WithCancel(context.Background())
	r.cancel = cancel
	r.mu.Unlock()

	// 记录策略（按 Kind，零 flag）：
	// Scheduled/Periodic/Oneshot: 每次执行落行；Daemon: 仅 startDaemon 落行
	runID := globalInsertRun(id, r.desc.Family, trigger)

	rc := RunContext{Ctx: ctx, Trigger: trigger, Operator: operator, RunID: runID}
	start := time.Now()
	if trigger == "manual" || trigger == "startup" {
		taskLogAppend(id, fmt.Sprintf("[start] %s触发", map[bool]string{true: "启动", false: "手动"}[trigger == "startup"]))
	}
	runErr := r.desc.Run(rc)
	status := terminalStatus(ctx, runErr)
	dur := time.Since(start).Milliseconds()
	msg := fmt.Sprintf("[done] %s 耗时=%dms 触发=%s", status, dur, trigger)
	if status == "failed" && runErr != nil {
		msg += " 错误=" + runErr.Error()
	}
	taskLogAppend(id, msg)

	r.mu.Lock()
	r.running = false
	r.cancel = nil
	// Scheduled：Run 已写新槽——重算缓存。若新槽仍为过去（业务失败未
	// 推进等），running 标志在 CAS 前防重入，此处值供下 tick 判定。
	if r.desc.Kind == KindScheduled && r.desc.NextSlotFn != nil {
		r.nextScheduledTime = r.desc.NextSlotFn()
	}
	r.mu.Unlock()
	cancel()

	if status == "failed" && runErr != nil {
		e.finishRunWithMessage(runID, status, dur, truncMsg(runErr))
	} else {
		e.finishRun(runID, status, dur)
	}
	return runID, runErr
}

func truncMsg(err error) string {
	m := err.Error()
	if len(m) > 500 {
		m = m[:500]
	}
	return m
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

// ---- 调度循环 ----

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
		if r == nil {
			continue
		}

		switch r.desc.Kind {
		case KindScheduled:
			// 排程感知：每 tick 重读 NextSlotFn（简单 SELECT——µs 级）；
			// 槽到点才触发 Run（中间零执行零落行零日志）；in-flight 不重入。
			r.mu.Lock()
			if !r.loopEnabled || r.running {
				r.mu.Unlock()
				continue
			}
			if r.desc.NextSlotFn != nil {
				r.nextScheduledTime = r.desc.NextSlotFn()
			}
			due := !r.nextScheduledTime.IsZero() && now.After(r.nextScheduledTime)
			r.mu.Unlock()
			if due && e.roleAllows(r.desc.RunsOn) {
				go func(rid string) { _, _ = e.runNow(rid, "auto", "") }(id)
			}

		case KindPeriodic:
			// 固定间隔：每轮独立执行（Run→exit→记录）；in-flight 跳过本轮
			r.mu.Lock()
			due := r.loopEnabled && !r.running && (r.lastCheck.IsZero() || now.Sub(r.lastCheck) >= r.desc.IntervalFn())
			if due {
				r.lastCheck = now
			}
			r.mu.Unlock()
			if due && e.roleAllows(r.desc.RunsOn) {
				go func(rid string) { _, _ = e.runNow(rid, "auto", "") }(id)
			}

		case KindDaemon:
			// 不进周期 tick——由 StartLoop 启动（Run 阻塞直到取消）
		case KindOneshot:
			// 不进周期 tick——仅 Trigger
		}
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

// ---- 时区 ----

var engineLocAtomic atomic.Value

func init() { engineLocAtomic.Store(time.Local) }

func SetLocation(loc *time.Location) {
	if loc != nil {
		engineLocAtomic.Store(loc)
	}
}

func engineLocPtr() *time.Location { return engineLocAtomic.Load().(*time.Location) }

func engineNowStr() string { return time.Now().In(engineLocPtr()).Format("2006-01-02 15:04:05") }

// ---- 日志 ----

var taskLogDir string

func SetLogDir(dir string) { taskLogDir = dir }

// LogDir 当前任务日志目录（B3：certjoblog 子目录挂靠点；空串=未初始化）。
func LogDir() string { return taskLogDir }

func TaskLogPath(taskID string) string {
	if taskLogDir == "" {
		return ""
	}
	return filepath.Join(taskLogDir, taskID+".log")
}

func taskLogAppend(taskID, line string) {
	path := TaskLogPath(taskID)
	if path == "" {
		return
	}
	_ = os.MkdirAll(taskLogDir, 0755)
	f, err := os.OpenFile(path, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0644)
	if err != nil {
		return
	}
	defer f.Close()
	fmt.Fprintf(f, "%s %s\n", engineNowStr(), line)
}

// ---- DB 落库 ----

func globalInsertRun(taskID, family, trigger string) int64 {
	return globalInsertRunAt(taskID, family, trigger, engineNowStr())
}

func globalInsertRunAt(taskID, family, trigger, startedAt string) int64 {
	if db.DB == nil {
		return 0
	}
	res, err := db.DB.Exec(`INSERT INTO task_runs (task_id, family, trigger, status, started_at) VALUES (?,?,?,'running',?)`, taskID, family, trigger, startedAt)
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
	_, _ = db.DB.Exec(`UPDATE task_runs SET status=?, finished_at=?, duration_ms=? WHERE id=?`, status, engineNowStr(), durMs, runID)
}

func (e *Engine) finishRunWithMessage(runID int64, status string, durMs int64, message string) {
	if runID <= 0 || db.DB == nil {
		return
	}
	_, _ = db.DB.Exec(`UPDATE task_runs SET status=?, finished_at=?, duration_ms=?, message=? WHERE id=?`, status, engineNowStr(), durMs, message, runID)
}

// RecordRunStart/Finish 族侧记录（legacy 路径：非引擎调用的直接执行）
func RecordRunStart(taskID, family, trigger string) int64 {
	return globalInsertRun(taskID, family, trigger)
}

func RecordRunFinish(runID int64, status string, durMs int64, message string) {
	if runID <= 0 {
		return
	}
	if message != "" {
		_, _ = db.DB.Exec(`UPDATE task_runs SET status=?, finished_at=?, duration_ms=?, message=? WHERE id=?`, status, engineNowStr(), durMs, message, runID)
		return
	}
	_, _ = db.DB.Exec(`UPDATE task_runs SET status=?, finished_at=?, duration_ms=? WHERE id=?`, status, engineNowStr(), durMs, runID)
}

// ---- 元数据 ----

type TaskMeta struct {
	ID             string `json:"id"`
	Family         string `json:"family"`
	Name           string `json:"name"`
	Description    string `json:"description"`
	Category       string `json:"category"`
	Kind           Kind   `json:"kind"`
	IntervalSec    int    `json:"interval_sec"`
	NextSlot       string `json:"next_slot"`
	Enabled        bool   `json:"enabled"`
	StatusMirror   string `json:"status_mirror"`
	Controllable   bool   `json:"controllable"`
	Cancelable     bool   `json:"cancelable"`
	Toggleable     bool   `json:"toggleable"`
	ToggleName     string `json:"toggle_name"`
	LoopOn         bool   `json:"loop_on"`
	Running        bool   `json:"running"` // Daemon：Run 实际存活（角色门/停止后=false）
	CanTrigger     bool   `json:"can_trigger"`
	StatusViewOnly bool   `json:"status_view_only"` // 被动守护：仅状态视图（控制面不适用）
}

// Lookup 单任务元数据（U1-P4-2：handler 为取单字段跑全量 DescribeAll
// ~12-18 条 SQL——现仅执行该任务的 Fn）。
func (e *Engine) Lookup(id string) (TaskMeta, bool) {
	e.mu.RLock()
	r := e.regs[id]
	e.mu.RUnlock()
	if r == nil {
		return TaskMeta{}, false
	}
	r.mu.Lock()
	loopOn, running := r.loopEnabled, r.running
	r.mu.Unlock()
	m := TaskMeta{
		ID: id, Family: r.desc.Family, Name: r.desc.Name,
		Description: r.desc.Description, Category: r.desc.Category, Kind: r.desc.Kind,
		CanTrigger:     r.desc.ManualRun,
		Cancelable:     r.desc.Cancelable,
		Toggleable:     r.desc.ToggleFn != nil,
		ToggleName:     r.desc.ToggleName,
		LoopOn:         loopOn,
		Running:        running,
		Enabled:        true,
		Controllable:   r.desc.Kind == KindDaemon && !r.desc.PassiveCarrier,
		StatusViewOnly: r.desc.Kind == KindDaemon && r.desc.PassiveCarrier,
	}
	if r.desc.IntervalFn != nil {
		m.IntervalSec = int(r.desc.IntervalFn().Seconds())
	}
	if r.desc.NextSlotFn != nil {
		if t := r.desc.NextSlotFn(); !t.IsZero() {
			m.NextSlot = t.In(engineLocPtr()).Format("2006-01-02 15:04:05")
		}
	}
	if r.desc.EnabledFn != nil {
		m.Enabled = r.desc.EnabledFn()
	}
	if r.desc.StatusFn != nil {
		m.StatusMirror = r.desc.StatusFn()
	}
	return m, true
}

func (e *Engine) DescribeAll() []TaskMeta {
	type snap struct {
		id      string
		desc    Descriptor
		loopOn  bool
		running bool
	}
	e.mu.RLock()
	snaps := make([]snap, 0, len(e.regs))
	for id, r := range e.regs {
		r.mu.Lock()
		loopOn, running := r.loopEnabled, r.running
		r.mu.Unlock()
		snaps = append(snaps, snap{id: id, desc: r.desc, loopOn: loopOn, running: running})
	}
	e.mu.RUnlock()

	out := make([]TaskMeta, 0, len(snaps))
	for _, s := range snaps {
		m := TaskMeta{
			ID: s.id, Family: s.desc.Family, Name: s.desc.Name,
			Description: s.desc.Description, Category: s.desc.Category, Kind: s.desc.Kind,
			CanTrigger:     s.desc.ManualRun,
			Cancelable:     s.desc.Cancelable,
			Toggleable:     s.desc.ToggleFn != nil,
			ToggleName:     s.desc.ToggleName,
			LoopOn:         s.loopOn,
			Running:        s.running,
			Enabled:        true,
			Controllable:   s.desc.Kind == KindDaemon && !s.desc.PassiveCarrier, // 常驻族可启停（被动守护除外=L1-1）
			StatusViewOnly: s.desc.Kind == KindDaemon && s.desc.PassiveCarrier,
		}
		if s.desc.IntervalFn != nil {
			m.IntervalSec = int(s.desc.IntervalFn().Seconds())
		}
		if s.desc.NextSlotFn != nil {
			if t := s.desc.NextSlotFn(); !t.IsZero() {
				m.NextSlot = t.In(engineLocPtr()).Format("2006-01-02 15:04:05")
			}
		}
		if s.desc.EnabledFn != nil {
			m.Enabled = s.desc.EnabledFn()
		}
		if s.desc.StatusFn != nil {
			m.StatusMirror = s.desc.StatusFn()
		}
		out = append(out, m)
	}
	return out
}

// ---- 统计 ----

type TaskRunsStats struct{ Runs, Success, Fail int }

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

func (e *Engine) LatestRun(taskID string) *RunRecord {
	runs := e.History(taskID, 1)
	if len(runs) == 0 {
		return nil
	}
	return &runs[0]
}

func PurgeTaskRuns(days int) int64 {
	if db.DB == nil || days <= 0 {
		return 0
	}
	res, err := db.DB.Exec(`DELETE FROM task_runs WHERE started_at < datetime(?, ?)`, engineNowStr(), fmt.Sprintf("-%d days", days))
	if err != nil {
		return 0
	}
	n, _ := res.RowsAffected()
	return n
}

// ---- 业务侧日志 helper ----

func TeeTaskLogTime(taskID, level, stage, message string) {
	TeeTaskLog(taskID, time.Now().In(engineLocPtr()).Format("2006/01/02 15:04:05"), level, stage, message)
}

func TeeTaskLog(taskID, timestamp, level, stage, message string) {
	path := TaskLogPath(taskID)
	if path == "" {
		return
	}
	_ = os.MkdirAll(taskLogDir, 0755)
	f, err := os.OpenFile(path, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0644)
	if err != nil {
		return
	}
	defer f.Close()
	fmt.Fprintf(f, "%s [%s] %s - %s\n", timestamp, level, stage, message)
}

func LogTaskLine(taskID, line string) { taskLogAppend(taskID, line) }
