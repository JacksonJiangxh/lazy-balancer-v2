package taskengine

// 调度自动停摆与唤醒复位钉测：
//   - Periodic 的 IntervalFn 返回非正周期必须停调，且停调来源机器可读
//     （failed 运行行 + [error] 日志），不得与用户主动停止同形；
//   - Scheduled「槽未推进+失败」的兜底退避必须有终点：连续 N 轮自动轮仍未
//     推进即停调，不得按 30s 节拍无限落行；
//   - RearmLoop 越过停止态时对 Scheduled 复位槽消费水位——否则旧水位会
//     永久压住当前槽（loop_on=true 却零投递）；
//   - 调度闭包 panic 告警按任务分桶，跨任务不得互相遮蔽。

import (
	"errors"
	"os"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"lazy-balancer-v2/internal/db"
)

// loopEnabledOf 读取任务的调度开关（装配字段，测试内直接读）。
func loopEnabledOf(t *testing.T, e *Engine, id string) bool {
	t.Helper()
	e.mu.RLock()
	r := e.regs[id]
	e.mu.RUnlock()
	if r == nil {
		t.Fatalf("任务 %s 未注册", id)
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.loopEnabled
}

// Given Periodic 任务的 IntervalFn 返回 0（配置读错被映射为零值等形态）。
// When tick 求值间隔。
// Then 停止该任务调度且不执行 Run，同时落一条 failed 运行行（状态列可见、
// 可与用户主动停止区分）与 [error] 日志。
func TestEngine_PeriodicNonPositiveIntervalStopsWithFailedRun(t *testing.T) {
	e := newTestEngine(t)
	const id = "t-nonpositive-interval"
	var runs atomic.Int32
	if err := e.Register(Descriptor{
		ID: id, Family: "t", Name: "非正周期", Kind: KindPeriodic, RunsOn: RoleAny,
		IntervalFn: func() time.Duration { return 0 },
		Run:        func(RunContext) error { runs.Add(1); return nil },
	}); err != nil {
		t.Fatal(err)
	}
	e.SetRole(true)
	e.StartLoop(id)

	waitForEngine(t, "非正周期停调", 2*time.Second, func() bool { return !loopEnabledOf(t, e, id) })
	if got := runs.Load(); got != 0 {
		t.Fatalf("非正周期不得执行 Run, got %d 次", got)
	}
	var status, message string
	if err := db.DB.QueryRow(`SELECT status, COALESCE(message,'') FROM task_runs WHERE task_id=? ORDER BY id DESC LIMIT 1`, id).
		Scan(&status, &message); err != nil {
		t.Fatalf("读取停调运行行: %v", err)
	}
	if status != "failed" || !strings.Contains(message, "IntervalFn 必须返回正周期") {
		t.Fatalf("停调应落 failed 行并带原因, got status=%q message=%q", status, message)
	}
	// 停调是终态：再等若干个 tick 不得追加运行行（循环已关闭）。
	time.Sleep(100 * time.Millisecond)
	if got := countRuns(t, id); got != 1 {
		t.Fatalf("停调后仍追加运行行, 共 %d 行（应在停调时恰落一行）", got)
	}
}

// Given Scheduled 任务的自动轮已连续失败且业务永不推进槽（streak 预置到
// 终点前一轮，槽缓存=当前过期槽）。
// When 第 scheduledFailStreakStopLimit 轮自动轮仍失败。
// Then 停止该任务调度（退避兜底必须有终点），留 [error] 日志与失败行；关→开
// 调度可恢复（不是不可恢复状态）。
func TestEngine_ScheduledUnadvancedSlotStopsAfterStreakLimit(t *testing.T) {
	e := newTestEngineWithOptions(t, Options{TickInterval: time.Hour})
	pastSlot := time.Now().Add(-time.Minute)
	const id = "t-streak-stop"
	if err := e.Register(Descriptor{
		ID: id, Family: "t", Name: "槽未推进停调", Kind: KindScheduled, RunsOn: RoleAny,
		NextSlotFn: func() time.Time { return pastSlot },
		Run:        func(RunContext) error { return os.ErrDeadlineExceeded },
	}); err != nil {
		t.Fatal(err)
	}
	e.SetRole(true)
	e.StartLoop(id)
	// 任务日志落盘目录（默认空=不写文件）——本用例断言 [error] 留痕。
	oldLogDir := LogDir()
	SetLogDir(t.TempDir())
	t.Cleanup(func() { SetLogDir(oldLogDir) })
	// tick 已按该槽求值过（prevSlot=同一过期槽）才会进退避分支——直接预置。
	e.mu.RLock()
	r := e.regs[id]
	e.mu.RUnlock()
	r.mu.Lock()
	r.nextScheduledTime = pastSlot
	r.schedFailStreak = scheduledFailStreakStopLimit - 1
	r.mu.Unlock()

	if _, err := e.RunSync(id, "auto", ""); err == nil {
		t.Fatal("注入失败的任务应记录失败")
	}
	if loopEnabledOf(t, e, id) {
		t.Fatalf("槽连续 %d 轮未推进且自动轮失败，必须停止调度（无终点会按 30s 节拍无限落行）", scheduledFailStreakStopLimit)
	}
	if got := countRuns(t, id); got != 1 {
		t.Fatalf("运行行 %d, want 1（停调轮自身的失败行）", got)
	}
	logBody, err := os.ReadFile(TaskLogPath(id))
	if err != nil {
		t.Fatalf("读取任务日志: %v", err)
	}
	if !strings.Contains(string(logBody), "已停止该任务调度") {
		t.Fatalf("停调必须留 [error] 日志，实际日志:\n%s", string(logBody))
	}
	// 关→开=显式恢复：复位槽水位与退避后照常调度。
	e.StartLoop(id)
	if !loopEnabledOf(t, e, id) {
		t.Fatal("StartLoop 关→开应恢复调度")
	}
	if _, done, retry, streak := scheduleStateOf(t, e, id); !done.IsZero() || !retry.IsZero() || streak != 0 {
		t.Fatalf("恢复后排程进度未复位: done=%v retry=%v streak=%d", done, retry, streak)
	}
}

// Given Scheduled 任务停调前 schedDoneSlot 已等于当前 due 槽（成功落定未推进
// 槽/用户取消已到期槽的形态）。
// When 业务唤醒经 RearmLoop(hasWork=true) 越过停止态。
// Then 槽水位与退避被复位，当前槽可投递（旧水位曾让重开后零投递）。
func TestEngine_RearmLoopResetsScheduledProgress(t *testing.T) {
	e := newTestEngine(t)
	pastSlot := time.Now().Add(-time.Minute)
	var runs atomic.Int32
	const id = "t-rearm-reset"
	if err := e.Register(Descriptor{
		ID: id, Family: "t", Name: "唤醒复位", Kind: KindScheduled, RunsOn: RoleAny,
		NextSlotFn: func() time.Time { return pastSlot },
		Run:        func(RunContext) error { runs.Add(1); return nil },
	}); err != nil {
		t.Fatal(err)
	}
	e.SetRole(true)
	e.StartLoop(id)
	waitForEngine(t, "首轮消费本槽", 2*time.Second, func() bool { return runs.Load() == 1 })
	// 首轮成功后本槽已被消费（水位=槽值），随后用户停止调度。
	waitForEngine(t, "槽被消费", 2*time.Second, func() bool {
		_, done, _, _ := scheduleStateOf(t, e, id)
		return !done.IsZero()
	})
	e.StopLoop(id)

	e.RearmLoop(id, true)
	slot, done, retry, streak := scheduleStateOf(t, e, id)
	if !slot.IsZero() || !done.IsZero() || !retry.IsZero() || streak != 0 {
		t.Fatalf("越过停止态未复位排程进度: slot=%v done=%v retry=%v streak=%d", slot, done, retry, streak)
	}
	waitForEngine(t, "越过停止后补跑", 2*time.Second, func() bool { return runs.Load() == 2 })
}

// Given 两个任务的调度闭包先后 panic。
// When 告警限流判定。
// Then 两个任务各自留一条告警（全局单槽会让后者的首报被前者的 1 分钟窗口
// 吞掉）；同一任务重复 panic 只累计抑制计数、不刷新放行时刻。
func TestWarnSchedFnPanicThrottlesPerKind(t *testing.T) {
	schedFnPanicMu.Lock()
	schedFnPanicLast = map[string]time.Time{}
	schedFnPanicSuppressed = map[string]int{}
	schedFnPanicMu.Unlock()
	t.Cleanup(func() {
		schedFnPanicMu.Lock()
		schedFnPanicLast = map[string]time.Time{}
		schedFnPanicSuppressed = map[string]int{}
		schedFnPanicMu.Unlock()
	})

	warnSchedFnPanic("task-a.IntervalFn", "boom-a")
	warnSchedFnPanic("task-b.NextSlotFn", "boom-b")

	schedFnPanicMu.Lock()
	firstA, okA := schedFnPanicLast["task-a.IntervalFn"]
	_, okB := schedFnPanicLast["task-b.NextSlotFn"]
	schedFnPanicMu.Unlock()
	if !okA || !okB {
		t.Fatalf("按任务分桶失败：a=%v b=%v（跨任务不得互相遮蔽）", okA, okB)
	}

	warnSchedFnPanic("task-a.IntervalFn", "boom-a-again")
	schedFnPanicMu.Lock()
	lastA := schedFnPanicLast["task-a.IntervalFn"]
	suppressed := schedFnPanicSuppressed["task-a.IntervalFn"]
	schedFnPanicMu.Unlock()
	if suppressed != 1 {
		t.Fatalf("同类 panic 抑制计数=%d, want 1（被抑制次数不得丢弃）", suppressed)
	}
	if !lastA.Equal(firstA) {
		t.Fatal("限流窗口内不得刷新放行时刻（否则每分钟洪峰无上限）")
	}
}

// Given 引擎已停止。
// When 注册新任务。
// Then 响亮拒绝（ErrEngineStopped）——已停引擎的调度 goroutine 已退出，
// 注册成功只会得到「已注册但永不被调度」的静默形态（StartLoop 对 stopped
// 恒 no-op），装配方须显式新建引擎。
func TestEngine_RegisterRejectedAfterStop(t *testing.T) {
	e := NewEngine(Options{TickInterval: time.Hour})
	e.Stop()
	err := e.Register(Descriptor{ID: "t-after-stop", Family: "t", Name: "停止后注册", Kind: KindOneshot,
		Run: func(RunContext) error { return nil }})
	if !errors.Is(err, ErrEngineStopped) {
		t.Fatalf("已停引擎注册 err=%v, want ErrEngineStopped", err)
	}
}
