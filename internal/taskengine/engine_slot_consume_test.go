package taskengine

// 排程槽生命周期钉测：①同一槽只执行一次（成功落定未推进=消费本槽）；
// ②用户取消在途定时轮=消费本槽（不立即重投），槽推进后恢复；
// ③槽闭包降频求值（远期/已消费槽不每 tick 读 DB）；④退避 WARN 首轮
// 5 分钟地板；⑤常驻净返回提前退出=异常（failed+有界重拉）；
// ⑥任务日志目录熔断；⑦Periodic 角色门前置。

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"

	"lazy-balancer-v2/internal/db"
	"testing"
	"time"
)

// 缩短槽重评地板（默认 1min 在测试时间尺度外）——包级单测串行执行；地板是
// 原子值（tick 读 vs 本 cleanup 写回并发，见 engine.go 的声明注释）。
func shrinkSlotEvalFloor(t *testing.T, d time.Duration) {
	t.Helper()
	old := schedSlotEvalFloor.Load()
	schedSlotEvalFloor.Store(int64(d))
	t.Cleanup(func() { schedSlotEvalFloor.Store(old) })
}

// Given Scheduled 任务成功落定但业务未推进槽（槽仍是过期旧值）。
// When tick 循环运转。
// Then 同一槽只执行一次——不再按 tick 频率重投（旧形态 ≈35 次/350ms）。
func TestEngine_ScheduledSuccessConsumesStaleSlot(t *testing.T) {
	e := newTestEngine(t)
	pastSlot := time.Now().Add(-time.Minute)
	var runs atomic.Int32
	if err := e.Register(Descriptor{ID: "t-once", Family: "t", Name: "成功消费槽", Kind: KindScheduled,
		NextSlotFn: func() time.Time { return pastSlot },
		Run: func(rc RunContext) error {
			runs.Add(1)
			return nil
		}}); err != nil {
		t.Fatal(err)
	}
	e.SetRole(true)
	e.StartLoop("t-once")

	time.Sleep(350 * time.Millisecond)
	if got := runs.Load(); got != 1 {
		t.Fatalf("同一过期槽成功落定后不得重投, got %d, want 1", got)
	}
	if got := countRuns(t, "t-once"); got != 1 {
		t.Fatalf("task_runs 落行 %d, want 1（重投风暴已收敛为槽消费）", got)
	}
}

// Given 同上，但业务随后把槽推进到新的（仍过期）值。
// When 槽值变化。
// Then 新槽恢复到期语义——再执行一次后再次消费（槽推进=新工作）。
func TestEngine_ScheduledAdvancedPastSlotRefiresOnce(t *testing.T) {
	e := newTestEngine(t)
	shrinkSlotEvalFloor(t, 20*time.Millisecond)
	slot1 := time.Now().Add(-2 * time.Minute)
	var slot atomic.Value
	slot.Store(slot1)
	var runs atomic.Int32
	if err := e.Register(Descriptor{ID: "t-refire", Family: "t", Name: "槽推进再投", Kind: KindScheduled,
		NextSlotFn: func() time.Time { return slot.Load().(time.Time) },
		Run: func(rc RunContext) error {
			runs.Add(1)
			return nil
		}}); err != nil {
		t.Fatal(err)
	}
	e.SetRole(true)
	e.StartLoop("t-refire")

	waitForEngine(t, "首槽执行", 2*time.Second, func() bool { return runs.Load() == 1 })
	// 业务推进到新的过期槽（槽值变化=新排程）——地板周期内重评后应再投一次。
	slot.Store(time.Now().Add(-time.Minute))
	waitForEngine(t, "新槽再投", 2*time.Second, func() bool { return runs.Load() == 2 })
	time.Sleep(200 * time.Millisecond)
	if got := runs.Load(); got != 2 {
		t.Fatalf("新槽消费后不得再重投, got %d, want 2", got)
	}
}

// Given 在途 Scheduled 自动轮（Run 阻塞）+ 用户点「取消」。
// When Cancel 命中。
// Then 终态落 cancelled 且本槽被消费——tick 不得按「槽仍过期」立即重投
// （旧形态下一 tick 整轮重投：全量重下载/重复整包备份）。
func TestEngine_ScheduledUserCancelConsumesSlot(t *testing.T) {
	e := newTestEngine(t)
	pastSlot := time.Now().Add(-time.Minute)
	started := make(chan struct{})
	var startOnce sync.Once
	var runs atomic.Int32
	if err := e.Register(Descriptor{ID: "t-cancel", Family: "t", Name: "取消消费槽", Kind: KindScheduled,
		Cancelable: true,
		NextSlotFn: func() time.Time { return pastSlot },
		Run: func(rc RunContext) error {
			runs.Add(1)
			startOnce.Do(func() { close(started) })
			<-rc.Ctx.Done()
			return rc.Ctx.Err()
		}}); err != nil {
		t.Fatal(err)
	}
	e.SetRole(true)
	e.StartLoop("t-cancel")

	select {
	case <-started:
	case <-time.After(2 * time.Second):
		t.Fatal("首论未启动")
	}
	if !e.Cancel("t-cancel") {
		t.Fatal("在途可取消任务 Cancel 应返回 true")
	}
	waitForEngine(t, "取消落定 cancelled 终态", 2*time.Second, func() bool {
		lr := e.LatestRun("t-cancel")
		return lr != nil && lr.Status == "cancelled"
	})
	// 取消落定后槽仍过期（业务未推进）——本槽已消费，不得重投。
	time.Sleep(350 * time.Millisecond)
	if got := runs.Load(); got != 1 {
		t.Fatalf("用户取消后同一过期槽不得重投, got %d, want 1", got)
	}
	if got := countRuns(t, "t-cancel"); got != 1 {
		t.Fatalf("task_runs 落行 %d, want 1（仅被取消轮）", got)
	}
}

// Given Scheduled 槽远期（+1h）/临近（+10s，前导窗内）。
// When 手动驱动 tick。
// Then 远期槽仅首 tick 求值（之后零闭包求值零 DB 读）；前导窗内每 tick
// 求值（到点即投的新鲜度不变）。
func TestEngine_ScheduledFarSlotSkipsClosureEval(t *testing.T) {
	e := newTestEngineWithOptions(t, Options{TickInterval: time.Hour})
	var slotEvals, enabledEvals atomic.Int32
	if err := e.Register(Descriptor{ID: "t-far", Family: "t", Name: "远期槽", Kind: KindScheduled, RunsOn: RoleAny,
		NextSlotFn: func() time.Time {
			slotEvals.Add(1)
			return time.Now().Add(time.Hour)
		},
		EnabledFn: func() bool {
			enabledEvals.Add(1)
			return true
		},
		Run: func(RunContext) error { return nil },
	}); err != nil {
		t.Fatal(err)
	}
	e.SetRole(true)
	e.StartLoop("t-far")

	for range 5 {
		e.tick()
	}
	if got := slotEvals.Load(); got != 1 {
		t.Fatalf("远期槽 NextSlotFn 求值 %d 次, want 1（首 tick 求值后进入降频）", got)
	}
	if got := enabledEvals.Load(); got != 1 {
		t.Fatalf("远期槽 EnabledFn 求值 %d 次, want 1", got)
	}

	// 前导窗内（slot-now < 30s）每 tick 求值。
	var nearEvals atomic.Int32
	if err := e.Register(Descriptor{ID: "t-near", Family: "t", Name: "临近槽", Kind: KindScheduled, RunsOn: RoleAny,
		NextSlotFn: func() time.Time {
			nearEvals.Add(1)
			return time.Now().Add(10 * time.Second)
		},
		Run: func(RunContext) error { return nil },
	}); err != nil {
		t.Fatal(err)
	}
	e.StartLoop("t-near")
	e.tick()
	e.tick()
	e.tick()
	if got := nearEvals.Load(); got != 3 {
		t.Fatalf("前导窗内槽每 tick 求值, got %d, want 3", got)
	}
}

// Given 「失败（槽未推进）→ 成功（新槽）→ 再失败」交替形态。
// When 退避 WARN 首轮豁免无地板（旧形态）。
// Then 第二个首轮 WARN 被 5 分钟地板压制——日志仅 1 条退避 WARN
// （旧形态两轮各 1 条；生产交替失败可 1 条/s 刷屏）。
func TestEngine_ScheduledBackoffFirstWarnFloor(t *testing.T) {
	e := newTestEngine(t)
	shrinkSlotEvalFloor(t, 20*time.Millisecond)
	oldDir := LogDir()
	SetLogDir(t.TempDir())
	t.Cleanup(func() { SetLogDir(oldDir) })

	base := time.Now()
	slot := []atomic.Value{{}, {}, {}}
	slot[0].Store(base.Add(-3 * time.Minute))
	slot[1].Store(base.Add(-2 * time.Minute))
	slot[2].Store(base.Add(-time.Minute))
	var idx atomic.Int32
	var failNext atomic.Bool
	failNext.Store(true)
	var runs atomic.Int32
	if err := e.Register(Descriptor{ID: "t-warnfloor", Family: "t", Name: "首轮 WARN 地板", Kind: KindScheduled,
		NextSlotFn: func() time.Time { return slot[idx.Load()].Load().(time.Time) },
		Run: func(rc RunContext) error {
			runs.Add(1)
			if failNext.Load() {
				return errors.New("boom")
			}
			return nil
		}}); err != nil {
		t.Fatal(err)
	}
	e.SetRole(true)
	e.StartLoop("t-warnfloor")

	// 轮 1：失败（streak=1，首次 WARN 必落）。
	waitForEngine(t, "首轮失败落定", 2*time.Second, func() bool {
		lr := e.LatestRun("t-warnfloor")
		return lr != nil && lr.Status == "failed"
	})
	// 轮 2：推进到新过期槽 + 成功（消费新槽、清零 streak）。
	idx.Store(1)
	failNext.Store(false)
	waitForEngine(t, "第二轮成功落定", 3*time.Second, func() bool {
		lr := e.LatestRun("t-warnfloor")
		return lr != nil && lr.Status == "success"
	})
	// 轮 3：再推进到新过期槽 + 失败——streak 重回 1，距上次 WARN 远小于
	// 5 分钟地板，WARN 被压制。
	idx.Store(2)
	failNext.Store(true)
	waitForEngine(t, "第三轮失败落定", 3*time.Second, func() bool {
		lr := e.LatestRun("t-warnfloor")
		return lr != nil && lr.Status == "failed"
	})
	if got := runs.Load(); got != 3 {
		t.Fatalf("执行轮次=%d, want 3", got)
	}
	body, err := os.ReadFile(TaskLogPath("t-warnfloor"))
	if err != nil {
		t.Fatalf("读任务日志: %v", err)
	}
	if n := strings.Count(string(body), "[warn] 排程槽未推进"); n != 1 {
		t.Fatalf("退避 WARN 行数=%d, want 1（第二个首轮受 5 分钟地板压制）:\n%s", n, body)
	}
}

// Given 常驻任务 Run 未收到取消信号却净返回（实现缺陷/内部条件早退）。
// When 调度开关仍开。
// Then 视为异常退出：落 failed 行 + 按退避有界重拉（旧形态落
// 「[done] stopped」呈现空闲，任务永久停摆零信号）。
func TestEngine_DaemonPrematureCleanExitRelaunches(t *testing.T) {
	e := newTestEngineWithOptions(t, Options{
		TickInterval:        10 * time.Millisecond,
		DaemonRestartDelays: []time.Duration{20 * time.Millisecond, 20 * time.Millisecond, 20 * time.Millisecond},
	})
	var calls atomic.Int32
	if err := e.Register(Descriptor{ID: "t-premature", Family: "t", Name: "常驻早退", Kind: KindDaemon,
		Run: func(rc RunContext) error {
			if calls.Add(1) == 1 {
				return nil // 早退：ctx 未取消、调度仍开
			}
			<-rc.Ctx.Done()
			return nil
		}}); err != nil {
		t.Fatal(err)
	}
	e.SetRole(true)
	e.StartLoop("t-premature")

	waitForEngine(t, "早退后有界重拉", 2*time.Second, func() bool { return calls.Load() >= 2 })
	// 重拉代会再插 boot success 行（id 更大）——按 failed 行计数断言，
	// 不能用 LatestRun（最新行恒为新一代 boot）。
	waitForEngine(t, "早退轮落 failed 行", 2*time.Second, func() bool {
		var n int
		if err := db.DB.QueryRow(`SELECT COUNT(*) FROM task_runs WHERE task_id=? AND status='failed' AND message LIKE '%提前返回%'`, "t-premature").Scan(&n); err != nil {
			return false
		}
		return n >= 1
	})
	e.StopLoop("t-premature")
}

// Given Periodic 任务挂 EnabledFn+IntervalFn（master-only），节点为从角色。
// When tick 若干轮。
// Then 角色不符整分支跳过——EnabledFn/IntervalFn 零求值（与 Scheduled
// 角色门前置同型对称）；promote 后下一 tick 立即恢复。
func TestEngine_PeriodicRoleGateSkipsClosureEval(t *testing.T) {
	e := newTestEngineWithOptions(t, Options{TickInterval: time.Hour})
	var enabledEvals, intervalEvals, runs atomic.Int32
	if err := e.Register(Descriptor{ID: "t-prole", Family: "t", Name: "周期角色门", Kind: KindPeriodic, RunsOn: RoleMasterOnly,
		EnabledFn:  func() bool { enabledEvals.Add(1); return true },
		IntervalFn: func() time.Duration { intervalEvals.Add(1); return time.Hour },
		Run:        func(RunContext) error { runs.Add(1); return nil },
	}); err != nil {
		t.Fatal(err)
	}
	e.SetRole(false)
	e.StartLoop("t-prole")

	for range 5 {
		e.tick()
	}
	if got := enabledEvals.Load(); got != 0 {
		t.Fatalf("从节点 EnabledFn 求值 %d 次, want 0（角色门未前置）", got)
	}
	if got := intervalEvals.Load(); got != 0 {
		t.Fatalf("从节点 IntervalFn 求值 %d 次, want 0（角色门未前置）", got)
	}
	if got := runs.Load(); got != 0 {
		t.Fatalf("从节点执行 %d 次, want 0", got)
	}

	// promote：节拍置零→下一 tick 立即到期投递。
	e.SetRole(true)
	e.tick()
	waitForEngine(t, "promote 后首轮投递", 2*time.Second, func() bool { return runs.Load() == 1 })
}

// Given 任务日志目录不可创建（路径被同名文件占用）。
// When 连续写入多行任务日志。
// Then 一次性 ERROR 进入熔断，熔断期静默丢弃（不再逐行 WARNING 刷
// 运行日志）；目录恢复后经探测退出熔断并补 INFO，后续行正常落盘。
func TestEngine_TaskLogDirCircuitBreaker(t *testing.T) {
	buf := captureEngineLog(t)

	oldProbe := taskLogDirProbeInterval
	taskLogDirProbeInterval = 20 * time.Millisecond
	t.Cleanup(func() { taskLogDirProbeInterval = oldProbe })

	blocker := filepath.Join(t.TempDir(), "blocker")
	if err := os.WriteFile(blocker, []byte("x"), 0644); err != nil {
		t.Fatal(err)
	}
	badDir := filepath.Join(blocker, "sub") // MkdirAll 必失败（父路径是文件）
	oldDir := LogDir()
	SetLogDir(badDir)
	t.Cleanup(func() { SetLogDir(oldDir) })

	for range 3 {
		taskLogAppend("t-fuse", "[start] 熔断期行")
	}
	if n := strings.Count(buf.String(), "进入熔断"); n != 1 {
		t.Fatalf("熔断 ERROR 行数=%d, want 1（逐行重试刷屏已熔断）:\n%s", n, buf.String())
	}
	if n := strings.Count(buf.String(), "open task log"); n != 0 {
		t.Fatalf("熔断期不得再有逐行 open WARNING, got %d", n)
	}

	// 恢复：解除占用，探测周期到点后下一行触发重探。
	if err := os.Remove(blocker); err != nil {
		t.Fatal(err)
	}
	time.Sleep(30 * time.Millisecond)
	taskLogAppend("t-fuse", "[done] 恢复行")
	if n := strings.Count(buf.String(), "恢复可写"); n != 1 {
		t.Fatalf("恢复 INFO 行数=%d, want 1:\n%s", n, buf.String())
	}
	body, err := os.ReadFile(TaskLogPath("t-fuse"))
	if err != nil {
		t.Fatalf("恢复后任务日志应落盘: %v", err)
	}
	if !strings.Contains(string(body), "恢复行") {
		t.Fatalf("恢复后写入行缺失: %q", body)
	}
}

// ErrRunCancelled 哨兵映射：manager 终态「已取消」经哨兵确定性落 cancelled
// （不靠 ctx.Err() 竞态窗）。
func TestEngine_TerminalStatusMapsRunCancelledSentinel(t *testing.T) {
	if got := terminalStatus(context.Background(), ErrRunCancelled); got != "cancelled" {
		t.Fatalf("terminalStatus(ErrRunCancelled)=%q, want cancelled", got)
	}
	if got := terminalStatus(context.Background(), errors.New("x")); got != "failed" {
		t.Fatalf("普通错误=%q, want failed", got)
	}
}
