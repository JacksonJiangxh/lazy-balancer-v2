package taskengine

// lazy-task-engine M1 单测：注册/调度/单飞/取消/历史/崩溃恢复/角色门/动态间隔。
// 纯增量包——M1 无任何消费方，行为契约在此钉死。

import (
	"context"
	"errors"
	"sync/atomic"
	"testing"
	"time"

	"lazy-balancer-v2/internal/db"
)

func newTestEngine(t *testing.T) *Engine {
	t.Helper()
	// 与 services 测试同模式：临时目录初始化全套库（含 task_runs 表迁移）
	oldDB, oldMetricsDB, oldAuditDB := db.DB, db.MetricsDB, db.AuditDB
	if err := db.Initialize(t.TempDir()); err != nil {
		t.Fatalf("initialize test database: %v", err)
	}
	t.Cleanup(func() {
		_ = db.Close()
		db.DB, db.MetricsDB, db.AuditDB = oldDB, oldMetricsDB, oldAuditDB
	})
	e := NewEngine(Options{TickInterval: 10 * time.Millisecond})
	t.Cleanup(e.Stop)
	return e
}

// Given 单飞任务运行中。
// When 再次 Trigger。
// Then 返回 ErrAlreadyRunning（409 语义），不重入。
func TestEngine_SingletonTriggerRejectedWhileRunning(t *testing.T) {
	e := newTestEngine(t)
	release := make(chan struct{})
	started := make(chan struct{})
	e.Register(Descriptor{ID: "t-single", Family: "t", Name: "单飞", Singleton: true,
		Run: func(rc RunContext) error {
			close(started)
			<-release
			return nil
		}})
	go func() { _ = e.Trigger("t-single", "manual", "") }()
	<-started
	if err := e.Trigger("t-single", "manual", ""); err != ErrAlreadyRunning {
		t.Fatalf("want ErrAlreadyRunning, got %v", err)
	}
	close(release)
}

// Given 可取消任务运行中（阻塞在 ctx.Done）。
// When Cancel。
// Then Run 返回且历史终态=cancelled（非 failed）。
func TestEngine_CancelMarksCancelled(t *testing.T) {
	e := newTestEngine(t)
	inRun := make(chan struct{})
	done := make(chan error, 1)
	e.Register(Descriptor{ID: "t-cancel", Family: "t", Name: "可取消", Singleton: true, Cancelable: true,
		Run: func(rc RunContext) error {
			close(inRun)
			<-rc.Ctx.Done()
			return context.Canceled
		}})
	go func() { done <- e.runNow("t-cancel", "manual", "") }()
	<-inRun
	if !e.Cancel("t-cancel") {
		t.Fatal("Cancel 应生效")
	}
	if err := <-done; err != nil && err != context.Canceled {
		t.Fatalf("run err=%v", err)
	}
	// 等终态落库
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		runs := e.History("t-cancel", 1)
		if len(runs) == 1 && runs[0].Status == "cancelled" {
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatalf("历史终态应为 cancelled, got %+v", e.History("t-cancel", 1))
}

// Given task_runs 残留 status=running 行（崩溃现场）。
// When 引擎 RecoverOrphans。
// Then 该行改标 interrupted。
func TestEngine_RecoverOrphansMarksInterrupted(t *testing.T) {
	e := newTestEngine(t)
	res, err := db.DB.Exec(`INSERT INTO task_runs (task_id, family, trigger, status) VALUES ('t-orph', 't', 'auto', 'running')`)
	if err != nil {
		t.Fatal(err)
	}
	id, _ := res.LastInsertId()
	if n := e.RecoverOrphans(); n != 1 {
		t.Fatalf("应回收 1 行, got %d", n)
	}
	var status string
	if err := db.DB.QueryRow(`SELECT status FROM task_runs WHERE id=?`, id).Scan(&status); err != nil || status != "interrupted" {
		t.Fatalf("status=%q err=%v, want interrupted", status, err)
	}
}

// Given slave-only 任务 + 当前为主节点。
// When 调度 tick 到期。
// Then 不执行（角色门拦截），快照状态 idle。
func TestEngine_RoleGateSlaveOnlyOnMasterSkips(t *testing.T) {
	e := newTestEngine(t)
	ran := false
	e.Register(Descriptor{ID: "t-role", Family: "t", Name: "从节点任务", RunsOn: RoleSlaveOnly,
		IntervalFn: func() time.Duration { return 20 * time.Millisecond },
		Run:        func(rc RunContext) error { ran = true; return nil }})
	e.StartLoop("t-role")
	e.SetRole(true) // 主节点
	time.Sleep(150 * time.Millisecond)
	if ran {
		t.Fatal("主节点不应执行 slave-only 任务")
	}
}

// Given 动态间隔任务(interval=500ms)。
// When IntervalFn 中途返回 20ms（tick 每轮重读间隔——变更自然生效）。
// Then 后续按新间隔执行（300ms 内 ≥2 次）。
func TestEngine_DynamicIntervalReread(t *testing.T) {
	e := newTestEngine(t)
	mu := make(chan struct{}, 32)
	var fast atomic.Bool
	e.Register(Descriptor{ID: "t-dyn", Family: "t", Name: "动态", Kind: KindContinuous, RunsOn: RoleAny,
		IntervalFn: func() time.Duration {
			if fast.Load() {
				return 20 * time.Millisecond
			}
			return 500 * time.Millisecond
		},
		Run: func(rc RunContext) error { mu <- struct{}{}; return nil }})
	e.StartLoop("t-dyn")
	e.SetRole(true)
	time.Sleep(80 * time.Millisecond) // 慢间隔期(最多1次)
	fast.Store(true)
	deadline := time.Now().Add(300 * time.Millisecond)
	count := 0
	for time.Now().Before(deadline) {
		select {
		case <-mu:
			count++
		case <-time.After(20 * time.Millisecond):
		}
	}
	if count < 2 {
		t.Fatalf("重排后应至少执行 2 次, got %d", count)
	}
}

// Given 常驻任务(loop)运行中。
// When StopLoop 后 StartLoop。
// Then 循环停/启真实生效（IsRunning 翻转）。
func TestEngine_LoopStopStart(t *testing.T) {
	e := newTestEngine(t)
	e.Register(Descriptor{ID: "t-loop", Family: "t", Name: "常驻", Kind: KindContinuous, RunsOn: RoleAny,
		IntervalFn: func() time.Duration { return 20 * time.Millisecond },
		Run:        func(rc RunContext) error { return nil }})
	e.SetRole(true)
	e.StartLoop("t-loop")
	if !e.IsRunning("t-loop") {
		t.Fatal("启动后应 running")
	}
	e.StopLoop("t-loop")
	if e.IsRunning("t-loop") {
		t.Fatal("停止后应非 running")
	}
}

// Given 成功执行一次。
// Then 历史行含 trigger/status/duration 与 task_id。
func TestEngine_HistoryRecordShape(t *testing.T) {
	e := newTestEngine(t)
	e.Register(Descriptor{ID: "t-hist", Family: "t", Name: "历史", Singleton: true,
		Run: func(rc RunContext) error {
			return nil
		}})
	if err := e.Trigger("t-hist", "manual", ""); err != nil {
		t.Fatal(err)
	}
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		runs := e.History("t-hist", 1)
		if len(runs) == 1 && runs[0].Status == "success" {
			r := runs[0]
			if r.TaskID != "t-hist" || r.Family != "t" || r.Trigger != "manual" {
				t.Fatalf("历史字段不全: %+v", r)
			}
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatalf("应有一条 success 历史: %+v", e.History("t-hist", 1))
}

// Given SilentProbes/RecordFailuresOnly 任务各执行一次成功。
// Then R63 新语义：RecordFailuresOnly 首轮 boot 恰 1 行（启动计数）；
// SilentProbes 恒零行（探测轮非工作轮）；后续成功轮不再增行。
func TestEngine_RecordPoliciesSilentOnSuccess(t *testing.T) {
	e := newTestEngine(t)
	e.Register(Descriptor{ID: "t-silent", Family: "t", Singleton: true, SilentProbes: true,
		Run: func(rc RunContext) error { return nil }})
	e.Register(Descriptor{ID: "t-failonly", Family: "t", Singleton: true, RecordFailuresOnly: true,
		Run: func(rc RunContext) error { return nil }})
	// auto 触发(探测/工作轮语义)：探测轮零行；RecordFailuresOnly boot 计 1 行
	if err := e.runNow("t-silent", "auto", ""); err != nil {
		t.Fatal(err)
	}
	if err := e.runNow("t-failonly", "auto", ""); err != nil {
		t.Fatal(err)
	}
	time.Sleep(200 * time.Millisecond)
	// SilentProbes（探测轮）恒不落库（含 boot——探测不是常驻工作轮）
	if got := len(e.History("t-silent", 10)); got != 0 {
		t.Fatalf("SilentProbes 探测轮不应落库, got %d 行", got)
	}
	// RecordFailuresOnly 首轮 boot 恰 1 行 success（启动计数）
	runs := e.History("t-failonly", 10)
	if len(runs) != 1 || runs[0].Status != "success" {
		t.Fatalf("首轮 boot 应恰 1 行 success, got %+v", runs)
	}
	// 第二轮 auto 成功——不再增行（boot 已计）
	if err := e.runNow("t-failonly", "auto", ""); err != nil {
		t.Fatal(err)
	}
	time.Sleep(100 * time.Millisecond)
	if got := len(e.History("t-failonly", 10)); got != 1 {
		t.Fatalf("后续成功轮不应增行（boot 已计）, got %d", got)
	}
	// manual 触发恒落库（用户显式动作）
	if err := e.runNow("t-silent", "manual", ""); err != nil {
		t.Fatal(err)
	}
	deadlineM := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadlineM) {
		if runs := e.History("t-silent", 5); len(runs) >= 1 {
			break
		}
		time.Sleep(20 * time.Millisecond)
	}
	if got := len(e.History("t-silent", 10)); got != 1 {
		t.Fatalf("manual 应落 1 行, got %d", got)
	}
	// 失败轮补一行（R63 新语义：boot 后运行期失败也记一行——区别于旧 RecordFailuresOnly 仅首败）
	e.Register(Descriptor{ID: "t-failonly", Family: "t", Singleton: true, RecordFailuresOnly: true,
		Run: func(rc RunContext) error { return errors.New("boom") }})
	if err := e.Trigger("t-failonly", "manual", ""); err == nil {
		t.Fatal("应返回错误")
	}
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		runs := e.History("t-failonly", 5)
		if len(runs) == 2 && runs[0].Status == "failed" {
			return
		}
		time.Sleep(20 * time.Millisecond)
	}
	t.Fatalf("失败轮应补 1 行 failed: %+v", e.History("t-failonly", 5))
}

func withTestLocation(t *testing.T, loc *time.Location) {
	t.Helper()
	old := engineLocPtr()
	SetLocation(loc)
	t.Cleanup(func() { SetLocation(old) })
}

func parseRunTime(s string) time.Time {
	tt, _ := time.ParseInLocation("2006-01-02 15:04:05", s, time.UTC)
	return tt
}

func TestEngine_DescribeAllReleasesLockBeforeFnCalls(t *testing.T) {
	e := newTestEngine(t)
	entered := make(chan struct{})
	release := make(chan struct{})
	e.Register(Descriptor{ID: "t-block", Family: "t", Name: "阻塞元数据",
		StatusFn: func() string {
			select {
			case <-entered:
			default:
				close(entered)
			}
			<-release
			return ""
		}})
	go e.DescribeAll()
	select {
	case <-entered:
	case <-time.After(2 * time.Second):
		t.Fatal("StatusFn 未被调用")
	}
	stopped := make(chan struct{})
	go func() {
		e.Stop()
		close(stopped)
	}()
	select {
	case <-stopped:
		close(release)
	case <-time.After(2 * time.Second):
		close(release) // 先放行避免 cleanup 挂死
		t.Fatal("DescribeAll 持锁期间 Stop 被阻塞（元数据 Fn 调用未移出锁外）")
	}
}

// Given 任务体捕获 RunContext.Operator。
// When Trigger(id, "manual", "alice")。
// Then 任务体收到 operator=alice（U1-P3-1：手动操作者身份通道）。
func TestEngine_TriggerCarriesOperator(t *testing.T) {
	e := newTestEngine(t)
	got := make(chan string, 1)
	e.Register(Descriptor{ID: "t-op", Family: "t", Name: "操作者", Singleton: true,
		Run: func(rc RunContext) error {
			got <- rc.Operator
			return nil
		}})
	if err := e.Trigger("t-op", "manual", "alice"); err != nil {
		t.Fatal(err)
	}
	select {
	case op := <-got:
		if op != "alice" {
			t.Fatalf("want operator=alice, got %q", op)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("任务未执行")
	}
}

// Given 注册了 Singleton 声明的任务。
// When DescribeAll。
// Then 元数据暴露 SingleFlight=true（U1-P3-7：生产描述符补单飞的可观察面）。
func TestEngine_DescribeAllExposesSingleFlight(t *testing.T) {
	e := newTestEngine(t)
	e.Register(Descriptor{ID: "t-sf", Family: "t", Name: "单飞元数据", Singleton: true})
	for _, m := range e.DescribeAll() {
		if m.ID == "t-sf" {
			if !m.SingleFlight {
				t.Fatal("Singleton 声明应在 DescribeAll 元数据中暴露为 SingleFlight")
			}
			return
		}
	}
	t.Fatal("未找到 t-sf")
}

// Given RecordFailuresOnly 任务运行 100ms 后失败（触发 auto，成功轮静默）。
// When 失败补插历史行。
// Then 行 started_at 反映真实开始时刻而非补插时刻（U2-P5-08c：
// started_at+duration 不越过 finished_at）。
func TestEngine_RecordFailuresOnlyBackfillStartsAtRealStart(t *testing.T) {
	e := newTestEngine(t)
	e.Register(Descriptor{ID: "t-backfill", Family: "t", Singleton: true, RecordFailuresOnly: true,
		Run: func(rc RunContext) error {
			time.Sleep(120 * time.Millisecond)
			return errors.New("boom")
		}})
	if err := e.runNow("t-backfill", "auto", ""); err == nil {
		t.Fatal("应返回错误")
	}
	runs := e.History("t-backfill", 1)
	if len(runs) != 1 {
		t.Fatalf("应补插 1 行 failed, got %+v", runs)
	}
	r := runs[0]
	if r.DurationMs < 100 {
		t.Fatalf("duration 应≥100ms, got %d", r.DurationMs)
	}
	if end := parseRunTime(r.StartedAt).Add(time.Duration(r.DurationMs) * time.Millisecond); end.After(parseRunTime(r.FinishedAt).Add(2 * time.Second)) {
		t.Fatalf("started_at 为补插时刻而非真实开始: started=%s duration=%dms finished=%s",
			r.StartedAt, r.DurationMs, r.FinishedAt)
	}
}
