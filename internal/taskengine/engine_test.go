package taskengine

// lazy-task-engine M1 单测：注册/调度/单飞/取消/历史/崩溃恢复/角色门/动态间隔。
// 纯增量包——M1 无任何消费方，行为契约在此钉死。

import (
	"context"
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
	go func() { _ = e.Trigger("t-single", "manual") }()
	<-started
	if err := e.Trigger("t-single", "manual"); err != ErrAlreadyRunning {
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
	go func() { done <- e.runNow("t-cancel", "manual") }()
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

// Given 动态间隔任务(interval=50ms)。
// When Reschedule 后 IntervalFn 返回 20ms。
// Then 后续按新间隔执行（200ms 内 ≥2 次）。
func TestEngine_DynamicIntervalReschedule(t *testing.T) {
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
	e.Reschedule("t-dyn")
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
			rc.Progress("downloading", "阶段消息")
			return nil
		}})
	if err := e.Trigger("t-hist", "manual"); err != nil {
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
