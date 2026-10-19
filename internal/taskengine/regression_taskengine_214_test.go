package taskengine

// 「暂停派发 + 有界等待在途落定」原语。旧实现 CancelInFlightRuns 只发取消
// 信号即返回（runWG 仅 Stop 等待）——导入持锁全量替换期间，在途轮可继续写
// 库（last-writer-wins），且 tick 仍在 dispatch 新轮。

import (
	"context"
	"sync/atomic"
	"testing"
	"time"
)

// 标准排空序列：暂停派发 → 取消 → 有界等待返回 true，计数归零。
func TestEngine_WaitInFlightRunsDrainsAfterCancel(t *testing.T) {
	e := NewEngine(Options{TickInterval: time.Hour})
	t.Cleanup(e.Stop)
	if err := e.Register(Descriptor{ID: "t-drain", Family: "t", Name: "排空", Kind: KindPeriodic,
		RunsOn: RoleAny, IntervalFn: func() time.Duration { return time.Hour },
		Run: func(rc RunContext) error {
			<-rc.Ctx.Done()
			return rc.Ctx.Err()
		}}); err != nil {
		t.Fatal(err)
	}

	done := make(chan struct{})
	go func() {
		defer close(done)
		_, _ = e.runNow("t-drain", "manual", "")
	}()
	waitForEngine(t, "Run 登记在途", 2*time.Second, func() bool { return e.inFlight.Load() == 1 })

	e.PauseScheduling()
	if cancelled := e.CancelInFlightRuns(); cancelled != 1 {
		t.Fatalf("cancelled=%d, want 1", cancelled)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	if !e.WaitInFlightRuns(ctx) {
		t.Fatal("cancellable run must drain within the deadline")
	}
	if got := e.inFlight.Load(); got != 0 {
		t.Fatalf("inFlight=%d after drain, want 0", got)
	}
	<-done
}

// 不消费 rc.Ctx 的 Run 体：取消等价 no-op——等待必须按 deadline 返回 false
// （调用方据此 409/留痕），不得无界阻塞导入。
func TestEngine_WaitInFlightRunsTimesOutForCtxBlindRun(t *testing.T) {
	e := NewEngine(Options{TickInterval: time.Hour})
	t.Cleanup(e.Stop)
	release := make(chan struct{})
	if err := e.Register(Descriptor{ID: "t-blind", Family: "t", Name: "不消费取消", Kind: KindPeriodic,
		RunsOn: RoleAny, IntervalFn: func() time.Duration { return time.Hour },
		Run: func(RunContext) error {
			<-release // 故意忽略 rc.Ctx（cert 四 tick 等族的真实形态）
			return nil
		}}); err != nil {
		t.Fatal(err)
	}

	done := make(chan struct{})
	go func() {
		defer close(done)
		_, _ = e.runNow("t-blind", "manual", "")
	}()
	waitForEngine(t, "Run 登记在途", 2*time.Second, func() bool { return e.inFlight.Load() == 1 })

	e.PauseScheduling()
	e.CancelInFlightRuns()
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Millisecond)
	defer cancel()
	start := time.Now()
	if e.WaitInFlightRuns(ctx) {
		t.Fatal("ctx-blind run must not report drained before it exits")
	}
	if elapsed := time.Since(start); elapsed > time.Second {
		t.Fatalf("bounded wait took %s; want ctx deadline bound", elapsed)
	}
	close(release)
	<-done
	if got := e.inFlight.Load(); got != 0 {
		t.Fatalf("inFlight=%d after run exit, want 0", got)
	}
}

// 暂停期间 tick 不再派发新轮；恢复后继续（暂停=只减不增）。
func TestEngine_PauseSchedulingStopsDispatch(t *testing.T) {
	e := NewEngine(Options{TickInterval: 5 * time.Millisecond})
	t.Cleanup(e.Stop)
	var runs atomic.Int32
	if err := e.Register(Descriptor{ID: "t-tick", Family: "t", Name: "节拍", Kind: KindPeriodic,
		RunsOn: RoleAny, IntervalFn: func() time.Duration { return time.Millisecond },
		Run: func(RunContext) error {
			runs.Add(1)
			return nil
		}}); err != nil {
		t.Fatal(err)
	}
	e.StartLoop("t-tick")
	waitForEngine(t, "首轮派发", 2*time.Second, func() bool { return runs.Load() > 0 })

	e.PauseScheduling()
	// CI87-15：用引擎自己的排空 API 等待在途轮落定，替代 20ms 墙钟猜测。
	drainCtx, drainCancel := context.WithTimeout(context.Background(), 2*time.Second)
	if !e.WaitInFlightRuns(drainCtx) {
		drainCancel()
		t.Fatal("PauseScheduling 后在途轮未在 2s 内落定")
	}
	drainCancel()
	baseline := runs.Load()
	time.Sleep(50 * time.Millisecond)
	if got := runs.Load(); got != baseline {
		t.Fatalf("paused engine dispatched %d new runs", got-baseline)
	}

	e.ResumeScheduling()
	waitForEngine(t, "恢复后继续派发", 2*time.Second, func() bool { return runs.Load() > baseline })
}

func TestEngine_PauseSchedulingRejectsLateDispatchAndManualTriggers(t *testing.T) {
	e := NewEngine(Options{TickInterval: time.Hour})
	t.Cleanup(e.Stop)
	var runs atomic.Int32
	if err := e.Register(Descriptor{ID: "t-paused-gate", Family: "t", Name: "暂停门", Kind: KindOneshot,
		RunsOn: RoleAny, Run: func(RunContext) error {
			runs.Add(1)
			return nil
		}}); err != nil {
		t.Fatal(err)
	}

	e.PauseScheduling()
	calls := map[string]func() error{
		"Trigger": func() error { return e.Trigger("t-paused-gate", "manual", "tester") },
		"RunSync": func() error { _, err := e.RunSync("t-paused-gate", "manual", "tester"); return err },
		// 模拟 tick 已越过入口检查后，在 Pause 返回后才抵达实际派发点。
		"late automatic runNow": func() error { _, err := e.runNow("t-paused-gate", "auto", ""); return err },
	}
	for name, call := range calls {
		t.Run(name, func(t *testing.T) {
			if err := call(); err == nil {
				t.Error("paused engine must reject the execution")
			}
		})
	}
	if got := runs.Load(); got != 0 {
		t.Fatalf("paused engine executed %d runs, want 0", got)
	}

	e.ResumeScheduling()
	if err := e.Trigger("t-paused-gate", "manual", "tester"); err != nil {
		t.Fatalf("resumed engine must accept manual trigger: %v", err)
	}
	if got := runs.Load(); got != 1 {
		t.Fatalf("resumed engine runs=%d, want 1", got)
	}
}
