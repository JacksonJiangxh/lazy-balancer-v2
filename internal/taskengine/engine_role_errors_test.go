package taskengine

import (
	"context"
	"errors"
	"fmt"
	"sync/atomic"
	"testing"
	"time"
)

func TestErrNotMaster_errorsIsTruthTable(t *testing.T) {
	for _, tc := range []struct {
		name string
		err  error
		want bool
	}{
		{name: "nil", err: nil, want: false},
		{name: "direct sentinel", err: ErrNotMaster, want: true},
		{name: "wrapped sentinel", err: fmt.Errorf("reserve role: %w", ErrNotMaster), want: true},
		{name: "same text is not sentinel", err: errors.New(ErrNotMaster.Error()), want: false},
		{name: "other sentinel", err: ErrAlreadyRunning, want: false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := errors.Is(tc.err, ErrNotMaster); got != tc.want {
				t.Fatalf("errors.Is(%v, ErrNotMaster)=%v, want %v", tc.err, got, tc.want)
			}
		})
	}
}

func TestEngine_masterOnlyEntriesReturnNotMasterSentinel(t *testing.T) {
	for _, tc := range []struct {
		name   string
		invoke func(*Engine) error
	}{
		{name: "Trigger", invoke: func(e *Engine) error {
			return e.Trigger("t-master-sentinel", "manual", "tester")
		}},
		{name: "RunSync", invoke: func(e *Engine) error {
			_, err := e.RunSync("t-master-sentinel", "manual", "tester")
			return err
		}},
		{name: "RunAsync reserveRun", invoke: func(e *Engine) error {
			return e.RunAsync("t-master-sentinel", "manual", "tester")
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			e := newTestEngine(t)
			var runs atomic.Int32
			if err := e.Register(Descriptor{
				ID: "t-master-sentinel", Family: "t", Name: "主节点哨兵", Kind: KindOneshot, RunsOn: RoleMasterOnly,
				Run: func(RunContext) error { runs.Add(1); return nil },
			}); err != nil {
				t.Fatalf("register: %v", err)
			}
			e.SetRole(false)

			err := tc.invoke(e)
			if err == nil {
				t.Fatal("master-only entry succeeded on slave")
			}
			if !errors.Is(err, ErrNotMaster) {
				t.Fatalf("err=%v, want ErrNotMaster", err)
			}
			if !errors.Is(fmt.Errorf("http mapping context: %w", err), ErrNotMaster) {
				t.Fatalf("wrapped err=%v must retain ErrNotMaster identity", err)
			}
			if got := runs.Load(); got != 0 {
				t.Fatalf("rejected task ran %d times, want 0", got)
			}
		})
	}
}

// 安全专项复核：Oneshot 与 Scheduled/Periodic 使用同一角色不变量；
// master-only 在途执行不得因 Kind 未列入 SetRole 目标集而在 demote 后写库。
func TestEngine_DemoteCancelsInFlightMasterOnlyOneshot(t *testing.T) {
	e := newTestEngine(t)
	started := make(chan struct{})
	if err := e.Register(Descriptor{
		ID: "t-oneshot-demote", Family: "t", Name: "主节点单次任务", Kind: KindOneshot, RunsOn: RoleMasterOnly,
		Run: func(rc RunContext) error {
			close(started)
			<-rc.Ctx.Done()
			return rc.Ctx.Err()
		},
	}); err != nil {
		t.Fatal(err)
	}
	done := make(chan error, 1)
	go func() { done <- e.Trigger("t-oneshot-demote", "manual", "tester") }()
	select {
	case <-started:
	case <-time.After(2 * time.Second):
		t.Fatal("Oneshot 未进入 Run")
	}

	e.SetRole(false)

	select {
	case err := <-done:
		if !errors.Is(err, context.Canceled) {
			t.Fatalf("demote 后 Run err=%v, want context.Canceled", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("master-only Oneshot 在 demote 后未被取消")
	}
	if latest := e.LatestRun("t-oneshot-demote"); latest == nil || latest.Status != "cancelled" {
		t.Fatalf("Oneshot demote 终态=%+v, want cancelled", latest)
	}
}

// 基线回归（豁免 RED）：BootSync 强制 RoleAny，角色翻转不得取消其在途启动执行。
func TestEngine_DemoteDoesNotCancelRoleAnyBootSync(t *testing.T) {
	e := newTestEngine(t)
	ctxSeen := make(chan context.Context, 1)
	release := make(chan struct{})
	if err := e.Register(Descriptor{
		ID: "t-boot-role-any", Family: "t", Name: "启动单次任务", Kind: KindOneshot, RunsOn: RoleAny, BootSync: true,
		Run: func(rc RunContext) error {
			ctxSeen <- rc.Ctx
			<-release
			return nil
		},
	}); err != nil {
		t.Fatal(err)
	}
	done := make(chan struct{})
	go func() {
		e.RunBootSyncTasks()
		close(done)
	}()
	var runCtx context.Context
	select {
	case runCtx = <-ctxSeen:
	case <-time.After(2 * time.Second):
		close(release)
		t.Fatal("BootSync 未进入 Run")
	}
	e.SetRole(false)
	cancelled := false
	select {
	case <-runCtx.Done():
		cancelled = true
	case <-time.After(100 * time.Millisecond):
	}
	close(release)
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("BootSync 未退出")
	}
	if cancelled {
		t.Fatal("RoleAny BootSync 在 demote 时被错误取消")
	}
	if latest := e.LatestRun("t-boot-role-any"); latest == nil || latest.Status != "success" {
		t.Fatalf("RoleAny BootSync 终态=%+v, want success", latest)
	}
}
