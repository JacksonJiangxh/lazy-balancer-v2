package taskengine

import (
	"strings"
	"testing"
	"time"
)

// 第 66 轮 U1-66-01/02/04 + L1-66-01 修复钉测试。
// 形状来源：生产调用形态=启动/翻转期三连 SetMasterRole→SetRole（每次转发），
// 既有测试每轮只翻一次与生产不符——本文件按真实形态钉。

// daemonRunning 直读 registration.running（IsRunning 含 loopEnabled&&
// roleAllows 的「将运行」投影——Stop 后调度开关仍在，须分真实运行位）。
func daemonRunning(e *Engine, id string) bool {
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

// waitDaemonNotRunning 轮询直到真实 running 位归 false。
func waitDaemonNotRunning(t *testing.T, e *Engine, id string, timeout time.Duration) bool {
	t.Helper()
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		if !daemonRunning(e, id) {
			return true
		}
		time.Sleep(5 * time.Millisecond)
	}
	return !daemonRunning(e, id)
}

// waitNotRunning 轮询直到 IsRunning(id)==false 或超时。
func waitNotRunning(t *testing.T, e *Engine, id string, timeout time.Duration) bool {
	t.Helper()
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		if !e.IsRunning(id) {
			return true
		}
		time.Sleep(5 * time.Millisecond)
	}
	return !e.IsRunning(id)
}

// Given RoleAny 常驻已运行 + 三连同角色 SetRole 重申（生产启动/翻转形态）。
// When 用户 StopLoop。
// Then daemon 停止且不复活（SetRole 重申不得栽 pendingRestart——U1-66-01①）。
func TestEngine_SetRoleReassertionDoesNotReviveStoppedDaemon(t *testing.T) {
	e := newTestEngine(t)
	started := make(chan struct{}, 4)
	e.Register(Descriptor{ID: "t-ra", Family: "t", Name: "常驻A", Kind: KindDaemon, RunsOn: RoleAny,
		Run: func(rc RunContext) error {
			started <- struct{}{}
			<-rc.Ctx.Done()
			return nil
		}})
	e.SetRole(true)
	e.StartLoop("t-ra")
	<-started
	// 生产形态：三连 SetRole 重申（启动期 threat/crs/ip2region 各一次）
	e.SetRole(true)
	e.SetRole(true)
	e.SetRole(true)
	e.StopLoop("t-ra")
	if !waitNotRunning(t, e, "t-ra", time.Second) {
		t.Fatal("StopLoop 后 daemon 应停止")
	}
	// 停止后 300ms 内不得复活（误栽 pendingRestart 的复活面）
	time.Sleep(300 * time.Millisecond)
	if e.IsRunning("t-ra") {
		t.Fatal("用户停止的 daemon 被 pendingRestart 复活——SetRole 重申不得栽重启意图")
	}
}

// Given master-only 常驻在主节点运行 + 启动/重申期 SetRole(true) 已栽标
// （生产形态：main 启动三连 SetMasterRole 全部走允许侧 tryStartDaemon）。
// When demote（三连 SetRole(false)——生产形态）。
// Then Run 取消退出后**不得按栽标在从节点复活**（U1-66-01③a）。
func TestEngine_DemoteTripleSetRoleDoesNotReviveOnSlave(t *testing.T) {
	e := newTestEngine(t)
	started := make(chan struct{}, 4)
	e.Register(Descriptor{ID: "t-mo", Family: "t", Name: "主常驻", Kind: KindDaemon, RunsOn: RoleMasterOnly,
		Run: func(rc RunContext) error {
			started <- struct{}{}
			<-rc.Ctx.Done()
			return nil
		}})
	e.SetRole(true)
	e.StartLoop("t-mo")
	<-started
	// 生产形态：运行中的允许侧重申（启动期三连的另两次）——bug 形态下栽标
	e.SetRole(true)
	e.SetRole(true)
	// demote 三连
	e.SetRole(false)
	e.SetRole(false)
	e.SetRole(false)
	if !waitNotRunning(t, e, "t-mo", time.Second) {
		t.Fatal("demote 后 master-only daemon 不得在从节点继续/复活运行")
	}
	time.Sleep(300 * time.Millisecond)
	if e.IsRunning("t-mo") {
		t.Fatal("demote 后 master-only daemon 在从节点复活——违反禁签发不变量")
	}
}

// Given 常驻运行中且已被 SetRole 重申（bug 形态下会栽标）。
// When Engine.Stop()（进程退出——U10 补充的第四触发面）。
// Then 不在 teardown 中拉起新代。
func TestEngine_StopPreventsRestart(t *testing.T) {
	e := newTestEngine(t)
	started := make(chan struct{}, 4)
	e.Register(Descriptor{ID: "t-sp", Family: "t", Name: "常驻S", Kind: KindDaemon, RunsOn: RoleAny,
		Run: func(rc RunContext) error {
			started <- struct{}{}
			<-rc.Ctx.Done()
			return nil
		}})
	e.SetRole(true)
	e.StartLoop("t-sp")
	<-started
	e.SetRole(true) // 生产启动期恒有的角色重申
	e.Stop()
	// Stop 后 cleanup 消费 pendingRestart 的路径必须被 stopped 门拦下
	if !waitDaemonNotRunning(t, e, "t-sp", 500*time.Millisecond) {
		t.Fatal("Engine.Stop 后不得复活 daemon（teardown 复活面）")
	}
}

// Given master-only Periodic（interval 1h）在从节点 StartLoop。
// When 若干 tick 后 promote（SetRole(true)）。
// Then 首轮在 promote 后立即执行（U1-66-02：置零分支不可达+tick 在角色门
// 前推进 lastCheck——两处叠加使首轮要等残余间隔）。
func TestEngine_PeriodicRunsPromptlyAfterPromote(t *testing.T) {
	e := newTestEngine(t)
	ran := make(chan struct{}, 4)
	e.Register(Descriptor{ID: "t-pd", Family: "t", Name: "周期P", Kind: KindPeriodic, RunsOn: RoleMasterOnly,
		IntervalFn: func() time.Duration { return time.Hour },
		Run: func(rc RunContext) error {
			select {
			case ran <- struct{}{}:
			default:
			}
			return nil
		}})
	e.SetRole(false)
	e.StartLoop("t-pd")
	time.Sleep(120 * time.Millisecond) // 从节点上若干 tick（bug：lastCheck 被推进）
	e.SetRole(true)                    // promote
	select {
	case <-ran:
	case <-time.After(500 * time.Millisecond):
		t.Fatal("promote 后 Periodic 首轮应在数百毫秒内执行，而非等残余 interval（最坏 6h/24h）")
	}
}

// Given StartLoop→StopLoop→StartLoop（restart 过渡）后立即 StopLoop
// （U1-66-04：restart 路径的 startDaemon 由退出 goroutine 异步调用——
// 占位与 cancel 登记之间的窗口内取消者读到 cancel==nil）。
// When 重复 20 次。
// Then 每次 daemon 最终停止（首停信号不得丢失）。
func TestEngine_StopLoopImmediatelyAfterStartEventuallyStops(t *testing.T) {
	e := newTestEngine(t)
	e.Register(Descriptor{ID: "t-w", Family: "t", Name: "常驻W", Kind: KindDaemon, RunsOn: RoleAny,
		Run: func(rc RunContext) error { <-rc.Ctx.Done(); return nil }})
	e.SetRole(true)
	for i := 0; i < 20; i++ {
		e.StartLoop("t-w")
		e.StopLoop("t-w")
		e.StartLoop("t-w") // restart 过渡（pendingRestart 消费路径）
		e.StopLoop("t-w")
		if !waitNotRunning(t, e, "t-w", 400*time.Millisecond) {
			t.Fatalf("第 %d 次 restart 过渡中 StopLoop：daemon 未停止（首停信号丢失——cancel 登记滞后窗口）", i+1)
		}
	}
}

// Given oneshot 任务体 panic（L1-66-01）。
// When Trigger。
// Then panic 被隔离为 failed 行（不得杀进程）。
func TestEngine_TaskRunPanicRecordsFailed(t *testing.T) {
	e := newTestEngine(t)
	e.Register(Descriptor{ID: "t-panic", Family: "t", Name: "恐慌任务", Kind: KindOneshot, ManualRun: true,
		Run: func(rc RunContext) error { panic("boom") }})
	_, err := e.RunSync("t-panic", "manual", "tester")
	if err == nil {
		t.Fatal("panic 应被隔离为任务失败（非 nil 错误）")
	}
	if !strings.Contains(err.Error(), "panic") {
		t.Fatalf("错误应标注 panic 来源，得到 %q", err.Error())
	}
	rec := e.LatestRun("t-panic")
	if rec == nil || rec.Status != "failed" {
		t.Fatalf("panic 应落 failed 行，得到 %+v", rec)
	}
}

// Given daemon 任务体启动即 panic（L1-66-01）。
// When StartLoop。
// Then 补记 failed 行且不自动重启（防紧循环）。
func TestEngine_DaemonRunPanicRecordsFailedNoRestart(t *testing.T) {
	e := newTestEngine(t)
	e.Register(Descriptor{ID: "t-dpanic", Family: "t", Name: "恐慌常驻", Kind: KindDaemon, RunsOn: RoleAny,
		Run: func(rc RunContext) error { panic("daemon boom") }})
	e.SetRole(true)
	e.StartLoop("t-dpanic")
	// 补 failed 行
	deadline := time.Now().Add(time.Second)
	sawFailed := false
	for time.Now().Before(deadline) {
		if rec := e.LatestRun("t-dpanic"); rec != nil && rec.Status == "failed" {
			sawFailed = true
			break
		}
		time.Sleep(5 * time.Millisecond)
	}
	if !sawFailed {
		t.Fatal("daemon panic 应补记 failed 行")
	}
	// 不自动重启：真实运行位归 false 后保持
	if !waitDaemonNotRunning(t, e, "t-dpanic", time.Second) {
		t.Fatal("daemon panic 后不得自动重启（防紧循环）")
	}
	time.Sleep(200 * time.Millisecond)
	if daemonRunning(e, "t-dpanic") {
		t.Fatal("daemon panic 后被自动重启——紧循环风险")
	}
}
