package taskengine

import (
	"sync/atomic"
	"testing"
	"time"
)

func validRegisterDescriptor() Descriptor {
	return Descriptor{
		ID: "valid", Family: "test", Name: "valid", Category: "测试",
		Kind: KindPeriodic, RunsOn: RoleAny,
		IntervalFn: func() time.Duration { return time.Second },
		Run:        func(RunContext) error { return nil },
	}
}

func TestEngineRegister_rejectsInvalidKind(t *testing.T) {
	e := NewEngine(Options{})
	t.Cleanup(e.Stop) // 引擎须停止——否则 scheduleLoop goroutine 跨测试泄漏
	d := validRegisterDescriptor()
	d.Kind = Kind("bogus")
	if err := e.Register(d); err == nil {
		t.Fatal("未知 Kind 必须响亮拒绝")
	}
}

func TestEngineRegister_rejectsInvalidRunsOn(t *testing.T) {
	e := NewEngine(Options{})
	t.Cleanup(e.Stop) // 引擎须停止——否则 scheduleLoop goroutine 跨测试泄漏
	d := validRegisterDescriptor()
	d.RunsOn = Role("bogus")
	if err := e.Register(d); err == nil {
		t.Fatal("未知 RunsOn 必须响亮拒绝，不得按 any 放行")
	}
}

func TestEngineRegister_rejectsBootSyncNonOneshot(t *testing.T) {
	e := NewEngine(Options{})
	t.Cleanup(e.Stop) // 引擎须停止——否则 scheduleLoop goroutine 跨测试泄漏
	d := validRegisterDescriptor()
	d.BootSync = true
	if err := e.Register(d); err == nil {
		t.Fatal("BootSync 仅允许 Oneshot，其他 Kind 必须响亮拒绝")
	}
}

func TestEngineRegister_rejectsMissingKind(t *testing.T) {
	e := NewEngine(Options{})
	t.Cleanup(e.Stop) // 引擎须停止——否则 scheduleLoop goroutine 跨测试泄漏
	d := validRegisterDescriptor()
	d.Kind = ""
	if err := e.Register(d); err == nil {
		t.Fatal("Kind 缺失必须响亮拒绝，不得静默降级为 Oneshot")
	}
}

func TestEngineRegister_rejectsDuplicateID(t *testing.T) {
	// Given：同引擎内已有一个有效任务。
	e := NewEngine(Options{})
	t.Cleanup(e.Stop) // 引擎须停止——否则 scheduleLoop goroutine 跨测试泄漏
	d := validRegisterDescriptor()
	if err := e.Register(d); err != nil {
		t.Fatal(err)
	}
	// When/Then：同 ID 再注册必须失败，不得覆盖原描述符、历史与日志身份。
	if err := e.Register(d); err == nil {
		t.Fatal("重复 ID 必须响亮拒绝")
	}
}

func TestEngineRegister_rejectsMissingName(t *testing.T) {
	e := NewEngine(Options{})
	t.Cleanup(e.Stop) // 引擎须停止——否则 scheduleLoop goroutine 跨测试泄漏
	d := validRegisterDescriptor()
	d.Name = ""
	if err := e.Register(d); err == nil {
		t.Fatal("空 Name 必须响亮拒绝")
	}
}

func TestEngineRegister_rejectsNilRun(t *testing.T) {
	e := NewEngine(Options{})
	t.Cleanup(e.Stop) // 引擎须停止——否则 scheduleLoop goroutine 跨测试泄漏
	d := validRegisterDescriptor()
	d.Run = nil
	if err := e.Register(d); err == nil {
		t.Fatal("nil Run 必须响亮拒绝，不得注册后空指针")
	}
}

func TestEngine_nonPositivePeriodicIntervalDisablesLoopWithoutRun(t *testing.T) {
	for _, interval := range []time.Duration{0, -time.Second} {
		t.Run(interval.String(), func(t *testing.T) {
			// Given：动态 IntervalFn 返回非正周期（注册期不得调用该函数）。
			e := newTestEngine(t)
			var runs atomic.Int32
			d := validRegisterDescriptor()
			d.IntervalFn = func() time.Duration { return interval }
			d.Run = func(RunContext) error { runs.Add(1); return nil }
			if err := e.Register(d); err != nil {
				t.Fatalf("注册只校验 IntervalFn 存在，不应调用动态函数: %v", err)
			}
			e.StartLoop(d.ID)
			// When：tick 求值发现非法周期。
			e.tick()
			// Then：停止该任务调度且 Run 未执行，不得形成忙循环。
			for _, meta := range e.DescribeAll() {
				if meta.ID == d.ID && meta.LoopOn {
					t.Errorf("非正周期 %v 后 LoopOn=true，任务会持续忙调度", interval)
				}
			}
			if runs.Load() != 0 {
				t.Errorf("非正周期 %v 仍执行 Run %d 次", interval, runs.Load())
			}
		})
	}
}

// 注册期响亮拒绝静默忽略的 Descriptor 组合：RestartOnRoleFlip 仅常驻族
// 消费（Periodic/Scheduled/Oneshot 声明即无效）；CancelHook 在
// Cancelable=false 时永不可达（Cancel 先按 Cancelable 短路）。
func TestEngineRegister_rejectsRestartOnRoleFlipNonDaemon(t *testing.T) {
	e := NewEngine(Options{})
	t.Cleanup(e.Stop)
	d := validRegisterDescriptor()
	d.RestartOnRoleFlip = true
	if err := e.Register(d); err == nil {
		t.Fatal("RestartOnRoleFlip∧Kind!=Daemon 必须响亮拒绝（声明于非常驻族静默无效）")
	}
}

func TestEngineRegister_rejectsCancelHookWithoutCancelable(t *testing.T) {
	e := NewEngine(Options{})
	t.Cleanup(e.Stop)
	d := validRegisterDescriptor()
	d.CancelHook = func() bool { return true }
	if err := e.Register(d); err == nil {
		t.Fatal("CancelHook∧!Cancelable 必须响亮拒绝（CancelHook 永不可达）")
	}
	// 对照形状：Cancelable+CancelHook 合法。
	d2 := validRegisterDescriptor()
	d2.ID = "valid-hook"
	d2.Cancelable = true
	d2.CancelHook = func() bool { return true }
	if err := e.Register(d2); err != nil {
		t.Fatalf("Cancelable+CancelHook 合法组合不得误拒: %v", err)
	}
}

// 常驻族不支持取消：Cancel 只按 Cancelable 路由，被取消的 daemon 走「非异常
// 退出」（abnormal=false、pendingRestart=false），loop_on 保持 true 而
// running=false、监控判 idle——常驻采集/签发/同步永久停摆且无任何信号。
// 守卫与 Daemon∧EnabledFn 同范式：注册期响亮拒绝（启停用 StartLoop/StopLoop）。
func TestEngineRegister_rejectsCancelableDaemon(t *testing.T) {
	e := NewEngine(Options{})
	t.Cleanup(e.Stop)
	d := validRegisterDescriptor()
	d.Kind = KindDaemon
	d.IntervalFn = nil
	d.Cancelable = true
	if err := e.Register(d); err == nil {
		t.Fatal("KindDaemon∧Cancelable 必须响亮拒绝（取消即永久停止且无异常信号）")
	}
	// 对照形状：非常驻族 Cancelable 合法。
	d2 := validRegisterDescriptor()
	d2.ID = "valid-cancelable"
	d2.Cancelable = true
	if err := e.Register(d2); err != nil {
		t.Fatalf("非常驻族 Cancelable 合法组合不得误拒: %v", err)
	}
	// 对照形状：非常驻 Daemon（无 Cancelable）合法。
	d3 := validRegisterDescriptor()
	d3.ID = "valid-daemon"
	d3.Kind = KindDaemon
	d3.IntervalFn = nil
	if err := e.Register(d3); err != nil {
		t.Fatalf("常驻族未声明 Cancelable 不得误拒: %v", err)
	}
}
