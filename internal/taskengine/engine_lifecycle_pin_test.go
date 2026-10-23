package taskengine

// 任务引擎生命周期与元数据的边界钉测：
//   - StartLoop 幂等（已开启状态不得重置节拍）；
//   - Cancel 的在途轮代际身份（hook 窗口内换轮不得作用于新一轮）；
//   - Register 的 Kind×Fn 白名单；
//   - Lookup/DescribeAll 元数据单源等价；
//   - Scheduled 跳过轮的退避兜底。

import (
	"errors"
	"reflect"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"lazy-balancer-v2/internal/db"
)

// Given Periodic 任务间隔 1h 且已跑完首轮。
// When 已开启状态下重复调用 StartLoop。
// Then 不产生额外执行（节拍只在关→开过渡复位；显式补跑归 RearmLoop）。
func TestEngine_StartLoopIdempotentOnEnabledPeriodic(t *testing.T) {
	e := newTestEngine(t)
	var runs atomic.Int32
	if err := e.Register(Descriptor{ID: "t-idempotent", Family: "t", Name: "幂等启动", Kind: KindPeriodic,
		IntervalFn: func() time.Duration { return time.Hour },
		Run:        func(RunContext) error { runs.Add(1); return nil }}); err != nil {
		t.Fatal(err)
	}
	e.SetRole(true)
	e.StartLoop("t-idempotent")
	waitForEngine(t, "首轮执行", 2*time.Second, func() bool { return runs.Load() == 1 })

	e.StartLoop("t-idempotent")
	time.Sleep(150 * time.Millisecond)
	if got := runs.Load(); got != 1 {
		t.Fatalf("已开启状态重复 StartLoop 后执行 %d 轮, want 1（幂等入口不得置零节拍）", got)
	}
}

// Given Scheduled 任务槽恒过期，首轮在 CancelHook 窗口内自然结束（skipped），
// 期间 tick 派发了同 trigger 的新一轮（阻塞中）。
// When hook 返回、Cancel 落定。
// Then 新一轮不被取消、本槽不被消费（水位为空），且退避到期后能重投第 3 次。
func TestEngine_CancelKeepsSlotForRunStartedDuringHook(t *testing.T) {
	e := newTestEngine(t)
	pastSlot := time.Now().Add(-time.Minute)
	const id = "t-cancel-generation"
	var runs atomic.Int32
	round1Release := make(chan struct{})
	round2Release := make(chan struct{})
	hookEntered := make(chan struct{})
	hookRelease := make(chan struct{})
	var round1Once, round2Once, hookOnce sync.Once
	releaseRound1 := func() { round1Once.Do(func() { close(round1Release) }) }
	releaseRound2 := func() { round2Once.Do(func() { close(round2Release) }) }
	releaseHook := func() { hookOnce.Do(func() { close(hookRelease) }) }
	// 断言失败路径也必须释放全部阻塞点（否则引擎 Stop 的 drain 会挂满超时）。
	t.Cleanup(func() { releaseRound1(); releaseRound2(); releaseHook() })
	var round2Cancelled atomic.Bool

	if err := e.Register(Descriptor{
		ID: id, Family: "t", Name: "取消代际", Kind: KindScheduled,
		NextSlotFn: func() time.Time { return pastSlot },
		Cancelable: true,
		CancelHook: func() bool {
			close(hookEntered)
			<-hookRelease
			return true
		},
		Run: func(rc RunContext) error {
			switch runs.Add(1) {
			case 1:
				// 首轮在 hook 窗口内结束为 cancelled（取消已作用于本轮）；
				// 取消轮不消费槽，故 tick 立即派发同 trigger 的新一轮。
				<-round1Release
				return ErrRunCancelled
			case 2:
				// hook 窗口内被派发的新一轮：必须存活到 Cancel 落定之后。
				<-round2Release
				if rc.Ctx.Err() != nil {
					round2Cancelled.Store(true)
				}
				return errors.New("boom")
			default:
				return nil
			}
		},
	}); err != nil {
		t.Fatal(err)
	}
	e.SetRole(true)
	e.StartLoop(id)
	waitForEngine(t, "首轮启动", 2*time.Second, func() bool { return runs.Load() == 1 })

	cancelDone := make(chan bool, 1)
	go func() { cancelDone <- e.Cancel(id) }()
	select {
	case <-hookEntered:
	case <-time.After(2 * time.Second):
		t.Fatal("CancelHook 未被调用")
	}
	releaseRound1() // 被取消轮在 hook 窗口内结束（cancelled，不消费槽）
	waitForEngine(t, "hook 窗口内派发新一轮", 3*time.Second, func() bool { return runs.Load() == 2 })
	releaseHook()
	if ok := <-cancelDone; !ok {
		t.Fatal("Cancel 应返回 true（hook 已接受）")
	}

	e.mu.RLock()
	r := e.regs[id]
	e.mu.RUnlock()
	r.mu.Lock()
	doneSlot, stillRunning := r.schedDoneSlot, r.running
	r.mu.Unlock()
	if !doneSlot.IsZero() {
		t.Fatalf("schedDoneSlot=%v, want 零值（旧轮不得消费新一轮所属的槽）", doneSlot)
	}
	if !stillRunning {
		t.Fatal("新一轮被旧取消动作终止（代际复核缺失）")
	}
	if round2Cancelled.Load() {
		t.Fatal("新一轮的 ctx 被旧取消动作取消（代际复核缺失）")
	}

	releaseRound2()
	waitForEngine(t, "退避到期重投第 3 轮", 3*time.Second, func() bool { return runs.Load() >= 3 })
}

// Given Kind 与调度/业务门 Fn 错配的七种形态。
// When Register。
// Then 注册期响亮拒绝且不入表（错配声明在生产是静默忽略的装配错误）。
func TestRegister_rejectsKindFnMismatch(t *testing.T) {
	interval := func() time.Duration { return time.Minute }
	slot := func() time.Time { return time.Time{} }
	enabled := func() bool { return true }
	cases := []struct {
		name string
		want string
		desc Descriptor
	}{
		{"Scheduled+IntervalFn", "IntervalFn", Descriptor{Kind: KindScheduled, NextSlotFn: slot, IntervalFn: interval}},
		{"Periodic+NextSlotFn", "NextSlotFn", Descriptor{Kind: KindPeriodic, IntervalFn: interval, NextSlotFn: slot}},
		{"Daemon+IntervalFn", "IntervalFn", Descriptor{Kind: KindDaemon, IntervalFn: interval}},
		{"Daemon+NextSlotFn", "NextSlotFn", Descriptor{Kind: KindDaemon, NextSlotFn: slot}},
		{"Oneshot+IntervalFn", "IntervalFn", Descriptor{Kind: KindOneshot, IntervalFn: interval}},
		{"Oneshot+NextSlotFn", "NextSlotFn", Descriptor{Kind: KindOneshot, NextSlotFn: slot}},
		{"Oneshot+EnabledFn", "EnabledFn", Descriptor{Kind: KindOneshot, EnabledFn: enabled}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			e := NewEngine(Options{})
			t.Cleanup(e.Stop)
			d := tc.desc
			d.ID, d.Family, d.Name = "mismatch", "t", "错配"
			d.Run = func(RunContext) error { return nil }
			err := e.Register(d)
			if err == nil {
				t.Fatalf("%s 必须被注册期拒绝（错配 Fn 在调度面静默忽略）", tc.name)
			}
			if !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("err=%v, want 提到 %s", err, tc.want)
			}
			if _, ok := e.Lookup(d.ID); ok {
				t.Fatal("被拒绝的注册不得进入注册表")
			}
		})
	}
}

// 回归：合法组合（Scheduled 带 EnabledFn/StatusFn、Periodic 带 EnabledFn/StatusFn、
// Daemon 仅 StatusFn）不被误伤。
func TestRegister_acceptsScheduleGatesAndStatusMirror(t *testing.T) {
	e := NewEngine(Options{})
	t.Cleanup(e.Stop)
	if err := e.Register(Descriptor{ID: "ok-s", Family: "t", Name: "s", Kind: KindScheduled,
		NextSlotFn: func() time.Time { return time.Time{} },
		EnabledFn:  func() bool { return true },
		StatusFn:   func() string { return "idle" },
		Run:        func(RunContext) error { return nil }}); err != nil {
		t.Fatalf("Scheduled 带 EnabledFn/StatusFn 必须合法: %v", err)
	}
	if err := e.Register(Descriptor{ID: "ok-p", Family: "t", Name: "p", Kind: KindPeriodic,
		IntervalFn: func() time.Duration { return time.Minute },
		EnabledFn:  func() bool { return true },
		StatusFn:   func() string { return "idle" },
		Run:        func(RunContext) error { return nil }}); err != nil {
		t.Fatalf("Periodic 带 EnabledFn/StatusFn 必须合法: %v", err)
	}
	if err := e.Register(Descriptor{ID: "ok-d", Family: "t", Name: "d", Kind: KindDaemon,
		StatusFn: func() string { return "" },
		Run:      func(RunContext) error { return nil }}); err != nil {
		t.Fatalf("Daemon 带 StatusFn 必须合法: %v", err)
	}
}

// Given 四种 Kind 各一任务（含调度闭包与状态镜像），一台常驻运行中。
// When 分别取 Lookup 与 DescribeAll 的同 ID 元数据。
// Then 两者逐字段等价（元数据构建单源，不得双份漂移）。
func TestEngine_LookupMatchesDescribeAll(t *testing.T) {
	e := newTestEngine(t)
	release := make(chan struct{})
	t.Cleanup(func() { close(release) })
	descs := []Descriptor{
		{ID: "meta-s", Family: "t", Name: "s", Kind: KindScheduled,
			NextSlotFn: func() time.Time { return time.Now().Add(time.Hour) },
			EnabledFn:  func() bool { return true },
			StatusFn:   func() string { return "running" },
			Run:        func(RunContext) error { return nil }},
		{ID: "meta-p", Family: "t", Name: "p", Kind: KindPeriodic,
			IntervalFn: func() time.Duration { return time.Minute },
			EnabledFn:  func() bool { return true },
			StatusFn:   func() string { return "idle" },
			Run:        func(RunContext) error { return nil }},
		{ID: "meta-d", Family: "t", Name: "d", Kind: KindDaemon,
			StatusFn: func() string { return "running" },
			Run:      func(RunContext) error { <-release; return nil }},
		{ID: "meta-o", Family: "t", Name: "o", Kind: KindOneshot,
			Run: func(RunContext) error { return nil }},
	}
	for _, d := range descs {
		if err := e.Register(d); err != nil {
			t.Fatalf("register %s: %v", d.ID, err)
		}
	}
	e.SetRole(true)
	e.StartLoop("meta-s")
	e.StartLoop("meta-p")
	e.StartLoop("meta-d")
	waitForEngine(t, "常驻运行", 2*time.Second, func() bool {
		meta, ok := e.Lookup("meta-d")
		return ok && meta.Running
	})

	byID := map[string]TaskMeta{}
	for _, meta := range e.DescribeAll() {
		byID[meta.ID] = meta
	}
	for _, d := range descs {
		looked, ok := e.Lookup(d.ID)
		if !ok {
			t.Fatalf("%s Lookup 未命中", d.ID)
		}
		listed, ok := byID[d.ID]
		if !ok {
			t.Fatalf("%s DescribeAll 未命中", d.ID)
		}
		if !reflect.DeepEqual(looked, listed) {
			t.Fatalf("%s 元数据双源漂移：Lookup=%+v DescribeAll=%+v", d.ID, looked, listed)
		}
	}
}

// Given Scheduled 任务槽恒过期且 Run 每次返回 ErrTaskSkipped。
// When tick 循环运转。
// Then 跳过轮同享有界退避（350ms 窗口内至多 2 次执行），退避到期后恢复重投，
// 且 task_runs 记录 skipped 终态。
func TestEngine_ScheduledSkippedSlotGetsBoundedBackoff(t *testing.T) {
	e := newTestEngine(t)
	pastSlot := time.Now().Add(-time.Minute)
	var runs atomic.Int32
	if err := e.Register(Descriptor{ID: "t-skip-slot", Family: "t", Name: "跳过退避", Kind: KindScheduled,
		NextSlotFn: func() time.Time { return pastSlot },
		Run:        func(RunContext) error { runs.Add(1); return ErrTaskSkipped }}); err != nil {
		t.Fatal(err)
	}
	e.SetRole(true)
	e.StartLoop("t-skip-slot")

	time.Sleep(350 * time.Millisecond)
	if got := runs.Load(); got == 0 || got > 2 {
		t.Fatalf("350ms 窗口内执行 %d 次, want 1-2（跳过轮须共用退避，不得 tick 频率重投）", got)
	}
	if got := countSkippedRuns(t, "t-skip-slot"); got == 0 {
		t.Fatal("跳过轮必须落 task_runs.status=skipped")
	}
	waitForEngine(t, "退避衰减后重投", 2*time.Second, func() bool { return runs.Load() >= 2 })
}

func countSkippedRuns(t *testing.T, id string) int {
	t.Helper()
	var n int
	if err := db.DB.QueryRow(`SELECT COUNT(*) FROM task_runs WHERE task_id=? AND status='skipped'`, id).Scan(&n); err != nil {
		t.Fatalf("count skipped runs: %v", err)
	}
	return n
}

// Given 注册一个触发类（Oneshot）任务。
// When StartLoop 与 RearmLoop（含 hasWork 绕过形态）。
// Then LoopOn 保持 false——触发类无调度语义（标准 §4：显示禁用开关）。引擎侧
// 必须在 handler 门之外自持纵深守卫：任何调用路径都不得产出「调度开」假信号，
// 也不得触发 ResetScheduleProgress/lastCheck 等无效副作用。
func TestEngine_LoopEntriesRejectOneshot(t *testing.T) {
	e := newTestEngine(t)
	const id = "t-oneshot-loop"
	var runs atomic.Int32
	if err := e.Register(Descriptor{ID: id, Family: "t", Name: "触发类任务", Kind: KindOneshot,
		Run: func(RunContext) error { runs.Add(1); return nil }}); err != nil {
		t.Fatal(err)
	}
	e.SetRole(true)
	loopOn := func() bool {
		m, ok := e.Lookup(id)
		if !ok {
			t.Fatalf("%s 未注册", id)
		}
		return m.LoopOn
	}

	e.StartLoop(id)
	if loopOn() {
		t.Fatal("Oneshot 任务 StartLoop 后 LoopOn=true——触发类不得被打开调度")
	}
	e.RearmLoop(id)
	if loopOn() {
		t.Fatal("Oneshot 任务 RearmLoop 后 LoopOn=true")
	}
	e.RearmLoop(id, true)
	if loopOn() {
		t.Fatal("Oneshot 任务 RearmLoop(hasWork) 后 LoopOn=true")
	}
	time.Sleep(100 * time.Millisecond)
	if got := runs.Load(); got != 0 {
		t.Fatalf("Oneshot 任务调度入口触发了 %d 轮执行, want 0（触发类不进调度面）", got)
	}
}
