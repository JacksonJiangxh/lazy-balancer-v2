package taskengine

// TaskMeta.RoleApplicable 是 RunsOn 的派生只读结论：从节点上 master-only
// 族必须标为不适用（调度开关/下次执行在从节点没有实际意义）。

import (
	"testing"
	"time"
)

func TestEngine_RoleApplicableReflectsRunsOn(t *testing.T) {
	e := newTestEngine(t)
	noop := func(RunContext) error { return nil }
	if err := e.Register(Descriptor{ID: "t-master-only", Family: "t", Name: "主节点任务",
		Kind: KindPeriodic, RunsOn: RoleMasterOnly, IntervalFn: func() time.Duration { return time.Hour }, Run: noop}); err != nil {
		t.Fatal(err)
	}
	if err := e.Register(Descriptor{ID: "t-any", Family: "t", Name: "任意角色",
		Kind: KindPeriodic, IntervalFn: func() time.Duration { return time.Hour }, Run: noop}); err != nil {
		t.Fatal(err)
	}

	e.SetRole(true)
	if m, _ := e.Lookup("t-master-only"); !m.RoleApplicable {
		t.Fatal("主节点上 master-only 任务应适用")
	}
	if m, _ := e.Lookup("t-any"); !m.RoleApplicable {
		t.Fatal("RoleAny 任务在主节点应适用")
	}

	e.SetRole(false)
	if m, _ := e.Lookup("t-master-only"); m.RoleApplicable {
		t.Fatal("从节点上 master-only 任务不应适用（视图需标注仅主节点）")
	}
	if m, _ := e.Lookup("t-any"); !m.RoleApplicable {
		t.Fatal("RoleAny 任务在从节点仍应适用")
	}
}
