package services

// StatusMirror 消费端词表归一钉测：状态列只承载执行态三态
// （running/idle/failed）——StatusMirror 直通前必须校验词表，非词表值
// （业务态混入/未来新增态未同步）按空镜像回落执行实态推导 + WARN 留痕，
// 不得直通渲染失真（前端词表同样只认三态）。

import (
	"testing"
	"time"

	"lazy-balancer-v2/internal/taskengine"
)

// Given 注册族的 StatusFn 产出非词表值（业务态混入形态）。
// Then 状态列回落执行实态推导（idle——无在途无失败行），不得直通业务态串。
func TestCollectEngineFamilies_statusMirrorOutOfVocabularyFallsBack(t *testing.T) {
	newClusterTestService(t)
	e := taskengine.NewEngine(taskengine.Options{TickInterval: time.Hour})
	t.Cleanup(e.Stop)
	if err := e.Register(taskengine.Descriptor{
		ID: "t-leaky-mirror", Family: "t", Name: "词表外镜像", Kind: taskengine.KindPeriodic,
		IntervalFn: func() time.Duration { return time.Hour },
		StatusFn:   func() string { return "downloading" }, // 业务态混入词表外值
		Run:        func(taskengine.RunContext) error { return nil },
	}); err != nil {
		t.Fatal(err)
	}

	rows := collectEngineFamilies(e)
	for _, ti := range rows {
		if ti.ID != "t-leaky-mirror" {
			continue
		}
		switch ti.Status {
		case TaskStatusIdle, TaskStatusRunning, TaskStatusFailed:
		default:
			t.Fatalf("词表外镜像直通状态列: %q（必须回落执行实态）", ti.Status)
		}
		if ti.Status != TaskStatusIdle {
			t.Fatalf("无在途无失败行应回落 idle, got %q", ti.Status)
		}
		return
	}
	t.Fatal("注册族缺失")
}

// 词表内值照常直通（回归形状——归一不得误杀合法镜像）。
func TestCollectEngineFamilies_statusMirrorInVocabularyPassesThrough(t *testing.T) {
	newClusterTestService(t)
	e := taskengine.NewEngine(taskengine.Options{TickInterval: time.Hour})
	t.Cleanup(e.Stop)
	if err := e.Register(taskengine.Descriptor{
		ID: "t-good-mirror", Family: "t", Name: "词表内镜像", Kind: taskengine.KindPeriodic,
		IntervalFn: func() time.Duration { return time.Hour },
		StatusFn:   func() string { return "running" },
		Run:        func(taskengine.RunContext) error { return nil },
	}); err != nil {
		t.Fatal(err)
	}

	rows := collectEngineFamilies(e)
	for _, ti := range rows {
		if ti.ID == "t-good-mirror" {
			if ti.Status != TaskStatusRunning {
				t.Fatalf("词表内镜像应直通, got %q", ti.Status)
			}
			return
		}
	}
	t.Fatal("注册族缺失")
}

// 引擎族产出词表钉测：全部装配族的 StatusFn 产出必须 ∈ 执行态词表
// （含空=无镜像）——生产侧漂移（新增业务态直通）当场拦截。
func TestWireFamilies_statusMirrorVocabulary(t *testing.T) {
	te := newWireTestEngine(t)
	te.SetRole(true)
	vocab := map[string]bool{"": true, "running": true, "idle": true, "failed": true}
	for _, m := range te.DescribeAll() {
		if !vocab[m.StatusMirror] {
			t.Fatalf("族 %s 状态镜像产出词表外值 %q（状态列只承载 running/idle/failed）", m.ID, m.StatusMirror)
		}
	}
}
