package services

// 「运行中」只由引擎真实在途执行支撑：task_runs 终态更新失败的残留 running
// 行不得让任务视图恒显运行中并禁用「运行」按钮；真实在途轮仍呈现运行中。

import (
	"testing"
	"time"

	"lazy-balancer-v2/internal/db"
	"lazy-balancer-v2/internal/taskengine"
)

func registerMonitorTestTask(t *testing.T, e *taskengine.Engine, id string, run func(taskengine.RunContext) error) {
	t.Helper()
	if err := e.Register(taskengine.Descriptor{
		ID: id, Family: "t", Name: id, Kind: taskengine.KindPeriodic,
		IntervalFn: func() time.Duration { return time.Hour },
		Run:        run,
	}); err != nil {
		t.Fatal(err)
	}
}

func findTaskInfo(t *testing.T, rows []TaskInfo, id string) TaskInfo {
	t.Helper()
	for _, ti := range rows {
		if ti.ID == id {
			return ti
		}
	}
	t.Fatalf("任务 %s 不在聚合视图", id)
	return TaskInfo{}
}

func TestCollectEngineFamilies_staleRunningRowIsNotRunning(t *testing.T) {
	newClusterTestService(t)
	e := taskengine.NewEngine(taskengine.Options{TickInterval: time.Hour})
	t.Cleanup(e.Stop)
	registerMonitorTestTask(t, e, "t-stale-run", func(taskengine.RunContext) error { return nil })

	if _, err := db.DB.Exec(`INSERT INTO task_runs (task_id, family, trigger, status, started_at)
		VALUES ('t-stale-run', 't', 'auto', 'running', datetime('now','-5 minutes'))`); err != nil {
		t.Fatal(err)
	}

	ti := findTaskInfo(t, collectEngineFamilies(e), "t-stale-run")
	if ti.Status == TaskStatusRunning {
		t.Fatal("进程内已无在途执行时，残留 running 行不得呈现运行中（运行按钮被永久禁用）")
	}
	if ti.Status != TaskStatusFailed {
		t.Fatalf("残留 running 行应呈现 failed, got %q", ti.Status)
	}
	if ti.LastRun == nil || ti.LastRun.Result != "interrupted" {
		t.Fatalf("最近运行结果应按中断呈现, got %+v", ti.LastRun)
	}
	if ti.LastRun.Message == "" {
		t.Fatal("残留行应说明终态未落库，避免与正常中断同形")
	}
}

func TestCollectEngineFamilies_youngRunningRowStaysRunningWithinGrace(t *testing.T) {
	// 行快照与内存快照之间的瞬态：刚写入的 running 行 + 内存已空闲（该轮
	// 在两次取数之间完成）不得立即呈现失败/中断。
	newClusterTestService(t)
	e := taskengine.NewEngine(taskengine.Options{TickInterval: time.Hour})
	t.Cleanup(e.Stop)
	registerMonitorTestTask(t, e, "t-young-run", func(taskengine.RunContext) error { return nil })

	startedAt := time.Now().In(CurrentLocation()).Format("2006-01-02 15:04:05")
	if _, err := db.DB.Exec(`INSERT INTO task_runs (task_id, family, trigger, status, started_at)
		VALUES ('t-young-run', 't', 'auto', 'running', ?)`, startedAt); err != nil {
		t.Fatal(err)
	}

	ti := findTaskInfo(t, collectEngineFamilies(e), "t-young-run")
	if ti.Status != TaskStatusRunning {
		t.Fatalf("宽限期内的 running 行应保持运行中（瞬态自愈），got %q", ti.Status)
	}
	if ti.LastRun != nil && ti.LastRun.Result == "interrupted" {
		t.Fatalf("宽限期内不得按中断呈现, got %+v", ti.LastRun)
	}
}

func TestCollectEngineFamilies_inFlightRunStaysRunning(t *testing.T) {
	newClusterTestService(t)
	e := taskengine.NewEngine(taskengine.Options{TickInterval: time.Hour})
	t.Cleanup(e.Stop)
	registerMonitorTestTask(t, e, "t-live-run", func(rc taskengine.RunContext) error {
		<-rc.Ctx.Done()
		return rc.Ctx.Err()
	})
	if err := e.RunAsync("t-live-run", "manual", ""); err != nil {
		t.Fatal(err)
	}

	deadline := time.Now().Add(2 * time.Second)
	for {
		ti := findTaskInfo(t, collectEngineFamilies(e), "t-live-run")
		// 状态列现在优先采信内存 running（行插入失败/静默轮的显示真值），
		// 因此可能在 task_runs running 行落库之前就呈现 running——此时
		// LastRun 尚未出现属正常瞬态，继续轮询等行落库后再断言结果列。
		if ti.Status == TaskStatusRunning && ti.LastRun != nil {
			if ti.LastRun.Result != "running" {
				t.Fatalf("在途轮最近运行结果应保持 running, got %+v", ti.LastRun)
			}
			return
		}
		if time.Now().After(deadline) {
			t.Fatalf("在途执行应呈现运行中（且落 running 行）, got %q lastRun=%+v", ti.Status, ti.LastRun)
		}
		time.Sleep(10 * time.Millisecond)
	}
}
