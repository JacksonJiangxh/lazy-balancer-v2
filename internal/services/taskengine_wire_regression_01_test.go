package services

// （不再内部二次查表） / 历史修复 装配暂停与 BootSync 后恢复调度的结构钉。

import (
	"errors"
	"testing"
	"time"

	"lazy-balancer-v2/internal/db"
	"lazy-balancer-v2/internal/taskengine"
)

// 表二次查询，传入快照被无视（此测试传「库中不存在」的偏好行，行为必须
// 按快照生效）。单任务版 loadTaskLoopPref 已删除，测试经 loadTaskLoopPrefs
// 取单键。
func TestApplyTaskLoopPrefs_consumesProvidedSnapshot(t *testing.T) {
	te := newWireTestEngine(t)
	meta, ok := te.Lookup("log-cleanup")
	if !ok || !meta.LoopOn {
		t.Fatalf("装配默认应开启 log-cleanup 调度, ok=%v loopOn=%v", ok, meta.LoopOn)
	}
	// 快照中的偏好行不在 task_loop_prefs 表内（旧实现内部重查 → 空映射 → 无效）。
	if prefs := loadTaskLoopPrefs(); len(prefs) != 0 {
		t.Fatalf("基线表应为空, got %v", prefs)
	}
	applyTaskLoopPrefs(te, map[string]bool{"log-cleanup": false})
	if meta, _ := te.Lookup("log-cleanup"); meta.LoopOn {
		t.Fatal("applyTaskLoopPrefs 必须消费调用方快照（旧实现内部重查表会无视该偏好）")
	}
}

// InitTaskEngine 装配期调度暂停、BootSync 完成后恢复——直接观察
// 引擎公开执行门，不再读取源码文本。暂停门与 tick 共用 schedPaused，BootSync
// 的 startup 触发是该暂停期唯一豁免。
func TestInitTaskEngine_pausesTickUntilBootSyncDone(t *testing.T) {
	oldDB, oldMetricsDB, oldAuditDB := db.DB, db.MetricsDB, db.AuditDB
	if err := db.Initialize(t.TempDir()); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		StopTaskEngine()
		_ = db.Close()
		db.DB, db.MetricsDB, db.AuditDB = oldDB, oldMetricsDB, oldAuditDB
	})
	bootEntered := make(chan struct{})
	releaseBoot := make(chan struct{})
	SetConfigLoadRerun(func(string) error {
		close(bootEntered)
		<-releaseBoot
		return nil
	})
	t.Cleanup(func() { SetConfigLoadRerun(nil) })
	initDone := make(chan *taskengine.Engine, 1)
	go func() { initDone <- InitTaskEngine("", t.TempDir()+"/app.log") }()

	select {
	case <-bootEntered:
	case <-time.After(2 * time.Second):
		t.Fatal("BootSync did not reach configLoadRerun")
	}
	te := TaskEngine()
	if te == nil {
		t.Fatal("engine must be registered before BootSync")
	}
	if err := te.Trigger("config-watchdog", "manual", "test"); !errors.Is(err, taskengine.ErrSchedulingPaused) {
		t.Fatalf("execution during BootSync err=%v, want ErrSchedulingPaused", err)
	}

	close(releaseBoot)
	select {
	case te = <-initDone:
	case <-time.After(2 * time.Second):
		t.Fatal("InitTaskEngine did not finish after BootSync release")
	}
	// 看门狗整轮未判定现在会返回错误（Caddy admin 不可达=未判定），
	// 本用例断言的是「BootSync 后调度已恢复」，故注入可用的假 Caddy admin，
	// 使 Trigger 的成功/失败只反映调度门状态。
	server := fakeCaddyWithRoutes(t, emptyCaddyConfig)
	oldURL := watchdogAdminURLValue
	watchdogAdminURLValue = server.URL
	t.Cleanup(func() { watchdogAdminURLValue = oldURL })
	if err := te.Trigger("config-watchdog", "manual", "test"); err != nil {
		t.Fatalf("execution after BootSync must be resumed: %v", err)
	}
}
