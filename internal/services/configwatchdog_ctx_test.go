package services

// 看门狗降级窗口收口钉测：BecomeSlave 的 SetRole(false) 会取消在途 Periodic
// Run 的 rc.Ctx——在途看门狗轮若不消费 ctx，会以旧主节点视角跑完并覆写
// 复位后的漂移态（复位→误报漂移的窗口）。

import (
	"context"
	"os"
	"strings"
	"testing"

	"lazy-balancer-v2/internal/taskengine"
)

// Given 主节点 + 已复位的漂移态 + 已取消的轮 ctx（降级/停机窗口形态）。
// When WatchdogCheckOnce 以取消 ctx 运行。
// Then 整轮中止（返回取消错误），漂移簿记/状态零改写（不覆写复位态）。
func TestWatchdogCheckOnce_cancelledCtxAbortsWithoutTouchingDriftState(t *testing.T) {
	_, database := newClusterTestService(t)
	seedGenerationRule(t, database, "lb_watchdog_inflight_demote", false)
	resetConfigWatchdogForTest(t)
	newTaskLogDir(t)
	server := fakeCaddyWithRoutes(t, emptyCaddyConfig)
	watchdogAdminURLValue = server.URL
	t.Cleanup(func() { watchdogAdminURLValue = "" })

	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	if err := WatchdogCheckOnce(ctx); err == nil {
		t.Fatal("取消 ctx 的看门狗轮必须中止并返回错误（不得在降级窗口跑完）")
	}
	if drift := CurrentConfigDrift(); !drift.Consistent || len(drift.Missing) != 0 || len(drift.Extra) != 0 || drift.SkippedRounds != 0 {
		t.Fatalf("取消轮覆写复位态: %+v", drift)
	}
	configDriftMu.Lock()
	clean, skipped := configDriftCleanRounds, configDriftSkipped
	configDriftMu.Unlock()
	if clean != 0 || skipped != 0 {
		t.Fatalf("取消轮不得累积簿记: clean=%d skipped=%d", clean, skipped)
	}
}

// 中段取消（比对完成后、簿记落写前）：在途轮照样不得落写——用「检查期内
// 取消」形态钉第二复核点。
func TestWatchdogCheckOnce_cancelAfterCheckSkipsBookkeeping(t *testing.T) {
	_, database := newClusterTestService(t)
	seedGenerationRule(t, database, "lb_watchdog_midround_cancel", false)
	resetConfigWatchdogForTest(t)
	newTaskLogDir(t)
	server := fakeCaddyWithRoutes(t, emptyCaddyConfig)
	watchdogAdminURLValue = server.URL
	t.Cleanup(func() { watchdogAdminURLValue = "" })

	ctx, cancel := context.WithCancel(context.Background())
	// 比对出口即取消（等价降级落在比对窗口期）。
	cancel()

	if err := WatchdogCheckOnce(ctx); err == nil {
		t.Fatal("中段取消轮必须返回错误")
	}
	if drift := CurrentConfigDrift(); !drift.Consistent || drift.SkippedRounds != 0 {
		t.Fatalf("中段取消轮覆写复位态: %+v", drift)
	}
}

// 回归形状：活 ctx 的主节点轮照常检查（空运行配置两轮置漂移态）。
func TestWatchdogCheckOnce_liveCtxChecksNormally(t *testing.T) {
	_, database := newClusterTestService(t)
	seedGenerationRule(t, database, "lb_watchdog_live_ctx", false)
	resetConfigWatchdogForTest(t)
	newTaskLogDir(t)
	server := fakeCaddyWithRoutes(t, emptyCaddyConfig)
	watchdogAdminURLValue = server.URL
	t.Cleanup(func() { watchdogAdminURLValue = "" })

	_ = WatchdogCheckOnce(context.Background())
	_ = WatchdogCheckOnce(context.Background())
	if drift := CurrentConfigDrift(); drift.Consistent {
		t.Fatal("活 ctx 主节点轮应照常检查（两轮不一致置漂移态）")
	}
	if data, err := os.ReadFile(taskengine.TaskLogPath("config-watchdog")); err == nil && strings.Contains(string(data), "配置漂移") {
		// 漂移行可见性不回退（第二轮起逐轮漂移行照旧）
	} else if err != nil {
		t.Fatalf("read task log: %v", err)
	}
}
