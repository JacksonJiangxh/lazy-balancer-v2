package services

// 看门狗降级窗口收口钉测：BecomeSlave 的 SetRole(false) 会取消在途 Periodic
// Run 的 rc.Ctx——在途看门狗轮若不消费 ctx，会以旧主节点视角跑完并覆写
// 复位后的漂移态（复位→误报漂移的窗口）。

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
	"time"

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
	if drift := CurrentConfigDrift(); !drift.Consistent || len(drift.Missing) != 0 || len(drift.Extra) != 0 {
		t.Fatalf("取消轮覆写复位态: %+v", drift)
	}
	configDriftMu.Lock()
	clean, skipped := configDriftCleanRounds, configDriftSkipped
	configDriftMu.Unlock()
	if clean != 0 || skipped != 0 {
		t.Fatalf("取消轮不得累积簿记: clean=%d skipped=%d", clean, skipped)
	}
}

// 中段取消（检查已开始、簿记未落）：在途轮照样不得落写——用可阻塞的
// admin 把取消精确落进比对窗口，钉住比对出口的第二复核点。
// 披露：检查函数内部的漂移状态转移（updateConfigDrift）在出口复核之前完成，
// 本用例保护的是「每轮簿记」（干净轮/跳过轮/心跳/任务日志）与「漂移确认」，
// 不宣称回滚检查内部已写入的单轮状态。
func TestWatchdogCheckOnce_cancelAfterCheckSkipsBookkeeping(t *testing.T) {
	_, database := newClusterTestService(t)
	seedGenerationRule(t, database, "lb_watchdog_midround_cancel", false)
	resetConfigWatchdogForTest(t)
	newTaskLogDir(t)
	started := make(chan struct{}, 1)
	release := make(chan struct{})
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		select {
		case started <- struct{}{}:
		default:
		}
		<-release
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(emptyCaddyConfig))
	}))
	defer server.Close()
	watchdogAdminURLValue = server.URL
	t.Cleanup(func() { watchdogAdminURLValue = "" })

	ctx, cancel := context.WithCancel(context.Background())
	errCh := make(chan error, 1)
	go func() { errCh <- WatchdogCheckOnce(ctx) }()
	select {
	case <-started:
	case <-time.After(5 * time.Second):
		cancel()
		close(release)
		t.Fatal("看门狗未抵达比对窗口（假 admin 未被请求）")
	}
	cancel()
	close(release)
	var err error
	select {
	case err = <-errCh:
	case <-time.After(5 * time.Second):
		t.Fatal("取消后的看门狗轮未返回")
	}

	if !errors.Is(err, context.Canceled) {
		t.Fatalf("中段取消轮必须返回取消错误: %v", err)
	}
	if drift := CurrentConfigDrift(); !drift.Consistent || len(drift.Missing) != 0 || len(drift.Extra) != 0 {
		t.Fatalf("中段取消轮不得确认漂移: %+v", drift)
	}
	configDriftMu.RLock()
	clean, skipped, heartbeatSkipped := configDriftCleanRounds, configDriftSkipped, configDriftHeartbeatSkipped
	configDriftMu.RUnlock()
	if clean != 0 || skipped != 0 || heartbeatSkipped != 0 {
		t.Fatalf("中段取消轮不得累积簿记: clean=%d skipped=%d heartbeatSkipped=%d", clean, skipped, heartbeatSkipped)
	}
	if data, readErr := os.ReadFile(taskengine.TaskLogPath("config-watchdog")); readErr == nil && len(data) != 0 {
		t.Fatalf("中段取消轮不得写任务日志: %q", string(data))
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
