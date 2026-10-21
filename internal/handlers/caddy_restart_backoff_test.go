package handlers

// caddy-restart 重试的退避与落行降频：持续失败（Caddy 长期不可达）时每 2s
// 轮询不得每轮落一条 task_runs 失败行——退避指数增长、行数有界。

import (
	"os"
	"path/filepath"
	"testing"
	"time"

	"lazy-balancer-v2/internal/services"
)

func TestCaddyRestartBackoff_boundsTaskRunsUnderSustainedFailure(t *testing.T) {
	resetCaddyRestartBackoffForTest()
	t.Cleanup(resetCaddyRestartBackoffForTest)

	// 模拟 10 分钟持续失败：watcher 每 2s 一轮（600 次轮询）。
	now := time.Now()
	polls := 0
	attempts := 0
	recorded := 0
	for range 300 {
		polls++
		if caddyRestartShouldAttempt(now) {
			attempts++
			record, _ := caddyRestartBeginAttempt(now)
			if record {
				recorded++
			}
			caddyRestartEndAttempt(false, now)
		}
		now = now.Add(2 * time.Second)
	}

	if polls != 300 {
		t.Fatalf("轮询次数=%d, want 300", polls)
	}
	// 指数退避 2→30s：10 分钟内尝试次数必须显著少于轮询次数。
	if attempts > 40 {
		t.Fatalf("持续失败尝试次数=%d, want ≤40（指数退避未生效）", attempts)
	}
	// 落行 = 首次 + 每 10 轮：必须远小于尝试次数且非零。
	if recorded == 0 || recorded > attempts/5+1 {
		t.Fatalf("落 task_runs 行数=%d（尝试 %d 次）, want 有界且远小于尝试数", recorded, attempts)
	}

	// 成功收敛：退避清零，下一次立即允许尝试。
	caddyRestartEndAttempt(true, now)
	if !caddyRestartShouldAttempt(now) {
		t.Fatal("成功后必须清零退避（下一轮立即可尝试）")
	}
}

// 集成形状：首次失败落 1 行；紧接着的下一轮（退避窗口内）不得再落行，
// 也不得重复执行。
func TestCaddyRestartWatcher_backoffSkipsImmediateRetry(t *testing.T) {
	initTaskEngineForTest(t)
	newBackupTestHandlers(t)
	services.SetConfigLoadRerun(nil)
	t.Cleanup(func() { services.SetConfigLoadRerun(nil) })
	resetCaddyRestartBackoffForTest()
	t.Cleanup(resetCaddyRestartBackoffForTest)

	h := &Handlers{}
	trigger := filepath.Join(t.TempDir(), "caddy-restarted")
	if err := os.WriteFile(trigger, []byte("1"), 0644); err != nil {
		t.Fatal(err)
	}
	processStart := time.Now().Add(-time.Minute)

	h.caddyRestartWatcherOnce(trigger, processStart)
	first := countCaddyRestartRuns(t)
	if first != 1 {
		t.Fatalf("首次失败落行=%d, want 1", first)
	}

	// 退避窗口内（2s 未到）：不执行、不落行。
	h.caddyRestartWatcherOnce(trigger, processStart)
	if got := countCaddyRestartRuns(t); got != first {
		t.Fatalf("退避窗口内新增行：%d → %d, want 不变", first, got)
	}
	if _, err := os.Stat(trigger); err != nil {
		t.Fatalf("失败轮必须保留触发文件: %v", err)
	}
}
