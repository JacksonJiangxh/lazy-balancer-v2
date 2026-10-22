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

	// Simulate 25 failed attempts. Each iteration fast-forwards the next poll only
	// after asserting that the just-finished attempt scheduled a bounded delay.
	attempts := 0
	recorded := 0
	for range 25 {
		now := time.Now()
		if !caddyRestartShouldAttempt(now) {
			t.Fatal("fast-forwarded retry window must admit the next attempt")
		}
		attempts++
		record, _ := caddyRestartBeginAttempt(now)
		if record {
			recorded++
		}
		caddyRestartEndAttempt(false)
		caddyRestartBackoff.mu.Lock()
		nextAttempt := caddyRestartBackoff.nextAttempt
		caddyRestartBackoff.nextAttempt = time.Time{}
		caddyRestartBackoff.mu.Unlock()
		if !nextAttempt.After(now) || nextAttempt.After(now.Add(caddyRestartBackoffMax+time.Second)) {
			t.Fatalf("next attempt=%s after %d failures, want a positive delay capped at %s", nextAttempt, attempts, caddyRestartBackoffMax)
		}
	}

	// 落行 = 首次 + 每 10 轮：必须远小于尝试次数且非零。
	if recorded == 0 || recorded > attempts/5+1 {
		t.Fatalf("落 task_runs 行数=%d（尝试 %d 次）, want 有界且远小于尝试数", recorded, attempts)
	}

	// 成功收敛：退避清零，下一次立即允许尝试。
	caddyRestartEndAttempt(true)
	if !caddyRestartShouldAttempt(time.Now()) {
		t.Fatal("成功后必须清零退避（下一轮立即可尝试）")
	}
}

func TestCaddyRestartBackoff_slowFailureStartsDelayAtAttemptEnd(t *testing.T) {
	resetCaddyRestartBackoffForTest()
	t.Cleanup(resetCaddyRestartBackoffForTest)

	// Given an attempt that started three seconds ago and is only failing now.
	attemptStart := time.Now().Add(-3 * time.Second)
	caddyRestartBeginAttempt(attemptStart)
	beforeEnd := time.Now()
	caddyRestartEndAttempt(false)
	afterEnd := time.Now()

	// Then the full delay starts at the end, not in the past at the start.
	caddyRestartBackoff.mu.Lock()
	nextAttempt := caddyRestartBackoff.nextAttempt
	caddyRestartBackoff.mu.Unlock()
	if nextAttempt.Before(beforeEnd.Add(caddyRestartBackoffBase)) || nextAttempt.After(afterEnd.Add(caddyRestartBackoffBase)) {
		t.Fatalf("next attempt=%s, want end-based window [%s, %s]", nextAttempt, beforeEnd.Add(caddyRestartBackoffBase), afterEnd.Add(caddyRestartBackoffBase))
	}
	if caddyRestartShouldAttempt(time.Now()) {
		t.Fatal("slow failure must not permit an immediate retry")
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
