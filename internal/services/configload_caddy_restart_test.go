package services

// V1（第 67 轮用户裁定）：Caddy 重启 watcher 直调 ApplyConfigOnStartup 绕过
// 引擎（无 task_runs/[start]/[done]/单飞，审计+任务日志双行）——一切任务统一
// 引擎调度。修复：watcher 改 RunSync("startup:config-load","caddy-restart")，
// Run 体触发门放行 caddy-restart（现门仅 manual/startup，直放会 no-op）。

import (
	"sync/atomic"
	"testing"
)

// Given 引擎在场且注入了配置重载执行体。
// When 以 trigger=caddy-restart 经引擎同步触发 startup:config-load。
// Then 执行体必须真实执行一次（现门 no-op——RED）。
func TestStartupConfigLoad_caddyRestartTriggerExecutes(t *testing.T) {
	eng := newWireTestEngine(t)
	var calls atomic.Int32
	SetConfigLoadRerun(func(operator string) error {
		calls.Add(1)
		return nil
	})
	t.Cleanup(func() { SetConfigLoadRerun(nil) })

	if _, err := eng.RunSync("startup:config-load", "caddy-restart", ""); err != nil {
		t.Fatalf("caddy-restart 触发应成功: %v", err)
	}
	if n := calls.Load(); n != 1 {
		t.Fatalf("caddy-restart 触发应执行配置载入 1 次, got %d（触发门未放行）", n)
	}
}

// 回归形状：manual/startup 两个既有触发形态保持执行。
func TestStartupConfigLoad_existingTriggersStillExecute(t *testing.T) {
	eng := newWireTestEngine(t)
	var calls atomic.Int32
	SetConfigLoadRerun(func(operator string) error {
		calls.Add(1)
		return nil
	})
	t.Cleanup(func() { SetConfigLoadRerun(nil) })

	for _, trigger := range []string{"manual", "startup"} {
		if _, err := eng.RunSync("startup:config-load", trigger, ""); err != nil {
			t.Fatalf("%s 触发应成功: %v", trigger, err)
		}
	}
	if n := calls.Load(); n != 2 {
		t.Fatalf("manual+startup 应各执行 1 次, got %d", n)
	}
}
