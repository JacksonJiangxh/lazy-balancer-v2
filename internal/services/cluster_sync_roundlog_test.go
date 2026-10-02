package services

import (
	"strings"
	"testing"
)

// 2026-10-03 用户裁定：cluster-sync 同步轮日志零噪音——304 无变化轮零日志，
// 应用轮记版本，失败后恢复记一次。钉 syncRoundSuccessLines 的四形状。

func TestSyncRoundSuccessLines_fourShapes(t *testing.T) {
	// 304 无变化且上轮正常：零行
	if got := syncRoundSuccessLines(false, SyncResult{}); len(got) != 0 {
		t.Fatalf("304 无变化轮应零日志, got %v", got)
	}
	// 应用轮：一行含版本号
	got := syncRoundSuccessLines(false, SyncResult{AppliedVersion: 3806, Changed: true})
	if len(got) != 1 || !strings.Contains(got[0], "3806") || !strings.Contains(got[0], "增量回放") {
		t.Fatalf("应用轮应记版本: %v", got)
	}
	// 上轮失败后恢复且本轮 304：一行恢复
	got = syncRoundSuccessLines(true, SyncResult{})
	if len(got) != 1 || !strings.Contains(got[0], "恢复") {
		t.Fatalf("恢复轮应记一次恢复: %v", got)
	}
	// 恢复+应用：两行（恢复行在前）
	got = syncRoundSuccessLines(true, SyncResult{AppliedVersion: 7, Changed: true})
	if len(got) != 2 || !strings.Contains(got[0], "恢复") || !strings.Contains(got[1], "版本 7") {
		t.Fatalf("恢复+应用应两行: %v", got)
	}
}
