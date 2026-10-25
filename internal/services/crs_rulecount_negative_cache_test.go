package services

import (
	"path/filepath"
	"testing"
	"time"
)

// 规则树不可读（缺失/迁移期/树交换窗口）时 /security/crs 轮询不得每次付一次
// 递归 WalkDir + 一条 ERROR：扫描失败按 30s 负缓存，树被替换的通道
// （InvalidateRuleCount）清零后立即重扫。
func TestRuleCount_negativeCacheOnScanFailure(t *testing.T) {
	m := newCRSUpdateManager(func() error { return nil })
	m.crsDir = t.TempDir() // 无 rules/ 子目录 → WalkDir 失败

	if got := m.RuleCount(); got != 0 {
		t.Fatalf("坏树 RuleCount=%d, want 0", got)
	}
	m.mu.Lock()
	retryAfter := m.ruleCountRetryAfter
	m.mu.Unlock()
	if retryAfter.IsZero() || !retryAfter.After(time.Now()) {
		t.Fatalf("扫描失败必须置负缓存截止时刻，got=%v", retryAfter)
	}

	// 树恢复后，负缓存期内不得重扫（否则坏树状态下每轮轮询各付一次递归 Walk）。
	writeTestFile(t, filepath.Join(m.crsDir, "rules", "REQUEST-900.conf"), "SecRule a\n")
	if got := m.RuleCount(); got != 0 {
		t.Fatalf("负缓存期内 RuleCount=%d, want 0（不得重扫）", got)
	}

	// 树被带外替换 → 失效通道清零负缓存 → 立即重扫。
	m.InvalidateRuleCount()
	if got := m.RuleCount(); got != 1 {
		t.Fatalf("失效后 RuleCount=%d, want 1（必须重新扫描）", got)
	}
}
