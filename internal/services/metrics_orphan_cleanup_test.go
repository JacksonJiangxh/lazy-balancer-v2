package services

// 历史修复：metrics_history 孤儿行收敛清理（taskengine metrics-orphan-cleanup
// 任务体）钉测试。

import (
	"database/sql"
	"testing"

	"lazy-balancer-v2/internal/db"
)

func seedMetricsHistory(t *testing.T, ruleID any, requests int) {
	t.Helper()
	if _, err := db.MetricsDB.Exec(`INSERT INTO metrics_history (rule_id, timestamp, requests_total) VALUES (?, datetime('now'), ?)`, ruleID, requests); err != nil {
		t.Fatalf("seed metrics_history(%v): %v", ruleID, err)
	}
}

func countMetricsHistory(t *testing.T, where string, args ...any) int {
	t.Helper()
	var count int
	query := `SELECT COUNT(*) FROM metrics_history`
	if where != "" {
		query += " WHERE " + where
	}
	if err := db.MetricsDB.QueryRow(query, args...).Scan(&count); err != nil {
		t.Fatalf("count metrics_history: %v", err)
	}
	return count
}

// Given 存活规则指标 + 已删除规则残留指标 + 全局(NULL rule_id)指标。
// When 执行孤儿清理。
// Then 仅残留行被删；存活规则与全局行保留；返回删除的规则数。
func TestPurgeOrphanMetricsHistory_deletesOrphansKeepsLiveAndGlobal(t *testing.T) {
	_, database := newClusterTestService(t)
	if _, err := database.Exec(`INSERT INTO lb_rules (caddy_id,name,protocol,listen_port,enabled) VALUES ('lb_live','live','http',18091,1)`); err != nil {
		t.Fatalf("seed live rule: %v", err)
	}
	seedMetricsHistory(t, "lb_live", 3)
	seedMetricsHistory(t, "lb_orphan", 4)
	seedMetricsHistory(t, "lb_orphan", 5)
	seedMetricsHistory(t, nil, 6)

	// When
	deletedRules, err := PurgeOrphanMetricsHistory(t.Context())

	// Then
	if err != nil {
		t.Fatalf("purge: %v", err)
	}
	if deletedRules != 1 {
		t.Fatalf("deletedRules=%d, want 1", deletedRules)
	}
	if got := countMetricsHistory(t, "rule_id='lb_orphan'"); got != 0 {
		t.Fatalf("孤儿行残留=%d, want 0", got)
	}
	if got := countMetricsHistory(t, "rule_id='lb_live'"); got != 1 {
		t.Fatalf("存活规则行=%d, want 1（不得误删）", got)
	}
	if got := countMetricsHistory(t, "rule_id IS NULL"); got != 1 {
		t.Fatalf("全局(NULL)行=%d, want 1（不得误删）", got)
	}
}

// Given 孤儿行数超过单轮上限。
// When 连续两轮执行。
// Then 首轮只删上限数（有界），次轮收敛余量——重试有界且最终收敛。
func TestPurgeOrphanMetricsHistory_boundedPerRun(t *testing.T) {
	_, database := newClusterTestService(t)
	_ = database
	for _, ruleID := range []string{"lb_o1", "lb_o2", "lb_o3"} {
		seedMetricsHistory(t, ruleID, 1)
	}
	previous := metricsOrphanPurgeRulesPerRun
	metricsOrphanPurgeRulesPerRun = 2
	t.Cleanup(func() { metricsOrphanPurgeRulesPerRun = previous })

	// When
	firstRun, err := PurgeOrphanMetricsHistory(t.Context())
	if err != nil {
		t.Fatalf("purge round 1: %v", err)
	}
	secondRun, err := PurgeOrphanMetricsHistory(t.Context())
	if err != nil {
		t.Fatalf("purge round 2: %v", err)
	}

	// Then
	if firstRun != 2 {
		t.Fatalf("首轮删除规则数=%d, want 2（单轮有界）", firstRun)
	}
	if secondRun != 1 {
		t.Fatalf("次轮删除规则数=%d, want 1（收敛余量）", secondRun)
	}
	if got := countMetricsHistory(t, "rule_id IS NOT NULL"); got != 0 {
		t.Fatalf("孤儿行残留=%d, want 0", got)
	}
}

// Given metrics 库不可用。
// When 执行孤儿清理。
// Then 错误显式上抛（task_runs 落 failed），不得假成功。
func TestPurgeOrphanMetricsHistory_surfacesMetricsDBError(t *testing.T) {
	_, _ = newClusterTestService(t)
	broken, err := sql.Open("sqlite", ":memory:")
	if err != nil {
		t.Fatalf("open scratch metrics db: %v", err)
	}
	if err := broken.Close(); err != nil {
		t.Fatalf("close scratch metrics db: %v", err)
	}
	previous := db.MetricsDB
	db.MetricsDB = broken
	t.Cleanup(func() { db.MetricsDB = previous })

	if _, err := PurgeOrphanMetricsHistory(t.Context()); err == nil {
		t.Fatal("metrics 库不可用时必须返回错误（task_runs 落 failed），不得静默成功")
	}
}
