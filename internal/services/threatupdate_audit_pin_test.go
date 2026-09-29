package services

// Round 62 修复钉：更新族审计单记+操作者归人（U1-P3-1/U1-P3-2）。
// threat 族零源路径（成功早退）为可测最小形：一次 run 恰一条审计、
// operator 经 RunContext 流入审计 username。

import (
	"testing"

	"lazy-balancer-v2/internal/db"
	"lazy-balancer-v2/internal/taskengine"
)

func countThreatAudits(t *testing.T) int {
	t.Helper()
	var n int
	if err := db.AuditDB.QueryRow(`SELECT COUNT(*) FROM audit_log WHERE resource='威胁情报库'`).Scan(&n); err != nil {
		t.Fatalf("count audits: %v", err)
	}
	return n
}

// Given 零启用源的威胁库（run 走成功早退）。
// When 经 RunContext 带 operator 执行一次 RunUpdate("manual")。
// Then 恰落 1 条审计（U1-P3-2：曾 defer+端点补记 2-3 条），且
// username=operator（U1-P3-1：曾恒 system，手动操作无法追责）。
func TestThreatRunUpdate_SingleAuditWithOperator(t *testing.T) {
	oldDB, oldMetricsDB, oldAuditDB := db.DB, db.MetricsDB, db.AuditDB
	if err := db.Initialize(t.TempDir()); err != nil {
		t.Fatalf("initialize test database: %v", err)
	}
	t.Cleanup(func() {
		_ = db.Close()
		db.DB, db.MetricsDB, db.AuditDB = oldDB, oldMetricsDB, oldAuditDB
	})
	m := GetThreatUpdateManager()
	if m == nil {
		ResetThreatUpdateManagerForTest()
		m = GetThreatUpdateManager()
	}
	if m == nil {
		t.Fatal("manager 未初始化")
	}
	if err := m.RunUpdate("manual", &taskengine.RunContext{Operator: "alice"}); err != nil {
		t.Fatalf("RunUpdate: %v", err)
	}
	if got := countThreatAudits(t); got != 1 {
		t.Fatalf("一次 run 应恰 1 条审计（单记口径）, got %d", got)
	}
	var user string
	if err := db.AuditDB.QueryRow(`SELECT username FROM audit_log WHERE resource='威胁情报库'`).Scan(&user); err != nil {
		t.Fatal(err)
	}
	if user != "alice" {
		t.Fatalf("审计 username 应为 operator=alice, got %q", user)
	}
}
