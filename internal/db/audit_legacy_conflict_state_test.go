package db

import (
	"database/sql"
	"path/filepath"
	"strings"
	"testing"
)

// 已知冲突态必须持久化：人工处理前，主库旧审计表每启动都会重跑
// INSERT OR IGNORE + 两次全表 mismatch 校验（跨库 ATTACH，历史库可达数十万
// 行）。冲突指纹（行数/MIN/MAX/SUM(id)）命中即跳过，仅留 WARN；主表内容变化
// 指纹失配则重新核对；冲突解除（主表被人工删除）自动清除标记。
func TestMigrateLegacyAuditLogs_conflictStateSkipsReprocessingUntilResolved(t *testing.T) {
	dir := t.TempDir()
	mainDB, err := sql.Open("sqlite", filepath.Join(dir, "main.db"))
	if err != nil {
		t.Fatalf("open main database: %v", err)
	}
	t.Cleanup(func() { _ = mainDB.Close() })
	if _, err := mainDB.Exec(legacyAuditTableDDL); err != nil {
		t.Fatalf("create legacy audit table: %v", err)
	}
	if _, err := mainDB.Exec(`INSERT INTO audit_log (id, username, action, resource, detail, ip_address, created_at) VALUES
		(1, 'admin', '旧动作', '对象甲', 'old', '1.1.1.1', '2026-01-01 00:00:00'),
		(2, 'admin', '无冲突动作', '对象乙', 'same', '2.2.2.2', '2026-01-02 00:00:00')`); err != nil {
		t.Fatalf("seed legacy audit rows: %v", err)
	}
	auditPath := filepath.Join(dir, "audit.db")
	auditDB, err := sql.Open("sqlite", auditPath)
	if err != nil {
		t.Fatalf("open audit database: %v", err)
	}
	t.Cleanup(func() { _ = auditDB.Close() })
	if _, err := auditDB.Exec(legacyAuditTableDDL); err != nil {
		t.Fatalf("create audit table: %v", err)
	}
	if _, err := auditDB.Exec(`INSERT INTO audit_log (id, username, action, resource, detail, ip_address, created_at) VALUES
		(1, 'admin', '新动作', '对象甲', 'new', '1.1.1.1', '2026-01-01 00:00:00'),
		(3, 'admin', '审计库动作', '对象丙', 'dst', '3.3.3.3', '2026-01-03 00:00:00')`); err != nil {
		t.Fatalf("seed audit rows: %v", err)
	}
	oldAuditDB := AuditDB
	AuditDB = auditDB
	t.Cleanup(func() { AuditDB = oldAuditDB })

	// 首轮：冲突 → 留痕一条并持久化冲突指纹。
	drainSystemAuditBuffer()
	if err := migrateLegacyAuditLogs(mainDB, auditPath); err != nil {
		t.Fatalf("conflict must not fail startup: %v", err)
	}
	entries := drainSystemAuditBuffer()
	if len(entries) != 1 || !strings.Contains(entries[0].detail, "冲突") {
		t.Fatalf("首轮冲突留痕=%+v, want 一条", entries)
	}
	var storedFingerprint string
	if err := auditDB.QueryRow(`SELECT fingerprint FROM audit_migration_state WHERE name=?`, auditLegacyConflictMarkerName).Scan(&storedFingerprint); err != nil {
		t.Fatalf("conflict fingerprint not persisted: %v", err)
	}

	// 次轮：同一冲突态 → 跳过复制与校验，且不重复刷审计。
	skipsBefore := auditLegacyConflictSkips.Load()
	if err := migrateLegacyAuditLogs(mainDB, auditPath); err != nil {
		t.Fatalf("second run: %v", err)
	}
	if got := auditLegacyConflictSkips.Load() - skipsBefore; got != 1 {
		t.Fatalf("冲突指纹命中跳过次数=%d, want 1（已知冲突态未持久化）", got)
	}
	if entries := drainSystemAuditBuffer(); len(entries) != 0 {
		t.Fatalf("已知冲突态不得每次启动重复留痕: %+v", entries)
	}

	// 主表内容变化 → 指纹失配 → 重新核对（仍冲突，再次留痕一次）。
	if _, err := mainDB.Exec(`INSERT INTO audit_log (id, username, action, resource, detail, ip_address, created_at) VALUES (4, 'admin', '新增动作', '对象丁', 'more', '4.4.4.4', '2026-01-04 00:00:00')`); err != nil {
		t.Fatalf("append legacy row: %v", err)
	}
	if err := migrateLegacyAuditLogs(mainDB, auditPath); err != nil {
		t.Fatalf("fingerprint-mismatch run: %v", err)
	}
	if entries := drainSystemAuditBuffer(); len(entries) != 1 || !strings.Contains(entries[0].detail, "冲突") {
		t.Fatalf("主表变化后重新核对留痕=%+v, want 一条", entries)
	}

	// 冲突解除：人工删除主库旧表 → 标记自动清除，后续启动零写。
	if _, err := mainDB.Exec(`DROP TABLE audit_log`); err != nil {
		t.Fatalf("drop legacy table: %v", err)
	}
	if err := migrateLegacyAuditLogs(mainDB, auditPath); err != nil {
		t.Fatalf("resolved run: %v", err)
	}
	var markers int
	if err := auditDB.QueryRow(`SELECT COUNT(*) FROM audit_migration_state WHERE name=?`, auditLegacyConflictMarkerName).Scan(&markers); err != nil {
		t.Fatalf("read migration state: %v", err)
	}
	if markers != 0 {
		t.Fatalf("冲突解除后标记残留=%d, want 0", markers)
	}
}
