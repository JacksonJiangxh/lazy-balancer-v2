package db

import (
	"database/sql"
	"path/filepath"
	"strings"
	"testing"
)

const legacyAuditTableDDL = `CREATE TABLE audit_log (
	id INTEGER PRIMARY KEY AUTOINCREMENT,
	username VARCHAR(100),
	action VARCHAR(50) NOT NULL,
	resource VARCHAR(100),
	detail TEXT,
	ip_address VARCHAR(45),
	created_at DATETIME DEFAULT CURRENT_TIMESTAMP
)`

// 旧审计表迁移冲突（主库 audit_log 与审计库同 id 不同内容，人工恢复旧主库
// 副本可达）：必须保留旧表 + 告警留痕 + 跳过迁移——硬失败会让进程无法启动
// 且无不改库的恢复路径（服务可用优先）。
func TestMigrateLegacyAuditLogs_conflictKeepsSourceTableAndSkips(t *testing.T) {
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
	if _, err := auditDB.Exec(legacyAuditTableDDL); err != nil {
		t.Fatalf("create audit table: %v", err)
	}
	// 同 id=1 内容不同（冲突）；审计库另有 id=3。
	if _, err := auditDB.Exec(`INSERT INTO audit_log (id, username, action, resource, detail, ip_address, created_at) VALUES
		(1, 'admin', '新动作', '对象甲', 'new', '1.1.1.1', '2026-01-01 00:00:00'),
		(3, 'admin', '审计库动作', '对象丙', 'dst', '3.3.3.3', '2026-01-03 00:00:00')`); err != nil {
		t.Fatalf("seed audit rows: %v", err)
	}
	if err := auditDB.Close(); err != nil {
		t.Fatalf("close audit database: %v", err)
	}

	drainSystemAuditBuffer()
	if err := migrateLegacyAuditLogs(mainDB, auditPath); err != nil {
		t.Fatalf("conflict must not fail startup: %v", err)
	}

	// 主库旧表保留（未 DROP）。
	var tableCount int
	if err := mainDB.QueryRow(`SELECT COUNT(*) FROM sqlite_master WHERE type='table' AND name='audit_log'`).Scan(&tableCount); err != nil {
		t.Fatal(err)
	}
	if tableCount != 1 {
		t.Fatalf("legacy audit table count=%d, want 1（冲突时旧表必须保留）", tableCount)
	}
	// 审计库冲突行未被覆盖；无冲突行已并入。
	verify, err := sql.Open("sqlite", auditPath)
	if err != nil {
		t.Fatalf("reopen audit database: %v", err)
	}
	defer func() { _ = verify.Close() }()
	var action string
	if err := verify.QueryRow(`SELECT action FROM audit_log WHERE id=1`).Scan(&action); err != nil {
		t.Fatal(err)
	}
	if action != "新动作" {
		t.Fatalf("audit row id=1 action=%q, want 新动作（冲突行不得被覆盖）", action)
	}
	var copied int
	if err := verify.QueryRow(`SELECT COUNT(*) FROM audit_log WHERE id=2 AND action='无冲突动作'`).Scan(&copied); err != nil {
		t.Fatal(err)
	}
	if copied != 1 {
		t.Fatalf("non-conflict row id=2 copied=%d, want 1（无冲突行照常并入）", copied)
	}
	// 冲突须留痕：系统审计一条（审计页可见）+ WARN 日志。
	entries := drainSystemAuditBuffer()
	if len(entries) != 1 || !strings.Contains(entries[0].detail, "冲突") {
		t.Fatalf("conflict audit entries=%+v, want 一条冲突留痕", entries)
	}
}

// 无冲突形态：复制+校验通过后旧表删除（既有契约回归钉）。
func TestMigrateLegacyAuditLogs_cleanCopyDropsSourceTable(t *testing.T) {
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
		(1, 'admin', '登录', '会话', 'ok', '1.1.1.1', '2026-01-01 00:00:00')`); err != nil {
		t.Fatalf("seed legacy audit rows: %v", err)
	}
	auditPath := filepath.Join(dir, "audit.db")
	auditDB, err := sql.Open("sqlite", auditPath)
	if err != nil {
		t.Fatalf("open audit database: %v", err)
	}
	if _, err := auditDB.Exec(legacyAuditTableDDL); err != nil {
		t.Fatalf("create audit table: %v", err)
	}
	if err := auditDB.Close(); err != nil {
		t.Fatalf("close audit database: %v", err)
	}

	if err := migrateLegacyAuditLogs(mainDB, auditPath); err != nil {
		t.Fatalf("clean migration: %v", err)
	}
	var tableCount int
	if err := mainDB.QueryRow(`SELECT COUNT(*) FROM sqlite_master WHERE type='table' AND name='audit_log'`).Scan(&tableCount); err != nil {
		t.Fatal(err)
	}
	if tableCount != 0 {
		t.Fatalf("legacy audit table count=%d, want 0（无冲突时旧表应删除）", tableCount)
	}
	verify, err := sql.Open("sqlite", auditPath)
	if err != nil {
		t.Fatalf("reopen audit database: %v", err)
	}
	defer func() { _ = verify.Close() }()
	var copied int
	if err := verify.QueryRow(`SELECT COUNT(*) FROM audit_log WHERE id=1 AND action='登录'`).Scan(&copied); err != nil {
		t.Fatal(err)
	}
	if copied != 1 {
		t.Fatalf("audit row copied=%d, want 1", copied)
	}
}
