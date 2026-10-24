package db

// nodes 整表重建前的去重不得只保 MIN(id)。
// 重复 (ip_address, port) 行里低 id 可能是旧的未批准行，被删的高 id 才是
// 已批准/持 cluster_token_hash 的当前节点——按 MIN(id) 删会让该节点从注册表
// 消失（令牌与 last_seen 一并丢失，需重新注册/审批）。

import (
	"strings"
	"testing"
)

// legacyNodesDedupeFixture 建出「唯一约束之前」的 nodes 形态（重跑同一 DDL
// 会插入重复行），用于验证去重保留策略。
func legacyNodesDedupeFixture(t *testing.T) {
	t.Helper()
	if _, err := DB.Exec(`CREATE TABLE nodes (
		id INTEGER PRIMARY KEY AUTOINCREMENT,
		name VARCHAR(100) NOT NULL,
		ip_address VARCHAR(45) NOT NULL,
		port INTEGER DEFAULT 8000,
		is_approved BOOLEAN DEFAULT FALSE,
		cluster_token_hash VARCHAR(64),
		registration_secret VARCHAR(64),
		last_seen DATETIME
	)`); err != nil {
		t.Fatalf("create legacy nodes fixture: %v", err)
	}
}

func TestDedupeNodesTx_keepsApprovedTokenHolderOverOlderRow(t *testing.T) {
	openMigrationTestDB(t)
	legacyNodesDedupeFixture(t)

	// 三行同身份：id=1 旧未批准、id=2 已批准且持令牌（最近上报）、id=3 更旧。
	if _, err := DB.Exec(`INSERT INTO nodes (id, name, ip_address, port, is_approved, cluster_token_hash, last_seen) VALUES
		(1, 'stale', '10.1.0.5', 8000, 0, NULL, '2026-01-01 00:00:00'),
		(2, 'current', '10.1.0.5', 8000, 1, 'tokenhash', '2026-10-19 12:00:00'),
		(3, 'older', '10.1.0.5', 8000, 0, NULL, '2025-12-31 00:00:00')`); err != nil {
		t.Fatalf("seed nodes: %v", err)
	}

	// When
	tx, err := DB.Begin()
	if err != nil {
		t.Fatalf("begin: %v", err)
	}
	removed, err := dedupeNodesTx(tx)
	if err != nil {
		_ = tx.Rollback()
		t.Fatalf("dedupeNodesTx: %v", err)
	}
	if err := tx.Commit(); err != nil {
		t.Fatalf("commit: %v", err)
	}
	if removed != 2 {
		t.Fatalf("removed=%d, want 2（三行同身份保留一行）", removed)
	}

	// Then 保留已批准且持令牌的行（旧实现只保 MIN(id)=1，令牌行被删）
	var kept int
	var name string
	var approved int
	var token string
	if err := DB.QueryRow(`SELECT id, name, IIF(is_approved IN ('1',1),1,0), COALESCE(cluster_token_hash,'')
		FROM nodes WHERE ip_address='10.1.0.5' AND port=8000`).Scan(&kept, &name, &approved, &token); err != nil {
		t.Fatalf("read kept row: %v", err)
	}
	if kept != 2 || name != "current" || approved != 1 || token != "tokenhash" {
		t.Fatalf("kept=(id=%d,name=%s,approved=%d,token=%s), want id=2/current/approved/tokenhash", kept, name, approved, token)
	}
	var total int
	if err := DB.QueryRow(`SELECT COUNT(*) FROM nodes WHERE ip_address='10.1.0.5' AND port=8000`).Scan(&total); err != nil {
		t.Fatalf("count rows: %v", err)
	}
	if total != 1 {
		t.Fatalf("rows=%d, want 1", total)
	}

	// 回归形状：不同身份的节点不受去重影响。
	if _, err := DB.Exec(`INSERT INTO nodes (name, ip_address, port, is_approved, last_seen) VALUES
		('other', '10.1.0.6', 8000, 1, '2026-10-19 12:00:00')`); err != nil {
		t.Fatalf("seed distinct node: %v", err)
	}
	tx2, err := DB.Begin()
	if err != nil {
		t.Fatalf("begin2: %v", err)
	}
	removed, err = dedupeNodesTx(tx2)
	if err != nil {
		_ = tx2.Rollback()
		t.Fatalf("dedupeNodesTx(2): %v", err)
	}
	if err := tx2.Commit(); err != nil {
		t.Fatalf("commit2: %v", err)
	}
	if removed != 0 {
		t.Fatalf("second removed=%d, want 0（已收敛库零命中）", removed)
	}
	if err := DB.QueryRow("SELECT COUNT(*) FROM nodes").Scan(&total); err != nil {
		t.Fatalf("count all: %v", err)
	}
	if total != 2 {
		t.Fatalf("total nodes=%d, want 2（不同身份行必须保留）", total)
	}
}

// legacyNodesDedupeRebuildFixture 建出「唯一约束之前」的完整 nodes 形态：
// 直接复用生产重建 DDL 单源（移除 UNIQUE(ip_address, port) 行以允许重复行），
// 再补回触发 migrateNodesDeadColumns 的 legacy sync 两列。
func legacyNodesDedupeRebuildFixture(t *testing.T) {
	t.Helper()
	const uniqueClause = ",\n\t\tUNIQUE(ip_address, port)"
	ddl := nodesRebuildDDL("nodes")
	ddl = strings.Replace(ddl, uniqueClause, "", 1)
	if strings.Contains(ddl, "UNIQUE(ip_address, port)") {
		t.Fatalf("nodesRebuildDDL 形态变化：去重夹具无法移除唯一约束")
	}
	if _, err := DB.Exec(ddl); err != nil {
		t.Fatalf("create legacy nodes fixture: %v", err)
	}
	if _, err := DB.Exec(`ALTER TABLE nodes ADD COLUMN sync_enabled BOOLEAN DEFAULT 0;
		ALTER TABLE nodes ADD COLUMN sync_scope VARCHAR(20) DEFAULT 'all'`); err != nil {
		t.Fatalf("add legacy sync columns: %v", err)
	}
	if _, err := DB.Exec(`INSERT INTO nodes (id, name, ip_address, port, is_approved, cluster_token_hash, last_seen) VALUES
		(1, 'stale', '10.1.0.7', 8000, 0, NULL, '2026-01-01 00:00:00'),
		(2, 'current', '10.1.0.7', 8000, 1, 'tokenhash', '2026-10-19 12:00:00'),
		(3, 'older', '10.1.0.7', 8000, 0, NULL, '2025-12-31 00:00:00')`); err != nil {
		t.Fatalf("seed duplicate nodes: %v", err)
	}
}

// 去重删行是用户可见的注册表改写（可能连同令牌/注册密钥消失）：
// 重建提交成功后必须落一条「启动迁移·集群节点」审计，回滚则不得留痕。
func TestMigrateNodesDeadColumns_recordsDedupeAuditAfterCommit(t *testing.T) {
	openMigrationTestDB(t)
	legacyNodesDedupeRebuildFixture(t)
	drainSystemAuditBuffer()

	// 回滚形状：去重被中断时不得留下「已删行」审计。
	if _, err := DB.Exec(`CREATE TRIGGER fail_nodes_dedupe BEFORE DELETE ON nodes
		BEGIN SELECT RAISE(ABORT, 'boom'); END`); err != nil {
		t.Fatalf("create failing trigger: %v", err)
	}
	if err := migrateNodesDeadColumns(); err == nil {
		t.Fatal("去重被 trigger 中断时迁移必须报错")
	}
	if entries := drainSystemAuditBuffer(); len(entries) != 0 {
		t.Fatalf("回滚迁移审计=%+v, want 空（提交成功才留痕）", entries)
	}
	if _, err := DB.Exec(`DROP TRIGGER fail_nodes_dedupe`); err != nil {
		t.Fatalf("drop failing trigger: %v", err)
	}

	// When 重试成功
	if err := migrateNodesDeadColumns(); err != nil {
		t.Fatalf("migrate legacy nodes columns: %v", err)
	}

	// Then 恰一条审计，点名删除条数与保留策略
	entries := drainSystemAuditBuffer()
	if len(entries) != 1 {
		t.Fatalf("审计=%+v, want 恰一条去重留痕", entries)
	}
	if entries[0].action != "启动迁移" || entries[0].resource != "集群节点" {
		t.Fatalf("审计 action/resource=%q/%q, want 启动迁移/集群节点", entries[0].action, entries[0].resource)
	}
	if !strings.Contains(entries[0].detail, "删除 2 条") || !strings.Contains(entries[0].detail, "ip_address, port") {
		t.Fatalf("审计 detail=%q, want 含「删除 2 条」与去重键", entries[0].detail)
	}
	var kept int
	if err := DB.QueryRow(`SELECT id FROM nodes WHERE ip_address='10.1.0.7' AND port=8000`).Scan(&kept); err != nil {
		t.Fatalf("read kept node: %v", err)
	}
	if kept != 2 {
		t.Fatalf("kept id=%d, want 2（已批准持令牌行）", kept)
	}

	// 回归形状：收敛库重跑（无 legacy 列）零审计。
	if err := migrateNodesDeadColumns(); err != nil {
		t.Fatalf("re-run migrate: %v", err)
	}
	if entries := drainSystemAuditBuffer(); len(entries) != 0 {
		t.Fatalf("收敛库重跑审计=%+v, want 空", entries)
	}
}
