package db

// 历史修复1：nodes 整表重建前的去重不得只保 MIN(id)。
// 重复 (ip_address, port) 行里低 id 可能是旧的未批准行，被删的高 id 才是
// 已批准/持 cluster_token_hash 的当前节点——按 MIN(id) 删会让该节点从注册表
// 消失（令牌与 last_seen 一并丢失，需重新注册/审批）。

import (
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
	if err := dedupeNodesTx(tx); err != nil {
		_ = tx.Rollback()
		t.Fatalf("dedupeNodesTx: %v", err)
	}
	if err := tx.Commit(); err != nil {
		t.Fatalf("commit: %v", err)
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
	if err := dedupeNodesTx(tx2); err != nil {
		_ = tx2.Rollback()
		t.Fatalf("dedupeNodesTx(2): %v", err)
	}
	if err := tx2.Commit(); err != nil {
		t.Fatalf("commit2: %v", err)
	}
	if err := DB.QueryRow("SELECT COUNT(*) FROM nodes").Scan(&total); err != nil {
		t.Fatalf("count all: %v", err)
	}
	if total != 2 {
		t.Fatalf("total nodes=%d, want 2（不同身份行必须保留）", total)
	}
}
