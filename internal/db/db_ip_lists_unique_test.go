package db

import "testing"

// system=1 名单必须有 name 唯一性兜底；同名 system=0 用户列表
// 仍允许存在（部分索引只覆盖 system=1）。
func TestMigrateSystemIPListUniqueIndex_dedupesAndEnforces(t *testing.T) {
	database := openMigrationTestDB(t)
	if err := createTables(); err != nil {
		t.Fatalf("create tables: %v", err)
	}
	// 模拟历史 check-then-act 竞态留下的重复 system 行。
	if _, err := database.Exec(`INSERT INTO security_ip_lists (name,description,category,entries,system,created_at,updated_at) VALUES
		('自动封禁名单','旧A','自动封禁','[]',1,datetime('now'),datetime('now')),
		('自动封禁名单','旧B','自动封禁','[]',1,datetime('now'),datetime('now')),
		('自动封禁名单','用户','自定义','[]',0,datetime('now'),datetime('now'))`); err != nil {
		t.Fatalf("seed duplicates: %v", err)
	}
	var keptID int
	if err := database.QueryRow(`SELECT MIN(id) FROM security_ip_lists WHERE name='自动封禁名单' AND system=1`).Scan(&keptID); err != nil {
		t.Fatal(err)
	}
	if err := migrateSystemIPListUniqueIndex(); err != nil {
		t.Fatalf("migrate: %v", err)
	}
	var systemRows, userRows int
	if err := database.QueryRow(`SELECT COUNT(*) FROM security_ip_lists WHERE name='自动封禁名单' AND system=1`).Scan(&systemRows); err != nil {
		t.Fatal(err)
	}
	if err := database.QueryRow(`SELECT COUNT(*) FROM security_ip_lists WHERE name='自动封禁名单' AND system=0`).Scan(&userRows); err != nil {
		t.Fatal(err)
	}
	if systemRows != 1 || userRows != 1 {
		t.Fatalf("system rows=%d user rows=%d, want 1/1", systemRows, userRows)
	}
	var survivingID int
	if err := database.QueryRow(`SELECT id FROM security_ip_lists WHERE name='自动封禁名单' AND system=1`).Scan(&survivingID); err != nil {
		t.Fatal(err)
	}
	if survivingID != keptID {
		t.Fatalf("surviving id=%d, want MIN(id)=%d", survivingID, keptID)
	}
	// 唯一索引生效：重复 system=1 必须被拒。
	if _, err := database.Exec(`INSERT INTO security_ip_lists (name,description,category,entries,system) VALUES ('自动封禁名单','dup','x','[]',1)`); err == nil {
		t.Fatal("duplicate system=1 insert must fail after unique index")
	}
	// 同名 system=0 不受约束。
	if _, err := database.Exec(`INSERT INTO security_ip_lists (name,description,category,entries,system) VALUES ('自动封禁名单','user2','x','[]',0)`); err != nil {
		t.Fatalf("same-name user list must be allowed: %v", err)
	}
}

// EnsureSystemIPList 在唯一索引下重复调用仍幂等（OR IGNORE 路径）。
func TestEnsureSystemIPList_idempotentWithUniqueIndex(t *testing.T) {
	database := openMigrationTestDB(t)
	if err := createTables(); err != nil {
		t.Fatalf("create tables: %v", err)
	}
	if err := migrateSystemIPListUniqueIndex(); err != nil {
		t.Fatalf("migrate: %v", err)
	}
	created, err := EnsureSystemIPList(database, "自动封禁名单", "文案", "自动封禁")
	if err != nil || !created {
		t.Fatalf("first seed created=%v err=%v, want true/nil", created, err)
	}
	created, err = EnsureSystemIPList(database, "自动封禁名单", "文案2", "自动封禁")
	if err != nil || created {
		t.Fatalf("second seed created=%v err=%v, want false/nil", created, err)
	}
	var rows int
	if err := database.QueryRow(`SELECT COUNT(*) FROM security_ip_lists WHERE name='自动封禁名单' AND system=1`).Scan(&rows); err != nil {
		t.Fatal(err)
	}
	if rows != 1 {
		t.Fatalf("rows=%d, want 1", rows)
	}
}

// 启动期索引探测门：唯一部分索引已在位时，重启必须跳过重复查重/重建
// （security_ip_lists 的 GROUP BY 查重是纯启动成本）。存量库索引缺失仍重建。
func TestMigrateSystemIPListUniqueIndex_skipsRebuildWhenIndexInPlace(t *testing.T) {
	database := openMigrationTestDB(t)
	if err := createTables(); err != nil {
		t.Fatalf("create tables: %v", err)
	}

	dedupesBefore, skipsBefore := systemIPListUniqueIndexDedupes.Load(), systemIPListUniqueIndexSkips.Load()

	// Given 首次启动：索引缺失 → 查重 + 建索引。
	if err := migrateSystemIPListUniqueIndex(); err != nil {
		t.Fatalf("first migrate: %v", err)
	}
	if got := systemIPListUniqueIndexDedupes.Load() - dedupesBefore; got != 1 {
		t.Fatalf("首次启动查重次数=%d, want 1", got)
	}
	if got := systemIPListUniqueIndexSkips.Load() - skipsBefore; got != 0 {
		t.Fatalf("首次启动跳过次数=%d, want 0", got)
	}

	// When 二次启动（索引已在位）。
	if err := migrateSystemIPListUniqueIndex(); err != nil {
		t.Fatalf("second migrate: %v", err)
	}
	// Then 零查重、零重建。
	if got := systemIPListUniqueIndexDedupes.Load() - dedupesBefore; got != 1 {
		t.Fatalf("二次启动累计查重=%d, want 1（重启不得重复查重）", got)
	}
	if got := systemIPListUniqueIndexSkips.Load() - skipsBefore; got != 1 {
		t.Fatalf("二次启动跳过次数=%d, want 1", got)
	}

	// And 索引被删（存量库形态）仍重新查重并补建——探测门不吞真实迁移。
	if _, err := database.Exec(`DROP INDEX u_security_ip_lists_system_name`); err != nil {
		t.Fatal(err)
	}
	if err := migrateSystemIPListUniqueIndex(); err != nil {
		t.Fatalf("reinit after index drop: %v", err)
	}
	if got := systemIPListUniqueIndexDedupes.Load() - dedupesBefore; got != 2 {
		t.Fatalf("索引缺失后累计查重=%d, want 2", got)
	}
	var indexCount int
	if err := database.QueryRow(`SELECT COUNT(*) FROM sqlite_master WHERE type='index' AND name='u_security_ip_lists_system_name'`).Scan(&indexCount); err != nil {
		t.Fatal(err)
	}
	if indexCount != 1 {
		t.Fatalf("索引重建后条数=%d, want 1", indexCount)
	}
}
