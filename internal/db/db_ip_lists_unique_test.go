package db

import "testing"

// 历史修复：system=1 名单必须有 name 唯一性兜底；同名 system=0 用户列表
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

// 历史修复：EnsureSystemIPList 在唯一索引下重复调用仍幂等（OR IGNORE 路径）。
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
