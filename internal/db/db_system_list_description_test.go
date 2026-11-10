package db

// EnsureSystemIPList 对已存在的 system=1 行必须把
// description 归一到当前种子文案——此前只在缺失时 INSERT，任何文案修订都要
// 再写一次性 UPDATE 补丁（2026-10-15「删除条目即解封」即复发路径），存量库与
// 新库文案长期分叉。

import "testing"

func TestEnsureSystemIPList_normalizesExistingDescription(t *testing.T) {
	database := openMigrationTestDB(t)
	if err := createTables(); err != nil {
		t.Fatalf("create tables: %v", err)
	}

	created, err := EnsureSystemIPList(database, "自动封禁名单", "文案A（当前）", "自动封禁")
	if err != nil {
		t.Fatalf("seed system list: %v", err)
	}
	if !created {
		t.Fatal("首播必须报告新建")
	}
	// 用户自建同名列表（system=0）：描述不得被系统种子改写。
	if _, err := database.Exec(`INSERT INTO security_ip_lists (name,description,category,entries,system,created_at,updated_at)
		VALUES ('自动封禁名单','用户自建描述','自定义','[]',0,datetime('now'),datetime('now'))`); err != nil {
		t.Fatalf("seed user list with same name: %v", err)
	}
	// 存量行旧文案漂移（旧备份/旧版本种子）。
	if _, err := database.Exec(`UPDATE security_ip_lists SET description='文案A（旧）' WHERE name='自动封禁名单' AND system=1`); err != nil {
		t.Fatalf("drift system description: %v", err)
	}

	// When 重播种子
	created, err = EnsureSystemIPList(database, "自动封禁名单", "文案A（当前）", "自动封禁")
	if err != nil {
		t.Fatalf("replay system list: %v", err)
	}

	// Then 已存在行不报新建，且描述归一；用户同名行保持原样。
	if created {
		t.Fatal("已存在的 system=1 行不得报告新建")
	}
	var systemDesc, userDesc string
	if err := database.QueryRow(`SELECT description FROM security_ip_lists WHERE name='自动封禁名单' AND system=1`).Scan(&systemDesc); err != nil {
		t.Fatalf("read system description: %v", err)
	}
	if err := database.QueryRow(`SELECT description FROM security_ip_lists WHERE name='自动封禁名单' AND COALESCE(system,0)=0`).Scan(&userDesc); err != nil {
		t.Fatalf("read user description: %v", err)
	}
	if systemDesc != "文案A（当前）" {
		t.Fatalf("system description=%q, want normalized", systemDesc)
	}
	if userDesc != "用户自建描述" {
		t.Fatalf("user description=%q, want untouched", userDesc)
	}
}

func TestSeedSystemIPLists_normalizesAutobanPresetDescription(t *testing.T) {
	database := openMigrationTestDB(t)
	if err := createTables(); err != nil {
		t.Fatalf("create tables: %v", err)
	}
	if err := SeedSystemIPLists(database); err != nil {
		t.Fatalf("seed system lists: %v", err)
	}
	// 「删除条目即解封」裁定前的旧种子文案（原一次性 UPDATE 补丁已退役）。
	if _, err := database.Exec(`UPDATE security_ip_lists SET description='自动封禁命中 IP（自动封禁任务维护；可手动追加或解封）'
		WHERE name='自动封禁名单' AND system=1`); err != nil {
		t.Fatalf("drift autoban description: %v", err)
	}

	if err := SeedSystemIPLists(database); err != nil {
		t.Fatalf("replay system lists: %v", err)
	}

	var description string
	if err := database.QueryRow(`SELECT description FROM security_ip_lists WHERE name='自动封禁名单' AND system=1`).Scan(&description); err != nil {
		t.Fatalf("read autoban description: %v", err)
	}
	want := "自动封禁命中 IP（自动封禁任务维护；可手动追加或删除条目）"
	if description != want {
		t.Fatalf("autoban description=%q, want %q", description, want)
	}
}
