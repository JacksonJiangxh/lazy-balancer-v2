package db

import (
	"database/sql"
	"path/filepath"
	"strings"
	"testing"
)

// 威胁情报库名单化（v2.3.2 重构）：security_ip_lists 增 system 列，
// 三个内置只读名单随迁移种子（name 稳定、条目空、由更新任务独占写）。
func TestIPListsSystemColumn_seededThreatLists(t *testing.T) {
	database := openMigrationTestDB(t)
	if err := createTables(); err != nil {
		t.Fatalf("create tables: %v", err)
	}
	if _, err := database.Exec("INSERT INTO global_config (id,caddy_config) VALUES (1,'{}')"); err != nil {
		t.Fatal(err)
	}
	if err := runMigrations(); err != nil {
		t.Fatalf("migrations: %v", err)
	}

	rows, err := database.Query(`SELECT name, category, system, entries FROM security_ip_lists WHERE system=1 ORDER BY id`)
	if err != nil {
		t.Fatalf("query system lists: %v", err)
	}
	defer rows.Close()
	var got []string
	for rows.Next() {
		var name, category, entries string
		var system bool
		if err := rows.Scan(&name, &category, &system, &entries); err != nil {
			t.Fatal(err)
		}
		if !system || entries != "[]" {
			t.Fatalf("system list %q: system=%v entries=%q, want system=1 且空名单", name, system, entries)
		}
		got = append(got, name)
	}
	if len(got) != 4 {
		t.Fatalf("system lists=%d %v, want 4（三威胁源 + 自动封禁名单，历史问题）", len(got), got)
	}

	// 幂等：二次迁移不重复种子
	if err := runMigrations(); err != nil {
		t.Fatalf("re-migrate: %v", err)
	}
	var count int
	if err := database.QueryRow(`SELECT COUNT(*) FROM security_ip_lists WHERE system=1`).Scan(&count); err != nil {
		t.Fatal(err)
	}
	if count != 4 {
		t.Fatalf("count=%d after re-seed, want 4", count)
	}
}

// 存量库迁移：无 system 列的旧表经 newColumns 补列后三行种子落位。
func TestIPListsSystemColumn_legacyMigration(t *testing.T) {
	database := openMigrationTestDB(t)
	if _, err := database.Exec(`CREATE TABLE security_ip_lists (
		id INTEGER PRIMARY KEY AUTOINCREMENT, name TEXT NOT NULL, description TEXT DEFAULT '',
		category TEXT DEFAULT '', entries TEXT DEFAULT '[]',
		created_by INTEGER DEFAULT 0, created_at TEXT DEFAULT '', updated_by INTEGER DEFAULT 0, updated_at TEXT DEFAULT '')`); err != nil {
		t.Fatal(err)
	}
	if err := createTables(); err != nil {
		t.Fatalf("createTables on legacy schema: %v", err)
	}
	if _, err := database.Exec("INSERT INTO global_config (id,caddy_config) VALUES (1,'{}')"); err != nil {
		t.Fatal(err)
	}
	// newColumns 在 runMigrations——模拟生产迁移顺序
	if err := runMigrations(); err != nil {
		t.Fatalf("migrations: %v", err)
	}
	var count int
	if err := database.QueryRow(`SELECT COUNT(*) FROM security_ip_lists WHERE system=1`).Scan(&count); err != nil {
		t.Fatalf("system column missing after migration: %v", err)
	}
	if count != 4 {
		t.Fatalf("migrated system lists=%d, want 4", count)
	}
}

// 内置名单重播的零写契约：收敛库（全部在位且文案已对齐）在只读句柄上必须
// 成功返回——探测门未生效时 INSERT/UPDATE 会直接以 readonly 失败，且收敛库
// 每次启动都要无谓取主库写锁。
func TestSeedSystemIPLists_convergedReplayIssuesNoWrites(t *testing.T) {
	path := filepath.Join(t.TempDir(), "converged.db")
	writeDB, err := sql.Open("sqlite", path+"?_pragma=foreign_keys(1)")
	if err != nil {
		t.Fatalf("open database: %v", err)
	}
	oldDB := DB
	DB = writeDB
	t.Cleanup(func() {
		_ = writeDB.Close()
		DB = oldDB
	})
	if err := createTables(); err != nil {
		t.Fatalf("create tables: %v", err)
	}
	if err := SeedSystemIPLists(writeDB); err != nil {
		t.Fatalf("initial seed: %v", err)
	}

	readOnly, err := sql.Open("sqlite", path+"?_pragma=query_only(1)")
	if err != nil {
		t.Fatalf("open read-only database: %v", err)
	}
	defer readOnly.Close()

	// 收敛库：探测门命中即整段零写。
	if err := SeedSystemIPLists(readOnly); err != nil {
		t.Fatalf("收敛库重播必须零写（探测门未生效）: %v", err)
	}

	// 反形状：描述漂移时同一只读句柄必然报写错误——证明上面的零写断言
	// 确实反映「没有写」，而不是只读设置无效。
	if _, err := writeDB.Exec(`UPDATE security_ip_lists SET description='旧文案' WHERE name='自动封禁名单' AND system=1`); err != nil {
		t.Fatalf("drift description: %v", err)
	}
	err = SeedSystemIPLists(readOnly)
	if err == nil {
		t.Fatal("描述漂移时只读句柄必须报写错误（零写断言无效）")
	}
	if !strings.Contains(err.Error(), "readonly") {
		t.Fatalf("漂移路径应因只读失败，实际 err=%v", err)
	}

	// 正常句柄重播：未收敛即走播种并归一文案。
	if err := SeedSystemIPLists(writeDB); err != nil {
		t.Fatalf("replay on writable handle: %v", err)
	}
	seeds := systemIPListSeeds()
	var autoban systemIPListSeed
	for _, seed := range seeds {
		if seed.Name == "自动封禁名单" {
			autoban = seed
		}
	}
	var description string
	if err := writeDB.QueryRow(`SELECT description FROM security_ip_lists WHERE name='自动封禁名单' AND system=1`).Scan(&description); err != nil {
		t.Fatalf("read description: %v", err)
	}
	if description != autoban.Description {
		t.Fatalf("description=%q, want %q", description, autoban.Description)
	}
}
