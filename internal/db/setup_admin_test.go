package db

import (
	"context"
	"database/sql"
	"path/filepath"
	"testing"
)

func seedSetupAdminFixture(t *testing.T, statements string) *sql.DB {
	t.Helper()
	database := openMigrationTestDB(t)
	if err := createTables(); err != nil {
		t.Fatalf("create tables: %v", err)
	}
	if statements != "" {
		if _, err := database.Exec(statements); err != nil {
			t.Fatalf("seed users: %v", err)
		}
	}
	return database
}

func setupAdminFlags(t *testing.T, database *sql.DB) map[int]int {
	t.Helper()
	rows, err := database.Query(`SELECT id, COALESCE(is_setup_admin,0) FROM users ORDER BY id`)
	if err != nil {
		t.Fatalf("read flags: %v", err)
	}
	defer rows.Close()
	flags := map[int]int{}
	for rows.Next() {
		var id, flag int
		if err := rows.Scan(&id, &flag); err != nil {
			t.Fatalf("scan flag: %v", err)
		}
		flags[id] = flag
	}
	if err := rows.Err(); err != nil {
		t.Fatalf("iterate flags: %v", err)
	}
	return flags
}

func TestEnsureSetupAdminFlag_marksLowestEnabledAdmin(t *testing.T) {
	database := seedSetupAdminFixture(t, `INSERT INTO users (id,username,password_hash,role,is_enabled) VALUES
		(1,'plain-user','h','user',1),
		(3,'admin-disabled','h','admin',0),
		(7,'admin-enabled','h','admin',1),
		(9,'admin-later','h','admin',1)`)

	if err := EnsureSetupAdminFlag(context.Background(), database); err != nil {
		t.Fatalf("ensure flag: %v", err)
	}
	flags := setupAdminFlags(t, database)
	if flags[7] != 1 {
		t.Fatalf("flags=%v, want 最低 id 的启用管理员(7) 被标记", flags)
	}
	for _, id := range []int{1, 3, 9} {
		if flags[id] != 0 {
			t.Fatalf("flags=%v, want id=%d 未标记", flags, id)
		}
	}
	if ok, err := IsSetupAdmin(context.Background(), database, 7); err != nil || !ok {
		t.Fatalf("IsSetupAdmin(7)=(%v,%v), want true", ok, err)
	}
	if ok, err := IsSetupAdmin(context.Background(), database, 9); err != nil || ok {
		t.Fatalf("IsSetupAdmin(9)=(%v,%v), want false", ok, err)
	}

	// 幂等：稳态再跑一次不改标记行。
	if err := EnsureSetupAdminFlag(context.Background(), database); err != nil {
		t.Fatalf("ensure flag (idempotent): %v", err)
	}
	if flags := setupAdminFlags(t, database); flags[7] != 1 {
		t.Fatalf("flags=%v, want 标记保持 7", flags)
	}
}

func TestEnsureSetupAdminFlag_movesStaleMarker(t *testing.T) {
	// 标记落在被禁用的管理员行（带外改库/手工编辑备份的坏形）：必须先清除，
	// 再落到当前最低 id 的启用管理员，避免保护落到不可登录的账号。
	database := seedSetupAdminFixture(t, `INSERT INTO users (id,username,password_hash,role,is_enabled,is_setup_admin) VALUES
		(2,'stale-disabled-admin','h','admin',0,1),
		(4,'enabled-admin','h','admin',1,0)`)

	if err := EnsureSetupAdminFlag(context.Background(), database); err != nil {
		t.Fatalf("ensure flag: %v", err)
	}
	flags := setupAdminFlags(t, database)
	if flags[2] != 0 || flags[4] != 1 {
		t.Fatalf("flags=%v, want 陈旧标记清除并落到 4", flags)
	}
}

func TestEnsureSetupAdminFlag_noEnabledAdminIsNoop(t *testing.T) {
	database := seedSetupAdminFixture(t, `INSERT INTO users (id,username,password_hash,role,is_enabled) VALUES
		(1,'only-user','h','user',1),
		(2,'disabled-admin','h','admin',0)`)

	if err := EnsureSetupAdminFlag(context.Background(), database); err != nil {
		t.Fatalf("ensure flag: %v", err)
	}
	for id, flag := range setupAdminFlags(t, database) {
		if flag != 0 {
			t.Fatalf("id=%d flag=%d, want 无启用管理员时零标记", id, flag)
		}
	}
}

func TestIsSetupAdmin_fallsBackWhenNoMarker(t *testing.T) {
	database := seedSetupAdminFixture(t, `INSERT INTO users (id,username,password_hash,role,is_enabled) VALUES
		(1,'first-admin','h','admin',1),
		(2,'second-admin','h','admin',1)`)

	// 标记缺失（升级窗口/直连旧库）：回落 setup 首个用户 id。
	if ok, err := IsSetupAdmin(context.Background(), database, SetupAdminFallbackUserID); err != nil || !ok {
		t.Fatalf("IsSetupAdmin(fallback)=(%v,%v), want true", ok, err)
	}
	if ok, err := IsSetupAdmin(context.Background(), database, 2); err != nil || ok {
		t.Fatalf("IsSetupAdmin(2)=(%v,%v), want false", ok, err)
	}
	// 不存在的用户：未标记且无标记行 → 仍按 id 缺省判定（不得误保护）。
	if ok, err := IsSetupAdmin(context.Background(), database, 99); err != nil || ok {
		t.Fatalf("IsSetupAdmin(99)=(%v,%v), want false", ok, err)
	}
}

func TestInitialize_backfillsSetupAdminFlagOnLegacyDatabase(t *testing.T) {
	oldDB, oldMetricsDB, oldAuditDB := DB, MetricsDB, AuditDB
	t.Cleanup(func() {
		_ = Close()
		DB, MetricsDB, AuditDB = oldDB, oldMetricsDB, oldAuditDB
	})

	// Given 旧库：users 无 is_setup_admin 列，已有启用管理员。
	dir := t.TempDir()
	legacy, err := sql.Open("sqlite", filepath.Join(dir, "lazy-balancer.db"))
	if err != nil {
		t.Fatalf("open legacy database: %v", err)
	}
	if _, err := legacy.Exec(`CREATE TABLE users (
		id INTEGER PRIMARY KEY AUTOINCREMENT,
		username VARCHAR(50) UNIQUE NOT NULL,
		password_hash VARCHAR(255) NOT NULL,
		role VARCHAR(20) NOT NULL DEFAULT 'user',
		display_name VARCHAR(100),
		is_enabled BOOLEAN NOT NULL DEFAULT 1,
		created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
		last_login DATETIME
	)`); err != nil {
		t.Fatalf("create legacy users: %v", err)
	}
	if _, err := legacy.Exec(`INSERT INTO users (id,username,password_hash,role,is_enabled) VALUES
		(1,'legacy-user','h','user',1), (5,'legacy-admin','h','admin',1)`); err != nil {
		t.Fatalf("seed legacy users: %v", err)
	}
	if err := legacy.Close(); err != nil {
		t.Fatalf("close legacy database: %v", err)
	}

	// When 真实升级路径（补列 + 回填 + 启动归一）。
	if err := Initialize(dir); err != nil {
		t.Fatalf("initialize legacy database: %v", err)
	}

	// Then 最低 id 的启用管理员成为受保护入口。
	flags := setupAdminFlags(t, DB)
	if flags[5] != 1 || flags[1] != 0 {
		t.Fatalf("flags=%v, want id=5 标记且 id=1 未标记", flags)
	}
}
