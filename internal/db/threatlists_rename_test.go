package db

import "testing"

// 内置威胁名单专业化改名迁移（2026-09-24 用户裁定）：存量 system=1 行按旧名
// 更新为新名（保 id——策略 refs 按 id 引用），新库直接以新名种子。
func TestThreatSystemListRename_migratesLegacyNames(t *testing.T) {
	openMigrationTestDB(t)
	if err := createTables(); err != nil {
		t.Fatalf("create tables: %v", err)
	}
	// 模拟存量：旧名三行 + 一条引用旧名单的策略不丢（id 稳定）
	if _, err := DB.Exec(`INSERT INTO security_ip_lists (name, description, category, entries, system, created_at, updated_at) VALUES
		('威胁情报库-中科大黑 IP', '旧', '恶意 IP', '[]', 1, datetime('now'), datetime('now')),
		('威胁情报库-FireHOL level1', '旧', '恶意 IP', '[]', 1, datetime('now'), datetime('now')),
		('威胁情报库-ET Compromised', '旧', '恶意 IP', '[]', 1, datetime('now'), datetime('now'))`); err != nil {
		t.Fatal(err)
	}
	oldID := 0
	if err := DB.QueryRow(`SELECT id FROM security_ip_lists WHERE name='威胁情报库-中科大黑 IP'`).Scan(&oldID); err != nil {
		t.Fatal(err)
	}

	if err := migrateThreatSystemListNames(); err != nil {
		t.Fatalf("migrate: %v", err)
	}

	// 新名存在且 id 不变；旧名清零
	var newID int
	if err := DB.QueryRow(`SELECT id FROM security_ip_lists WHERE name=? AND system=1`, ThreatListNameBySource("ustc")).Scan(&newID); err != nil {
		t.Fatalf("新名行不存在: %v", err)
	}
	if newID != oldID {
		t.Fatalf("id 漂移: %d→%d", oldID, newID)
	}
	var legacy int
	if err := DB.QueryRow(`SELECT COUNT(*) FROM security_ip_lists WHERE name LIKE '威胁情报库-%'`).Scan(&legacy); err != nil {
		t.Fatal(err)
	}
	if legacy != 0 {
		t.Fatalf("旧名残留 %d 行", legacy)
	}
	// 幂等：二次执行无变化
	if err := migrateThreatSystemListNames(); err != nil {
		t.Fatalf("二次执行: %v", err)
	}
}

func TestThreatSystemListRename_renamesUserConflictAndTakesCanonicalName(t *testing.T) {
	// Given 旧名 system=1 行 + 用户手工占用的同名（新名）system=0 行。
	// 冲突用户行必须改名为「规范名（用户 <id>）」（保 id/数据），随后
	// system 行接管规范名，避免同名双行与内置名单永久失更。
	openMigrationTestDB(t)
	if err := createTables(); err != nil {
		t.Fatalf("create tables: %v", err)
	}
	newName := ThreatListNameBySource("ustc")
	if _, err := DB.Exec(`INSERT INTO security_ip_lists (name, description, category, entries, system, created_at, updated_at) VALUES
		('威胁情报库-中科大黑 IP', '旧', '恶意 IP', '[]', 1, datetime('now'), datetime('now')),
		(?, '用户自建同名名单', '恶意 IP', '[]', 0, datetime('now'), datetime('now'))`, newName); err != nil {
		t.Fatal(err)
	}

	// When
	if err := migrateThreatSystemListNames(); err != nil {
		t.Fatalf("migrate: %v（冲突用户行改名与规范名接管不得阻断启动）", err)
	}

	// Then 旧 system 行接管规范名；占用新名的用户行被改名（保 id/数据），
	// 不产生同名双行。
	var canonicalSystem int
	if err := DB.QueryRow(`SELECT COUNT(*) FROM security_ip_lists WHERE system=1 AND name=?`, newName).Scan(&canonicalSystem); err != nil {
		t.Fatal(err)
	}
	if canonicalSystem != 1 {
		t.Fatalf("规范名 system=1 行=%d, want 1", canonicalSystem)
	}
	var legacyCount int
	if err := DB.QueryRow(`SELECT COUNT(*) FROM security_ip_lists WHERE system=1 AND name='威胁情报库-中科大黑 IP'`).Scan(&legacyCount); err != nil {
		t.Fatal(err)
	}
	if legacyCount != 0 {
		t.Fatalf("旧名 system=1 行=%d, want 0", legacyCount)
	}
	var userRows int
	if err := DB.QueryRow(`SELECT COUNT(*) FROM security_ip_lists WHERE system=0 AND name LIKE ?`, newName+"（用户 %").Scan(&userRows); err != nil {
		t.Fatal(err)
	}
	if userRows != 1 {
		t.Fatalf("冲突用户行改名=%d, want 1", userRows)
	}
	// And 幂等：二次执行不报错且不再改名
	if err := migrateThreatSystemListNames(); err != nil {
		t.Fatalf("二次执行: %v", err)
	}
}

func TestThreatSystemListRename_returnsConflictScanError(t *testing.T) {
	// Given 真实 SQLite 中的畸形存量 schema：id 携带不可转 int64 的文本。
	openMigrationTestDB(t)
	if _, err := DB.Exec(`CREATE TABLE security_ip_lists (
		id TEXT PRIMARY KEY,
		name TEXT,
		description TEXT,
		system INTEGER,
		updated_at TEXT
	)`); err != nil {
		t.Fatalf("create malformed legacy list table: %v", err)
	}
	newName := ThreatListNameBySource("ustc")
	if _, err := DB.Exec(`INSERT INTO security_ip_lists (id,name,description,system,updated_at) VALUES
		('system-row','威胁情报库-中科大黑 IP','旧',1,datetime('now')),
		('broken-user-id',?,'用户自建同名名单',0,datetime('now'))`, newName); err != nil {
		t.Fatalf("seed malformed conflict row: %v", err)
	}

	// When
	err := migrateThreatSystemListNames()

	// Then Scan 错误必须上抛，且不得让 system 行在冲突未处理时接管规范名。
	if err == nil {
		t.Fatal("conflict row Scan error was swallowed")
	}
	var legacySystem, canonicalUser int
	if err := DB.QueryRow(`SELECT COUNT(*) FROM security_ip_lists WHERE id='system-row' AND name='威胁情报库-中科大黑 IP'`).Scan(&legacySystem); err != nil {
		t.Fatal(err)
	}
	if err := DB.QueryRow(`SELECT COUNT(*) FROM security_ip_lists WHERE id='broken-user-id' AND name=?`, newName).Scan(&canonicalUser); err != nil {
		t.Fatal(err)
	}
	if legacySystem != 1 || canonicalUser != 1 {
		t.Fatalf("rows changed despite Scan failure: legacySystem=%d canonicalUser=%d", legacySystem, canonicalUser)
	}
}

// 新名口径：去「威胁情报库-」前缀，专业化命名
func TestThreatSystemLists_professionalNames(t *testing.T) {
	names := map[string]string{}
	for _, sl := range ThreatSystemLists {
		names[sl.Source] = sl.Name
	}
	want := map[string]string{
		"ustc":           "中科大恶意 IP 名单（USTC）",
		"firehol_l1":     "FireHOL Level 1 综合黑名单",
		"et_compromised": "Emerging Threats 失陷主机名单",
	}
	for src, w := range want {
		if names[src] != w {
			t.Fatalf("%s 名单名=%q, want %q", src, names[src], w)
		}
	}
}
