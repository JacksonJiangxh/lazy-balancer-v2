package db

import "testing"

// （system=0）不得阻止内置行创建。
func TestRunMigrations_seedsAutobanPresetDespiteSameNameUserList(t *testing.T) {
	openMigrationTestDB(t)
	if err := createTables(); err != nil {
		t.Fatalf("create tables: %v", err)
	}
	if _, err := DB.Exec("INSERT INTO global_config (id, caddy_config) VALUES (1, '{}')"); err != nil {
		t.Fatal(err)
	}
	if _, err := DB.Exec(`INSERT INTO security_ip_lists (name,description,category,entries,system)
		VALUES ('自动封禁名单', 'user-owned', '恶意 IP', '[]', 0)`); err != nil {
		t.Fatal(err)
	}
	if err := runMigrations(); err != nil {
		t.Fatalf("run migrations: %v", err)
	}
	var systemRows, userRows int
	if err := DB.QueryRow(`SELECT COUNT(*) FROM security_ip_lists WHERE name='自动封禁名单' AND COALESCE(system,0)=1`).Scan(&systemRows); err != nil {
		t.Fatal(err)
	}
	if err := DB.QueryRow(`SELECT COUNT(*) FROM security_ip_lists WHERE name='自动封禁名单' AND COALESCE(system,0)=0`).Scan(&userRows); err != nil {
		t.Fatal(err)
	}
	if systemRows != 1 || userRows != 1 {
		t.Fatalf("system rows=%d user rows=%d, want 1/1 (seeded despite name collision)", systemRows, userRows)
	}
}

// 1000000，此后运行期值不得被重启静默改写。
func TestMigrateSecurityEventRetentionDefaults_oneTimeMarker(t *testing.T) {
	openMigrationTestDB(t)
	if err := createTables(); err != nil {
		t.Fatalf("create tables: %v", err)
	}
	if _, err := DB.Exec("INSERT INTO global_config (id, caddy_config) VALUES (1, '{}')"); err != nil {
		t.Fatal(err)
	}
	if err := runMigrations(); err != nil {
		t.Fatalf("run migrations: %v", err)
	}
	if _, err := DB.Exec(`UPDATE global_config SET security_events_retention_days=0, security_events_row_cap=0, security_events_retention_migrated=0 WHERE id=1`); err != nil {
		t.Fatal(err)
	}
	if err := migrateSecurityEventRetentionDefaults(); err != nil {
		t.Fatal(err)
	}
	var days, rows, migrated int
	if err := DB.QueryRow(`SELECT security_events_retention_days, security_events_row_cap, security_events_retention_migrated FROM global_config WHERE id=1`).Scan(&days, &rows, &migrated); err != nil {
		t.Fatal(err)
	}
	if days != 90 || rows != 1000000 || migrated != 1 {
		t.Fatalf("days=%d rows=%d migrated=%d, want 90/1000000/1", days, rows, migrated)
	}
	// marker 已置位：运行期 0（legacy/带外）不得再被每启动改写。
	if _, err := DB.Exec(`UPDATE global_config SET security_events_retention_days=0 WHERE id=1`); err != nil {
		t.Fatal(err)
	}
	if err := migrateSecurityEventRetentionDefaults(); err != nil {
		t.Fatal(err)
	}
	if err := DB.QueryRow(`SELECT security_events_retention_days FROM global_config WHERE id=1`).Scan(&days); err != nil {
		t.Fatal(err)
	}
	if days != 0 {
		t.Fatalf("second run rewrote marker-protected value: days=%d, want 0", days)
	}
}
