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

// 安全事件保留两列的越上界值（DBA 直连改库、旧版本语义写入、畸形备份恢复）
// 在下次启动归默认——写入侧/导入钳制/从端 apply 都以 Max* 为界，启动迁移是
// 带外脏行的最后防线。合法区间（含上界本身与 marker 置位后的 0）不得被改写：
// 下界语义由一次性 marker 承担，运行期显式值不因重启而变。
func TestRunMigrations_clampsSecurityEventRetentionAboveMax(t *testing.T) {
	openMigrationTestDB(t)
	if err := createTables(); err != nil {
		t.Fatalf("create tables: %v", err)
	}
	if _, err := DB.Exec("INSERT INTO global_config (id, caddy_config) VALUES (1, '{}')"); err != nil {
		t.Fatalf("seed global config: %v", err)
	}
	if err := runMigrations(); err != nil {
		t.Fatalf("run migrations: %v", err)
	}

	readRetention := func() (int, int) {
		t.Helper()
		var days, rows int
		if err := DB.QueryRow(`SELECT security_events_retention_days, security_events_row_cap FROM global_config WHERE id=1`).Scan(&days, &rows); err != nil {
			t.Fatalf("read retention: %v", err)
		}
		return days, rows
	}
	setRetention := func(days, rows int) {
		t.Helper()
		if _, err := DB.Exec(`UPDATE global_config SET security_events_retention_days=?, security_events_row_cap=?, security_events_retention_migrated=1 WHERE id=1`, days, rows); err != nil {
			t.Fatalf("set retention: %v", err)
		}
	}

	// When：两列都越上界（marker 已置位，一次性迁移分支不再处理）。
	setRetention(MaxSecurityEventsRetentionDays+1, MaxSecurityEventsRowCap+1)
	if err := runMigrations(); err != nil {
		t.Fatalf("run migrations: %v", err)
	}
	// Then：归默认。
	if days, rows := readRetention(); days != DefaultSecurityEventsRetentionDays || rows != DefaultSecurityEventsRowCap {
		t.Fatalf("retention=%d/%d, want 上界外归默认 %d/%d", days, rows, DefaultSecurityEventsRetentionDays, DefaultSecurityEventsRowCap)
	}

	// 合法值（上界本身 + 更小的显式值）不得被改写。
	setRetention(MaxSecurityEventsRetentionDays, MaxSecurityEventsRowCap)
	if err := runMigrations(); err != nil {
		t.Fatalf("run migrations: %v", err)
	}
	if days, rows := readRetention(); days != MaxSecurityEventsRetentionDays || rows != MaxSecurityEventsRowCap {
		t.Fatalf("retention=%d/%d, want 上界值原样保留", days, rows)
	}
	setRetention(DefaultSecurityEventsRetentionDays, DefaultSecurityEventsRowCap)
	if err := runMigrations(); err != nil {
		t.Fatalf("run migrations: %v", err)
	}
	if days, rows := readRetention(); days != DefaultSecurityEventsRetentionDays || rows != DefaultSecurityEventsRowCap {
		t.Fatalf("retention=%d/%d, want 显式合法值原样保留", days, rows)
	}

	// marker 置位后的 0 属既定保留语义（下界只在一次性迁移里处理）。
	setRetention(0, 0)
	if err := runMigrations(); err != nil {
		t.Fatalf("run migrations: %v", err)
	}
	if days, rows := readRetention(); days != 0 || rows != 0 {
		t.Fatalf("retention=%d/%d, want marker 置位后 0 不被启动迁移改写", days, rows)
	}
}
