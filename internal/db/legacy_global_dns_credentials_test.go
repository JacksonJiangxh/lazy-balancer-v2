package db

import (
	"database/sql"
	"testing"
)

func seedGlobalConfigTable(t *testing.T, database *sql.DB) {
	t.Helper()
	if _, err := database.Exec(`CREATE TABLE global_config (id INTEGER PRIMARY KEY, dns_credentials TEXT)`); err != nil {
		t.Fatalf("create global_config: %v", err)
	}
}

// 启动迁移清空遗留 global_config.dns_credentials（读/写路径均已收口的
// 存量残余面），且对已收敛库零写、可重复执行。
func TestMigrateLegacyGlobalDNSCredentials_clearsStoredValue(t *testing.T) {
	database := openMigrationTestDB(t)
	seedGlobalConfigTable(t, database)
	if _, err := database.Exec(`INSERT INTO global_config (id, dns_credentials) VALUES (1, 'legacy-id,legacy-token')`); err != nil {
		t.Fatalf("seed legacy credentials: %v", err)
	}

	if err := migrateLegacyGlobalDNSCredentials(); err != nil {
		t.Fatalf("migrate legacy global credentials: %v", err)
	}

	var stored sql.NullString
	if err := database.QueryRow(`SELECT dns_credentials FROM global_config WHERE id=1`).Scan(&stored); err != nil {
		t.Fatal(err)
	}
	if stored.Valid && stored.String != "" {
		t.Fatalf("dns_credentials=%q, want NULL/空（遗留值必须清除）", stored.String)
	}

	// 二次执行幂等：不报错、不改变终态。
	if err := migrateLegacyGlobalDNSCredentials(); err != nil {
		t.Fatalf("second run: %v", err)
	}
	if err := database.QueryRow(`SELECT dns_credentials FROM global_config WHERE id=1`).Scan(&stored); err != nil {
		t.Fatal(err)
	}
	if stored.Valid && stored.String != "" {
		t.Fatalf("dns_credentials=%q after second run, want NULL/空", stored.String)
	}
}
