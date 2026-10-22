package db

// CA 提供商播种必须是一次性的（marker 门）——此前
// 「表空即播种」每次启动评估，导入/集群快照清空 ca_providers 后重启会复活
// ZeroSSL/LE 并覆盖 default_ca_provider_id，与「删除即不存在」相悖。

import "testing"

func TestRunMigrations_caProvidersSeedOnlyOnce(t *testing.T) {
	database := openMigrationTestDB(t)
	if err := createTables(); err != nil {
		t.Fatalf("create tables: %v", err)
	}
	if _, err := database.Exec("INSERT INTO global_config (id,caddy_config) VALUES (1,'{}')"); err != nil {
		t.Fatalf("seed global config: %v", err)
	}

	// When 首启（fresh 库）
	if err := runMigrations(); err != nil {
		t.Fatalf("run migrations: %v", err)
	}

	// Then 播种两条内置提供商并落 marker；默认 CA 指向 Let's Encrypt。
	var providers int
	if err := database.QueryRow(`SELECT COUNT(*) FROM ca_providers`).Scan(&providers); err != nil {
		t.Fatalf("count CA providers: %v", err)
	}
	if providers != 2 {
		t.Fatalf("providers=%d, want 2 after fresh seed", providers)
	}
	var seeded int
	if err := database.QueryRow(`SELECT ca_providers_seeded FROM global_config WHERE id=1`).Scan(&seeded); err != nil {
		t.Fatalf("read seed marker: %v", err)
	}
	if seeded != 1 {
		t.Fatalf("ca_providers_seeded=%d, want 1", seeded)
	}
	var defaultProvider int
	if err := database.QueryRow(`SELECT default_ca_provider_id FROM global_config WHERE id=1`).Scan(&defaultProvider); err != nil {
		t.Fatalf("read default CA provider: %v", err)
	}
	if defaultProvider == 0 {
		t.Fatal("fresh seed must set default_ca_provider_id")
	}

	// And 模拟导入/快照清空提供商表（并保留用户的默认 CA 选择）。
	if _, err := database.Exec("DELETE FROM ca_providers"); err != nil {
		t.Fatalf("clear CA providers: %v", err)
	}

	// When 重启
	if err := runMigrations(); err != nil {
		t.Fatalf("rerun migrations: %v", err)
	}

	// Then 表保持空、默认 CA 不被覆盖（删除即不存在）。
	if err := database.QueryRow(`SELECT COUNT(*) FROM ca_providers`).Scan(&providers); err != nil {
		t.Fatalf("count CA providers after restart: %v", err)
	}
	if providers != 0 {
		t.Fatalf("providers=%d after restart, want 0（一次性 marker 之后不得复活）", providers)
	}
	var defaultAfter int
	if err := database.QueryRow(`SELECT default_ca_provider_id FROM global_config WHERE id=1`).Scan(&defaultAfter); err != nil {
		t.Fatalf("read default CA provider after restart: %v", err)
	}
	if defaultAfter != defaultProvider {
		t.Fatalf("default_ca_provider_id=%d after restart, want unchanged %d", defaultAfter, defaultProvider)
	}
}

func TestRunMigrations_caProvidersSeedMarkerAdoptedWithoutDuplicates(t *testing.T) {
	database := openMigrationTestDB(t)
	if err := createTables(); err != nil {
		t.Fatalf("create tables: %v", err)
	}
	if _, err := database.Exec("INSERT INTO global_config (id,caddy_config) VALUES (1,'{}')"); err != nil {
		t.Fatalf("seed global config: %v", err)
	}
	// 存量库形态：提供商已存在、marker 刚由 newColumns 补为 0。
	if _, err := database.Exec(`INSERT INTO ca_providers (name,provider,directory_url,credentials,enabled)
		VALUES ('ZeroSSL','zerossl','https://acme.zerossl.com/v2/DV90','{}',1),
		       ('Let''s Encrypt','letsencrypt','https://acme-v02.api.letsencrypt.org/directory','{}',1)`); err != nil {
		t.Fatalf("seed CA providers: %v", err)
	}

	if err := runMigrations(); err != nil {
		t.Fatalf("run migrations: %v", err)
	}

	var providers, seeded int
	if err := database.QueryRow(`SELECT COUNT(*) FROM ca_providers`).Scan(&providers); err != nil {
		t.Fatalf("count CA providers: %v", err)
	}
	if err := database.QueryRow(`SELECT ca_providers_seeded FROM global_config WHERE id=1`).Scan(&seeded); err != nil {
		t.Fatalf("read seed marker: %v", err)
	}
	if providers != 2 || seeded != 1 {
		t.Fatalf("providers=%d seeded=%d, want 2/1（存量表不重复播种，marker 采纳）", providers, seeded)
	}
}
