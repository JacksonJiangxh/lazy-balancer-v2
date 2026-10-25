package db

import "testing"

// CA 提供商播种的四条语句（INSERT → SELECT id → UPDATE default → marker）
// 必须同事务：中途失败/进程被杀后，下次启动因 caCount>0 跳过播种、只置
// marker，default_ca_provider_id 永久停在 0——GetDefaultCAProvider 把 0 归为
// 「首个启用提供商」，默认签发商会从播种意图的 Let's Encrypt 静默漂移成
// ZeroSSL（限额/端点策略不同），且无错误、无审计、marker 阻断自愈。
func TestRunMigrations_caProviderSeedIsAtomic(t *testing.T) {
	database := openMigrationTestDB(t)
	if err := createTables(); err != nil {
		t.Fatalf("create tables: %v", err)
	}
	if _, err := database.Exec("INSERT INTO global_config (id,caddy_config) VALUES (1,'{}')"); err != nil {
		t.Fatalf("seed global config: %v", err)
	}
	// 让「设置默认 CA」这一步失败：此前 INSERT 已自动提交，失败后表里留下
	// 两条提供商且 marker=0，下一次启动不再重播默认值。
	if _, err := database.Exec(`CREATE TRIGGER fail_default_ca BEFORE UPDATE OF default_ca_provider_id ON global_config
		BEGIN SELECT RAISE(ABORT, '注入的默认 CA 写失败'); END;`); err != nil {
		t.Fatalf("create failure trigger: %v", err)
	}

	if err := runMigrations(); err == nil {
		t.Fatal("默认 CA 写失败必须向上返回错误")
	}
	var providers, seeded int
	if err := database.QueryRow(`SELECT COUNT(*) FROM ca_providers`).Scan(&providers); err != nil {
		t.Fatalf("count CA providers: %v", err)
	}
	if providers != 0 {
		t.Fatalf("providers=%d after failed seed, want 0（四语句必须同事务回滚）", providers)
	}
	if err := database.QueryRow(`SELECT COALESCE(ca_providers_seeded,0) FROM global_config WHERE id=1`).Scan(&seeded); err != nil {
		t.Fatalf("read seed marker: %v", err)
	}
	if seeded != 0 {
		t.Fatalf("ca_providers_seeded=%d after failed seed, want 0（marker 不得掩盖失败）", seeded)
	}

	// 故障解除后重试：播种成功、marker 落位、默认指向 Let's Encrypt（与
	// 「首启即成功」的终态一致）。
	if _, err := database.Exec(`DROP TRIGGER fail_default_ca`); err != nil {
		t.Fatalf("drop failure trigger: %v", err)
	}
	if err := runMigrations(); err != nil {
		t.Fatalf("retry migrations: %v", err)
	}
	if err := database.QueryRow(`SELECT COUNT(*) FROM ca_providers`).Scan(&providers); err != nil {
		t.Fatalf("count CA providers after retry: %v", err)
	}
	if err := database.QueryRow(`SELECT ca_providers_seeded FROM global_config WHERE id=1`).Scan(&seeded); err != nil {
		t.Fatalf("read seed marker after retry: %v", err)
	}
	if providers != 2 || seeded != 1 {
		t.Fatalf("providers=%d seeded=%d after retry, want 2/1", providers, seeded)
	}
	var letsEncryptID, defaultID int
	if err := database.QueryRow(`SELECT id FROM ca_providers WHERE provider='letsencrypt'`).Scan(&letsEncryptID); err != nil {
		t.Fatalf("read letsencrypt provider: %v", err)
	}
	if err := database.QueryRow(`SELECT COALESCE(default_ca_provider_id,0) FROM global_config WHERE id=1`).Scan(&defaultID); err != nil {
		t.Fatalf("read default CA provider: %v", err)
	}
	if defaultID != letsEncryptID || defaultID == 0 {
		t.Fatalf("default_ca_provider_id=%d, want 播种意图的 Let's Encrypt id=%d", defaultID, letsEncryptID)
	}
}
