package db

import "testing"

// global_config.dns_credentials 是退役列：读路径不回显、写路径已移除、备份
// 三面排除、集群快照不再携带——现存的唯一形态是「存量库里的残留列 + 残留
// 值」。启动迁移把它列入 deadColumnDrops 幂等删除，值与列一并消失，不再有
// 任何写入方（旧备份导入侧另有保护键 + 列存在性判定，不会把列写回）。
func TestRunMigrationsDropsLegacyGlobalDNSCredentials(t *testing.T) {
	// Given 存量库形态：global_config 仍带该列与残留凭证
	database := openMigrationTestDB(t)
	if err := createTables(); err != nil {
		t.Fatalf("create tables: %v", err)
	}
	var hasColumn int
	if err := database.QueryRow("SELECT COUNT(*) FROM pragma_table_info('global_config') WHERE name='dns_credentials'").Scan(&hasColumn); err != nil {
		t.Fatalf("query global_config schema: %v", err)
	}
	if hasColumn == 0 {
		if _, err := database.Exec("ALTER TABLE global_config ADD COLUMN dns_credentials TEXT"); err != nil {
			t.Fatalf("simulate legacy column: %v", err)
		}
	}
	if _, err := database.Exec(`INSERT INTO global_config (id,caddy_config,dns_credentials) VALUES (1,'{}','legacy-id,legacy-token')`); err != nil {
		t.Fatalf("seed legacy credentials: %v", err)
	}
	// 旧版本的集群版本触发器在 OF 清单里引用该列（升级现场的真实形态）：
	// 删列不得因触发器引用而失败（触发器随后由启动序列按最新清单重建）。
	if _, err := database.Exec(`CREATE TRIGGER cluster_version_global_config_update AFTER UPDATE OF dns_credentials ON global_config WHEN 1 BEGIN SELECT 1; END`); err != nil {
		t.Fatalf("seed legacy cluster version trigger: %v", err)
	}

	// When
	if err := runMigrations(); err != nil {
		t.Fatalf("run migrations: %v", err)
	}

	// Then 列已删、行存活（删除列不等于删配置行）
	var count int
	if err := database.QueryRow("SELECT COUNT(*) FROM pragma_table_info('global_config') WHERE name='dns_credentials'").Scan(&count); err != nil {
		t.Fatalf("query global_config schema after migration: %v", err)
	}
	if count != 0 {
		t.Fatalf("global_config.dns_credentials count=%d, want 0（退役列未删）", count)
	}
	var id int
	if err := database.QueryRow("SELECT id FROM global_config WHERE id=1").Scan(&id); err != nil {
		t.Fatalf("global_config 行必须存活: %v", err)
	}

	// 二次执行幂等：列已不存在，不报错、不改终态。
	if err := runMigrations(); err != nil {
		t.Fatalf("second run: %v", err)
	}
}
