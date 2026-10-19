package db

// 历史问题（历史）：TCP 死值清零 / stale DNS 清理与 cluster_version
// bump 必须同事务——此前清零先提交、bump 失败后下次启动 WHERE 不再命中，
// bump 永不发生（主从 canonical 长期分叉）；stale DNS 侧此前完全不 bump。

import (
	"database/sql"
	"testing"
)

func seedTCPDeadFieldRules(t *testing.T, database *sql.DB) {
	t.Helper()
	if _, err := database.Exec(`INSERT INTO global_config (id,caddy_config,cluster_version) VALUES (1,'{}',0);
		INSERT INTO lb_rules (name,protocol,listen_port,host_header,enable_dns_server,dns_server,caddy_id) VALUES
			('tcp-dead','tcp',9090,'dead.example',0,'','lb_tcp_dead'),
			('tcp-dns','tcp',9091,'',1,'8.8.8.8:53','lb_tcp_dns');`); err != nil {
		t.Fatalf("seed tcp rules: %v", err)
	}
}

func clusterVersion(t *testing.T, database *sql.DB) int {
	t.Helper()
	var version int
	if err := database.QueryRow(`SELECT cluster_version FROM global_config WHERE id=1`).Scan(&version); err != nil {
		t.Fatalf("read cluster_version: %v", err)
	}
	return version
}

func TestTCPRuleDeadFields_rollsBackWhenClusterVersionBumpFails(t *testing.T) {
	database := openMigrationTestDB(t)
	if err := createTables(); err != nil {
		t.Fatalf("create tables: %v", err)
	}
	seedTCPDeadFieldRules(t, database)
	if _, err := database.Exec(`CREATE TRIGGER block_cluster_bump BEFORE UPDATE OF cluster_version ON global_config
		BEGIN SELECT RAISE(ABORT, 'bump blocked'); END;`); err != nil {
		t.Fatalf("create blocking trigger: %v", err)
	}

	// When bump 失败
	if err := migrateTCPRuleDeadFields(); err == nil {
		t.Fatal("bump 失败必须向上返回错误")
	}

	// Then 清零与 bump 同事务回滚：字段保持原值、版本不变（下次启动可重试）。
	var hostHeader string
	if err := database.QueryRow(`SELECT host_header FROM lb_rules WHERE caddy_id='lb_tcp_dead'`).Scan(&hostHeader); err != nil {
		t.Fatalf("read tcp rule: %v", err)
	}
	if hostHeader != "dead.example" {
		t.Fatalf("host_header=%q, want rollback-preserved dead.example", hostHeader)
	}
	if version := clusterVersion(t, database); version != 0 {
		t.Fatalf("cluster_version=%d, want 0", version)
	}

	// And：故障解除后重跑一次成功——字段清零且版本恰好 +1。
	if _, err := database.Exec(`DROP TRIGGER block_cluster_bump`); err != nil {
		t.Fatalf("drop blocking trigger: %v", err)
	}
	if err := migrateTCPRuleDeadFields(); err != nil {
		t.Fatalf("retry dead-field cleanup: %v", err)
	}
	if err := database.QueryRow(`SELECT host_header FROM lb_rules WHERE caddy_id='lb_tcp_dead'`).Scan(&hostHeader); err != nil {
		t.Fatalf("read normalized tcp rule: %v", err)
	}
	if hostHeader != "" {
		t.Fatalf("host_header=%q, want cleared", hostHeader)
	}
	if version := clusterVersion(t, database); version != 1 {
		t.Fatalf("cluster_version=%d, want 1 after single successful bump", version)
	}
}

func TestTCPRuleStaleDNSServer_bumpsClusterVersionOnce(t *testing.T) {
	database := openMigrationTestDB(t)
	if err := createTables(); err != nil {
		t.Fatalf("create tables: %v", err)
	}
	seedTCPDeadFieldRules(t, database)

	// When：首轮清理 stale DNS（该行同时命中死字段谓词，但死字段迁移不在本
	// 测试调用范围内——两迁移在生产启动链各自独立）。
	if err := migrateTCPRuleStaleDNSServer(); err != nil {
		t.Fatalf("migrate stale dns: %v", err)
	}

	// Then：清字段并 bump 一次（从端版本门失效 → 下轮收敛）。
	var dnsServer string
	if err := database.QueryRow(`SELECT dns_server FROM lb_rules WHERE caddy_id='lb_tcp_dns'`).Scan(&dnsServer); err != nil {
		t.Fatalf("read tcp dns rule: %v", err)
	}
	if dnsServer != "" {
		t.Fatalf("dns_server=%q, want cleared", dnsServer)
	}
	if version := clusterVersion(t, database); version != 1 {
		t.Fatalf("cluster_version=%d, want 1 after stale dns cleanup", version)
	}

	// And：重跑零命中零扰动。
	if err := migrateTCPRuleStaleDNSServer(); err != nil {
		t.Fatalf("repeat stale dns migration: %v", err)
	}
	if version := clusterVersion(t, database); version != 1 {
		t.Fatalf("cluster_version=%d after idempotent rerun, want 1", version)
	}
}

func TestTCPRuleStaleDNSServer_rollsBackWhenBumpFails(t *testing.T) {
	database := openMigrationTestDB(t)
	if err := createTables(); err != nil {
		t.Fatalf("create tables: %v", err)
	}
	seedTCPDeadFieldRules(t, database)
	if _, err := database.Exec(`CREATE TRIGGER block_cluster_bump BEFORE UPDATE OF cluster_version ON global_config
		BEGIN SELECT RAISE(ABORT, 'bump blocked'); END;`); err != nil {
		t.Fatalf("create blocking trigger: %v", err)
	}

	if err := migrateTCPRuleStaleDNSServer(); err == nil {
		t.Fatal("bump 失败必须向上返回错误")
	}
	var dnsServer string
	if err := database.QueryRow(`SELECT dns_server FROM lb_rules WHERE caddy_id='lb_tcp_dns'`).Scan(&dnsServer); err != nil {
		t.Fatalf("read tcp dns rule: %v", err)
	}
	if dnsServer != "8.8.8.8:53" {
		t.Fatalf("dns_server=%q, want rollback-preserved", dnsServer)
	}
}
