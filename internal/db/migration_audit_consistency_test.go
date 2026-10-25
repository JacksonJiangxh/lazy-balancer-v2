package db

import (
	"strings"
	"testing"
)

// 一次性迁移的审计口径必须统一为「提交后按实际变更计数、一行聚合」：
//   - 探测计数会重复计数（同一行命中多条子查询）且并发修正后与实际变更脱节，
//     不能直接当「已清零处数」；
//   - 逐规则一条审计在存量 N 条时写 N 条，受 systemAuditBufferCap 截断且噪音大。
func TestMigrateRuleTLSModeResidue_skipsAuditWhenNothingChanged(t *testing.T) {
	database := openMigrationTestDB(t)
	if err := createTables(); err != nil {
		t.Fatalf("create tables: %v", err)
	}
	if _, err := database.Exec("INSERT OR IGNORE INTO global_config (id, caddy_config, cluster_version) VALUES (1,'{}',0)"); err != nil {
		t.Fatalf("seed global config: %v", err)
	}
	if _, err := database.Exec(`INSERT INTO lb_rules (id, caddy_id, name, protocol, domain, listen_port, tls_source, tls_cert, tls_key)
		VALUES (1, 'lb_residue_noop', 'residue-noop', 'http', 'residue.example.test', 443, 'acme_dns', 'CERT', 'KEY')`); err != nil {
		t.Fatalf("seed residue rule: %v", err)
	}
	// 探测命中但 UPDATE 全部被跳过（等价：探测到加锁/执行之间行已被并发修正）。
	if _, err := database.Exec(`CREATE TRIGGER skip_tls_residue BEFORE UPDATE ON lb_rules
		BEGIN SELECT RAISE(IGNORE); END;`); err != nil {
		t.Fatalf("create skip trigger: %v", err)
	}
	drainSystemAuditBuffer()

	if err := migrateRuleTLSModeResidue(); err != nil {
		t.Fatalf("migrate: %v", err)
	}

	if entries := drainSystemAuditBuffer(); len(entries) != 0 {
		t.Fatalf("实际变更 0 行时不得写审计（探测计数不得冒充变更数）: %+v", entries)
	}
	var version int
	if err := database.QueryRow(`SELECT cluster_version FROM global_config WHERE id=1`).Scan(&version); err != nil {
		t.Fatal(err)
	}
	if version != 0 {
		t.Fatalf("cluster_version=%d, want 0（无实际变更不得 bump）", version)
	}
}

// 逐规则审计改一行聚合 + 计数（caddy_id 清单上限 20）：存量 N 条不再写 N 条。
func TestMigrateTCPRuleStaleDNSServer_aggregatesAudit(t *testing.T) {
	database := openMigrationTestDB(t)
	if err := createTables(); err != nil {
		t.Fatalf("create tables: %v", err)
	}
	if _, err := database.Exec("INSERT OR IGNORE INTO global_config (id, caddy_config, cluster_version) VALUES (1,'{}',0)"); err != nil {
		t.Fatalf("seed global config: %v", err)
	}
	if _, err := database.Exec(`INSERT INTO lb_rules (caddy_id, name, protocol, domain, listen_port, enable_dns_server, dns_server)
		VALUES ('lb_tcp_dns_a','tcp-dns-a','tcp','',19001,1,'8.8.8.8:53'),
		       ('lb_tcp_dns_b','tcp-dns-b','tcp','',19002,1,'1.1.1.1:53')`); err != nil {
		t.Fatalf("seed stale dns rules: %v", err)
	}
	drainSystemAuditBuffer()

	if err := migrateTCPRuleStaleDNSServer(); err != nil {
		t.Fatalf("migrate: %v", err)
	}

	entries := drainSystemAuditBuffer()
	if len(entries) != 1 {
		t.Fatalf("audit entries=%d, want 1（按批聚合，避免截断与噪音）: %+v", len(entries), entries)
	}
	for _, fragment := range []string{"2", "lb_tcp_dns_a", "lb_tcp_dns_b"} {
		if !strings.Contains(entries[0].detail, fragment) {
			t.Fatalf("audit detail=%q, want 含 %q", entries[0].detail, fragment)
		}
	}
}

// 遗留记账行被删除时若目标列已非空（搬运 UPDATE 的谓词不成立），遗留哈希/版本
// 会被整体丢弃——一次性记账丢失不可恢复，必须留痕说明丢弃了什么。
func TestMigrateDropMergedSyncSwitchColumns_recordsDiscardedLegacyBookkeeping(t *testing.T) {
	database := openMigrationTestDB(t)
	if err := createTables(); err != nil {
		t.Fatalf("create tables: %v", err)
	}
	// 目标记账列由 runMigrations 的 newColumns 通道补齐（本用例直调迁移，
	// 需显式补列以复现升级后形态）。
	if err := ensureNewColumns(map[string]string{
		"global_config.applied_waf_ref_hash":    "TEXT DEFAULT ''",
		"global_config.applied_waf_ref_version": "INTEGER DEFAULT 0",
	}, nil); err != nil {
		t.Fatalf("add bookkeeping columns: %v", err)
	}
	if _, err := database.Exec(`INSERT INTO global_config (id, caddy_config, applied_waf_ref_hash, applied_waf_ref_version)
		VALUES (1,'{}','target-hash',9)`); err != nil {
		t.Fatalf("seed global config: %v", err)
	}
	if _, err := database.Exec(`CREATE TABLE cluster_applied_sections (
		section TEXT PRIMARY KEY,
		hash TEXT DEFAULT '',
		applied_version INTEGER DEFAULT 0,
		applied_at DATETIME
	)`); err != nil {
		t.Fatalf("create legacy applied sections table: %v", err)
	}
	if _, err := database.Exec(`INSERT INTO cluster_applied_sections (section, hash, applied_version, applied_at)
		VALUES ('waf_files','legacy-hash',3,datetime('now'))`); err != nil {
		t.Fatalf("seed legacy bookkeeping: %v", err)
	}
	drainSystemAuditBuffer()

	if err := migrateDropMergedSyncSwitchColumns(); err != nil {
		t.Fatalf("migrate: %v", err)
	}

	var legacyRows int
	if err := database.QueryRow(`SELECT COUNT(*) FROM cluster_applied_sections WHERE section='waf_files'`).Scan(&legacyRows); err != nil {
		t.Fatal(err)
	}
	if legacyRows != 0 {
		t.Fatalf("legacy rows=%d, want 0", legacyRows)
	}
	var hash string
	var version int
	if err := database.QueryRow(`SELECT COALESCE(applied_waf_ref_hash,''), COALESCE(applied_waf_ref_version,0) FROM global_config WHERE id=1`).Scan(&hash, &version); err != nil {
		t.Fatal(err)
	}
	if hash != "target-hash" || version != 9 {
		t.Fatalf("target bookkeeping=(%q,%d), want (target-hash,9)（已非空的目标列不得被遗留值覆盖）", hash, version)
	}
	entries := drainSystemAuditBuffer()
	if len(entries) != 1 {
		t.Fatalf("audit entries=%d, want 1（丢弃遗留记账必须留痕）: %+v", len(entries), entries)
	}
	for _, fragment := range []string{"legacy-hash", "target-hash"} {
		if !strings.Contains(entries[0].detail, fragment) {
			t.Fatalf("audit detail=%q, want 含 %q", entries[0].detail, fragment)
		}
	}
}
