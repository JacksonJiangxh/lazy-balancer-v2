package db

import "testing"

// TCP 规则的上游回源域名是死值（origin_domain 仅 HTTP 回源消费，保存族自
// 该字段引入起即拒绝 TCP 携带）：存量残留会随 rules 节同步到从端，并让系统
// 自身导出的备份在导入校验被整包 400 拒绝（备份自毒）。启动迁移必须清零，
// 且 HTTP 规则的 per-upstream 回源域名不得被误清。
func TestMigrateTCPRuleDeadFields_clearsUpstreamOrigin(t *testing.T) {
	database := openMigrationTestDB(t)
	if err := createTables(); err != nil {
		t.Fatalf("create tables: %v", err)
	}
	if _, err := database.Exec("INSERT OR IGNORE INTO global_config (id, caddy_config, cluster_version) VALUES (1,'{}',0)"); err != nil {
		t.Fatalf("seed global config: %v", err)
	}
	if _, err := database.Exec(`INSERT INTO lb_rules (id, caddy_id, name, protocol, domain, listen_port)
		VALUES (1, 'lb_tcp_origin', 'tcp-origin', 'tcp', '', 19443)`); err != nil {
		t.Fatalf("seed tcp rule: %v", err)
	}
	if _, err := database.Exec(`INSERT INTO lb_rules (id, caddy_id, name, protocol, domain, listen_port)
		VALUES (2, 'lb_http_origin', 'http-origin', 'http', 'origin.example.test', 18443)`); err != nil {
		t.Fatalf("seed http rule: %v", err)
	}
	if _, err := database.Exec(`INSERT INTO upstreams (rule_id, host, port, weight, enabled, protocol, origin_domain)
		VALUES ('lb_tcp_origin', '10.0.0.1', 8080, 1, 1, 'http', 'stale.example.test'),
		       ('lb_http_origin', '10.0.0.2', 8080, 1, 1, 'https', 'keep.example.test')`); err != nil {
		t.Fatalf("seed upstreams: %v", err)
	}

	if err := migrateTCPRuleDeadFields(); err != nil {
		t.Fatalf("migrate: %v", err)
	}

	var tcpOrigin, httpOrigin string
	if err := database.QueryRow(`SELECT COALESCE(origin_domain,'') FROM upstreams WHERE rule_id='lb_tcp_origin'`).Scan(&tcpOrigin); err != nil {
		t.Fatalf("read tcp upstream: %v", err)
	}
	if err := database.QueryRow(`SELECT COALESCE(origin_domain,'') FROM upstreams WHERE rule_id='lb_http_origin'`).Scan(&httpOrigin); err != nil {
		t.Fatalf("read http upstream: %v", err)
	}
	if tcpOrigin != "" {
		t.Fatalf("tcp upstream origin=%q, want 清零", tcpOrigin)
	}
	if httpOrigin != "keep.example.test" {
		t.Fatalf("http upstream origin=%q, want 保留（per-upstream 回源仅 HTTP 消费）", httpOrigin)
	}
	var version int
	if err := database.QueryRow(`SELECT cluster_version FROM global_config WHERE id=1`).Scan(&version); err != nil {
		t.Fatalf("read version: %v", err)
	}
	if version != 1 {
		t.Fatalf("cluster_version=%d, want 1（残留清零须 bump 触发从端收敛）", version)
	}
	// 幂等：重跑无命中，不再 bump。
	if err := migrateTCPRuleDeadFields(); err != nil {
		t.Fatalf("migrate again: %v", err)
	}
	if err := database.QueryRow(`SELECT cluster_version FROM global_config WHERE id=1`).Scan(&version); err != nil {
		t.Fatalf("read version again: %v", err)
	}
	if version != 1 {
		t.Fatalf("cluster_version=%d after rerun, want 1（无命中零写）", version)
	}
}

// HTTP 规则的跨模式 TLS 残留（非 manual 带证书材料、非 acme_dns 带 CA 引用、
// manual 带 ACME 配置引用）只在保存/导入写侧清零——升级前遗留行此前只有再
// 编辑才自愈。启动迁移按同一不变量归零，bump 一次触发从端收敛。
func TestMigrateRuleTLSModeResidue(t *testing.T) {
	database := openMigrationTestDB(t)
	if err := createTables(); err != nil {
		t.Fatalf("create tables: %v", err)
	}
	if _, err := database.Exec("INSERT OR IGNORE INTO global_config (id, caddy_config, cluster_version) VALUES (1,'{}',0)"); err != nil {
		t.Fatalf("seed global config: %v", err)
	}
	if _, err := database.Exec(`INSERT INTO lb_rules (id, caddy_id, name, protocol, domain, listen_port, tls_source, tls_cert, tls_key, acme_config_id, ca_provider_id)
		VALUES (1, 'lb_acme_residue', 'acme-residue', 'http', 'acme.example.test', 443, 'acme_dns', 'CERT', 'KEY', 2, 3),
		       (2, 'lb_manual_residue', 'manual-residue', 'http', 'manual.example.test', 443, 'manual', 'KEEP_CERT', 'KEEP_KEY', 7, 9),
		       (3, 'lb_manual_clean', 'manual-clean', 'http', 'clean.example.test', 443, 'manual', 'CERT2', 'KEY2', 0, 0)`); err != nil {
		t.Fatalf("seed rules: %v", err)
	}

	if err := migrateRuleTLSModeResidue(); err != nil {
		t.Fatalf("migrate: %v", err)
	}

	var cert, key string
	var acmeID, caID int
	if err := database.QueryRow(`SELECT COALESCE(tls_cert,''), COALESCE(tls_key,''), COALESCE(acme_config_id,0), COALESCE(ca_provider_id,0) FROM lb_rules WHERE caddy_id='lb_acme_residue'`).
		Scan(&cert, &key, &acmeID, &caID); err != nil {
		t.Fatalf("read acme rule: %v", err)
	}
	if cert != "" || key != "" {
		t.Fatalf("acme rule cert=%q key=%q, want 清零（非 manual 不保留材料）", cert, key)
	}
	if caID != 3 {
		t.Fatalf("acme rule ca_provider_id=%d, want 3（acme 源保留 CA 引用）", caID)
	}
	if err := database.QueryRow(`SELECT COALESCE(tls_cert,''), COALESCE(tls_key,''), COALESCE(acme_config_id,0), COALESCE(ca_provider_id,0) FROM lb_rules WHERE caddy_id='lb_manual_residue'`).
		Scan(&cert, &key, &acmeID, &caID); err != nil {
		t.Fatalf("read manual rule: %v", err)
	}
	if cert != "KEEP_CERT" || key != "KEEP_KEY" {
		t.Fatalf("manual rule cert=%q key=%q, want 保留材料", cert, key)
	}
	if acmeID != 0 {
		t.Fatalf("manual rule acme_config_id=%d, want 0（manual 源不保留 ACME 引用）", acmeID)
	}
	if caID != 0 {
		t.Fatalf("manual rule ca_provider_id=%d, want 0（非 acme_dns 不保留 CA 引用）", caID)
	}
	var cleanCert string
	if err := database.QueryRow(`SELECT COALESCE(tls_cert,'') FROM lb_rules WHERE caddy_id='lb_manual_clean'`).Scan(&cleanCert); err != nil {
		t.Fatalf("read clean rule: %v", err)
	}
	if cleanCert != "CERT2" {
		t.Fatalf("clean manual rule cert=%q, want 保留", cleanCert)
	}
	var version int
	if err := database.QueryRow(`SELECT cluster_version FROM global_config WHERE id=1`).Scan(&version); err != nil {
		t.Fatalf("read version: %v", err)
	}
	if version != 1 {
		t.Fatalf("cluster_version=%d, want 1", version)
	}
	if err := migrateRuleTLSModeResidue(); err != nil {
		t.Fatalf("migrate again: %v", err)
	}
	if err := database.QueryRow(`SELECT cluster_version FROM global_config WHERE id=1`).Scan(&version); err != nil {
		t.Fatalf("read version again: %v", err)
	}
	if version != 1 {
		t.Fatalf("cluster_version=%d after rerun, want 1（二次启动零写）", version)
	}
}
