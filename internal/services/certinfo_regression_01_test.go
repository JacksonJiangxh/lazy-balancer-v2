package services

import (
	"testing"
	"time"
)

// CertificateCandidate.Domain 恒为空，selectCertificate 的「同过期精确匹配
// 优先」决胜层失效：同 NotAfter 时退化为 updated_at/id 决胜，规则证书信息
// 会展示域名超集的新任务证书而非精确匹配证书。
func TestGetRuleCertInfo_prefersExactDomainMatchOnExpiryTie(t *testing.T) {
	_, database := newClusterTestService(t)

	// Given: 同 NotAfter 两候选——精确匹配任务（旧 updated_at）与超集 SAN 任务（新）
	now := time.Now().UTC()
	notAfter := now.Add(60 * 24 * time.Hour)
	exactCert, exactKey := certificatePairForDomains(t, now.Add(-time.Hour), notAfter, "tie.example.test")
	coverCert, coverKey := certificatePairForDomains(t, now.Add(-time.Hour), notAfter, "tie.example.test", "api.tie.example.test")
	if _, err := database.Exec(`INSERT INTO lb_rules (caddy_id,name,domain,protocol,listen_port,enabled,enable_tls,tls_source) VALUES ('lb_tie','tie','tie.example.test','http',8080,1,1,'acme_dns')`); err != nil {
		t.Fatal(err)
	}
	if _, err := database.Exec(`INSERT INTO cert_jobs (rule_id, domain, status, cert_pem, key_pem, updated_at) VALUES ('lb_tie','tie.example.test','issued',?,?,'2026-01-01 00:00:00')`, exactCert, exactKey); err != nil {
		t.Fatal(err)
	}
	if _, err := database.Exec(`INSERT INTO cert_jobs (rule_id, domain, status, cert_pem, key_pem, updated_at) VALUES ('lb_tie','tie.example.test,api.tie.example.test','issued',?,?,'2026-06-01 00:00:00')`, coverCert, coverKey); err != nil {
		t.Fatal(err)
	}

	// When
	info, err := GetRuleCertInfo("lb_tie")
	if err != nil {
		t.Fatalf("GetRuleCertInfo: %v", err)
	}

	// Then: 同过期时精确域名匹配优先（updated_at 更新不得压过精确匹配）。
	// 必须同时断言解析成功：仅凭「不含 api.tie」在候选选择整体失效、回退到
	// missing 文案（Domains=规则域名、Status=unknown）时同样成立。
	if info == nil {
		t.Fatal("info is nil")
	}
	if info.Status != "valid" {
		t.Fatalf("status=%q, want valid（选择失败会回退 missing 形态 status=unknown）", info.Status)
	}
	if info.Domains != "tie.example.test" {
		t.Fatalf("domains=%q, want 精确匹配任务的证书域名（api.tie.example.test 为超集候选）", info.Domains)
	}
}

// Given 手动证书（tls_source=manual）的启用 TLS 规则，规则行带合法 PEM。
// When 单规则证书信息入口（`/rules/:caddy_id/cert-info` 的服务层实现）。
// Then 返回解析成功的证书详情（status=valid、域名为证书 DNSNames、到期/生效
// 时间与到期天数与批量入口同一 formatter 一致）——覆盖此前只有「旧域证书被
// 忽略」空材料路径的单规则成功面。
func TestGetRuleCertInfo_manualPEMReturnsParsedCertificate(t *testing.T) {
	_, database := newClusterTestService(t)
	now := time.Now().UTC()
	notAfter := now.Add(45*24*time.Hour + 3*time.Hour)
	certPEM, keyPEM := certificatePairForDomains(t, now.Add(-time.Hour), notAfter, "manual.example.test", "www.manual.example.test")
	if _, err := database.Exec(`INSERT INTO lb_rules
		(caddy_id,name,domain,protocol,listen_port,enabled,enable_tls,tls_source,tls_cert,tls_key)
		VALUES ('lb_manual','manual','manual.example.test','http',8443,1,1,'manual',?,?)`, certPEM, keyPEM); err != nil {
		t.Fatalf("seed manual TLS rule: %v", err)
	}

	info, err := GetRuleCertInfo("lb_manual")
	if err != nil {
		t.Fatalf("GetRuleCertInfo: %v", err)
	}
	if info == nil {
		t.Fatal("info is nil, want 解析后的证书详情")
	}
	if info.CaddyID != "lb_manual" || info.Source != "manual" {
		t.Fatalf("caddy_id=%q source=%q, want lb_manual/manual", info.CaddyID, info.Source)
	}
	if info.Status != "valid" {
		t.Fatalf("status=%q error=%q, want valid（空材料/解析失败会落 unknown）", info.Status, info.Error)
	}
	if info.Domains != "manual.example.test, www.manual.example.test" {
		t.Fatalf("domains=%q, want 证书 DNSNames 顺序串接", info.Domains)
	}
	// 与批量入口（FormatRuleCertInfo）同口径：同一段 PEM 的时间字段与天数一致。
	want := FormatRuleCertInfo(certPEM, "manual", "manual.example.test", "lb_manual", GetCertExpiryThreshold(), time.Now())
	if info.NotBefore != want.NotBefore || info.NotAfter != want.NotAfter {
		t.Fatalf("时间字段 not_before=%q not_after=%q, want %q/%q",
			info.NotBefore, info.NotAfter, want.NotBefore, want.NotAfter)
	}
	if diff := info.DaysRemaining - want.DaysRemaining; diff < -1 || diff > 1 {
		t.Fatalf("days_remaining=%d, want ≈%d（同一 formatter 口径）", info.DaysRemaining, want.DaysRemaining)
	}
	if info.DaysRemaining <= 0 {
		t.Fatalf("days_remaining=%d, want 正数（45 天后到期）", info.DaysRemaining)
	}
}
