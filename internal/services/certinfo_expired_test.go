package services

// 历史修复(历史):ACME 规则证书信息对「已过期证书」不得误报「尚未签发
// 或不存在」——cert_jobs 存在 PEM 但已过期时按 expired 呈现(解析真实
// NotAfter),运维可从规则列表直接看到过期状态。

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"strings"
	"testing"
	"time"

	"lazy-balancer-v2/internal/db"
)

// expiredShapeCertAndKey 生成指定域名/有效期外的证书+私钥 PEM 对。
func expiredShapeCertAndKey(t *testing.T, domain string, notAfter time.Time) (string, string) {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 1024)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	template := &x509.Certificate{
		SerialNumber: big.NewInt(2),
		Subject:      pkix.Name{CommonName: domain},
		DNSNames:     []string{domain},
		NotBefore:    time.Now().Add(-48 * time.Hour),
		NotAfter:     notAfter,
	}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		t.Fatalf("create certificate: %v", err)
	}
	certPEM := string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}))
	keyPEM := string(pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(key)}))
	return certPEM, keyPEM
}

func TestGetRuleCertInfo_reportsExpiredACMECert(t *testing.T) {
	_, database := newClusterTestService(t)

	// Given:ACME 规则 + cert_jobs 携带已过期证书(SelectCertificate 因过期跳过)
	certPEM, keyPEM := expiredShapeCertAndKey(t, "expired.test", time.Now().Add(-24*time.Hour))
	if _, err := database.Exec(`INSERT INTO lb_rules (caddy_id,name,domain,protocol,listen_port,enabled,enable_tls,tls_source) VALUES ('lb_expired','expired','expired.test','http',8080,1,1,'acme_dns')`); err != nil {
		t.Fatal(err)
	}
	if _, err := database.Exec(`INSERT INTO cert_jobs (rule_id, domain, status, cert_pem, key_pem, updated_at) VALUES ('lb_expired', 'expired.test', 'issued', ?, ?, datetime('now'))`, certPEM, keyPEM); err != nil {
		t.Fatal(err)
	}

	// When
	info, err := GetRuleCertInfo("lb_expired")
	if err != nil {
		t.Fatalf("GetRuleCertInfo: %v", err)
	}

	// Then:expired 而非「尚未签发」
	if info == nil {
		t.Fatal("info is nil")
	}
	if info.Status != "expired" {
		t.Fatalf("status=%q, want expired (must not report 尚未签发)", info.Status)
	}
	if !strings.Contains(info.Error, "已过期") {
		t.Fatalf("error=%q, want ACME 证书已过期", info.Error)
	}
}

// ---- 历史（SV历史问题）----

// SV历史问题：GetRuleCertInfo 的读故障必须上抛（handler 500），不得折叠成
// 「无证书信息」假成功；规则不存在仍是 (nil, nil)。
func TestGetRuleCertInfo_propagates_database_errors(t *testing.T) {
	newClusterTestService(t)
	if err := db.DB.Close(); err != nil {
		t.Fatalf("close db: %v", err)
	}

	// When
	info, err := GetRuleCertInfo("lb_missing")

	// Then
	if err == nil {
		t.Fatalf("info=%v err=nil, want DB error（fail-visible）", info)
	}
	if info != nil {
		t.Fatalf("info=%v, want nil on error", info)
	}
}

func TestGetRuleCertInfo_missing_rule_is_not_an_error(t *testing.T) {
	newClusterTestService(t)

	info, err := GetRuleCertInfo("lb_missing")

	if err != nil {
		t.Fatalf("err=%v, want nil（规则不存在沿用 200+null 契约）", err)
	}
	if info != nil {
		t.Fatalf("info=%v, want nil", info)
	}
}

// ACME 分支的 cert_jobs 读取故障必须与规则行读取同契约
// 上抛——此前查询/Scan/迭代失败全部折叠成 missingACMECertInfo(nil)，DB 故障
// 时单规则证书接口返回 200 +「ACME 证书尚未签发或不存在」，与真实「还没签发」
// 不可区分。仅「无候选行」允许返回 missing 信息。
func TestGetRuleCertInfo_propagates_cert_jobs_read_errors(t *testing.T) {
	_, database := newClusterTestService(t)
	if _, err := database.Exec(`INSERT INTO lb_rules (caddy_id,name,domain,protocol,listen_port,enabled,enable_tls,tls_source) VALUES ('lb_acme_read_fault','fault','fault.test','http',8080,1,1,'acme_dns')`); err != nil {
		t.Fatalf("seed rule: %v", err)
	}
	// Given：cert_jobs 读取故障（表缺失模拟迁移中断/库损坏——查询期即失败）
	if _, err := database.Exec(`DROP TABLE cert_jobs`); err != nil {
		t.Fatalf("drop cert_jobs: %v", err)
	}

	// When
	info, err := GetRuleCertInfo("lb_acme_read_fault")

	// Then：读故障上抛，不得假成功
	if err == nil {
		t.Fatalf("info=%+v err=nil, want cert_jobs 读故障上抛（不得折叠成「尚未签发」假成功）", info)
	}
	if info != nil {
		t.Fatalf("info=%+v, want nil on error", info)
	}
}

// 回归形状：ACME 规则没有任何候选行（确实还没签发）仍返回 missing 信息 + nil
// error——上抛改造不得把「无证书」也变成 500。
func TestGetRuleCertInfo_acme_without_candidates_is_missing_info(t *testing.T) {
	_, database := newClusterTestService(t)
	if _, err := database.Exec(`INSERT INTO lb_rules (caddy_id,name,domain,protocol,listen_port,enabled,enable_tls,tls_source) VALUES ('lb_acme_pending','pending','pending.test','http',8080,1,1,'acme_dns')`); err != nil {
		t.Fatalf("seed rule: %v", err)
	}

	info, err := GetRuleCertInfo("lb_acme_pending")

	if err != nil {
		t.Fatalf("err=%v, want nil（无候选行不是读故障）", err)
	}
	if info == nil || info.Status != "unknown" || !strings.Contains(info.Error, "尚未签发") {
		t.Fatalf("info=%+v, want missing ACME 信息（unknown + 尚未签发）", info)
	}
}
