package services

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"testing"
	"time"
)

// 续签窗口接近证书寿命时（W=88/89 天 + 90 天证书，或 CA 实际寿命略长于 90 天），
// 相邻两次自动续签的自然间隔 L−W 会退化到小时级：每轮扫描都入队 → 每日甚至
// 亚日级完整重签，命中 CA 重复证书限流后落 waiting_ca/failed，约一个寿命周期后
// 证书到期中断。成功侧迟滞要求「距上次签发 ≥ max(24h, L−W)」。

func hysteresisLeaf(lifetime, age time.Duration, now time.Time) *x509.Certificate {
	notBefore := now.Add(-age)
	return &x509.Certificate{NotBefore: notBefore, NotAfter: notBefore.Add(lifetime)}
}

func TestCertRenewalHysteresisActive_table(t *testing.T) {
	now := time.Date(2026, 10, 23, 12, 0, 0, 0, time.UTC)
	cases := []struct {
		name       string
		lifetime   time.Duration
		age        time.Duration
		windowDays int
		want       bool
	}{
		// W=89/L=90：自然间隔 1 天，24h 下限不改变日级节奏
		{"W89 just issued", 90 * 24 * time.Hour, time.Hour, 89, true},
		{"W89 23h after issuance", 90 * 24 * time.Hour, 23 * time.Hour, 89, true},
		{"W89 25h after issuance", 90 * 24 * time.Hour, 25 * time.Hour, 89, false},
		// W=88/L=90：自然间隔 2 天
		{"W88 1h", 90 * 24 * time.Hour, time.Hour, 88, true},
		{"W88 47h", 90 * 24 * time.Hour, 47 * time.Hour, 88, true},
		{"W88 49h", 90 * 24 * time.Hour, 49 * time.Hour, 88, false},
		// W=90/L=90：窗口覆盖寿命，24h 下限仍生效（窗口守卫另有一道）
		{"W90 1h", 90 * 24 * time.Hour, time.Hour, 90, true},
		{"W90 25h", 90 * 24 * time.Hour, 25 * time.Hour, 90, false},
		// W=60/L=90：自然间隔 30 天
		{"W60 29d", 90 * 24 * time.Hour, 29 * 24 * time.Hour, 60, true},
		{"W60 31d", 90 * 24 * time.Hour, 31 * 24 * time.Hour, 60, false},
		// 保护区（剩余 ≤ 7 天）一律放行
		{"W80 remaining 6d", 90 * 24 * time.Hour, 84 * 24 * time.Hour, 80, false},
		// 未知签发时刻不迟滞（读侧保持既有语义）
		{"zero issuance", 90 * 24 * time.Hour, 0, 89, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			leaf := hysteresisLeaf(tc.lifetime, tc.age, now)
			issuedAt := time.Time{}
			if tc.age > 0 {
				issuedAt = now.Add(-tc.age)
			}
			got := certRenewalHysteresisActive(time.Duration(tc.windowDays)*24*time.Hour, leaf, issuedAt, now)
			if got != tc.want {
				t.Fatalf("hysteresis=%v, want %v (lifetime=%s age=%s W=%d)", got, tc.want, tc.lifetime, tc.age, tc.windowDays)
			}
		})
	}
}

func hysteresisCertPair(t *testing.T, notBefore, notAfter time.Time) (certPEM, keyPEM string) {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 1024)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	template := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "example.com"},
		DNSNames:     []string{"example.com"},
		NotBefore:    notBefore,
		NotAfter:     notAfter,
	}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		t.Fatalf("create certificate: %v", err)
	}
	certPEM = string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}))
	keyPEM = string(pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(key)}))
	return certPEM, keyPEM
}

// 真实扫描链路：窗口接近证书寿命（库值 89 天按安全上限 88 天生效；证书实际
// 寿命 88.5 天 → L−W = 12h）时，签发 13h 后仍处于迟滞窗口，不得被再次选中；
// 签发时刻超过 24h 后恢复可续签。
func TestCheckExpiration_hysteresisBlocksFreshRenewalWhenWindowNearLifetime(t *testing.T) {
	_, database := newClusterTestService(t)
	const ruleID = "lb_hysteresis"
	if _, err := database.Exec(`INSERT INTO lb_rules (caddy_id,name,domain,protocol,listen_port,enabled,enable_tls,tls_source)
		VALUES (?, 'hysteresis', 'example.com', 'http', 8443, 1, 1, 'acme_dns')`, ruleID); err != nil {
		t.Fatalf("seed rule: %v", err)
	}
	// 旧版本遗留的 89 天：库值原样保留，读侧按安全上限 88 天生效（显性告警）。
	if _, err := database.Exec("UPDATE global_config SET cert_renewal_days=89 WHERE id=1"); err != nil {
		t.Fatalf("set renewal days: %v", err)
	}
	now := time.Now()
	notBefore := now.Add(-13 * time.Hour)
	notAfter := notBefore.Add(88*24*time.Hour + 12*time.Hour) // 寿命 88.5 天 → L−W = 12h
	certPEM, keyPEM := hysteresisCertPair(t, notBefore, notAfter)
	result, err := database.Exec(`INSERT INTO cert_jobs (rule_id,domain,status,ca_provider_id,cert_pem,key_pem,expires_at,updated_at)
		VALUES (?, 'example.com', 'issued', 0, ?, ?, ?, datetime('now','-13 hours'))`, ruleID, certPEM, keyPEM, notAfter.UTC().Format("2006-01-02 15:04:05"))
	if err != nil {
		t.Fatalf("seed job: %v", err)
	}
	jobID, err := result.LastInsertId()
	if err != nil {
		t.Fatalf("read job id: %v", err)
	}

	service := NewCertificateService()
	resetCertificateServiceForTest(t)

	// When：签发后立即扫描
	jobs, skipped, err := service.CheckExpiration()

	// Then：迟滞阻止密集重签
	if err != nil {
		t.Fatalf("check expiration: %v", err)
	}
	if skipped != 0 {
		t.Fatalf("scan skipped=%d, want 0", skipped)
	}
	for _, job := range jobs {
		if int64(job.ID) == jobID {
			t.Fatalf("freshly issued job %d selected for renewal, want hysteresis skip", jobID)
		}
	}

	// When：真实签发时刻回拨 25h（超过 24h 下限）——迟滞以证书 NotBefore
	// 为签发时刻，簿记写（updated_at）不参与判定，因此必须连同材料一起回拨。
	agedNotBefore := now.Add(-25 * time.Hour)
	agedNotAfter := agedNotBefore.Add(88*24*time.Hour + 12*time.Hour)
	agedCertPEM, agedKeyPEM := hysteresisCertPair(t, agedNotBefore, agedNotAfter)
	if _, err := database.Exec("UPDATE cert_jobs SET cert_pem=?, key_pem=?, expires_at=?, updated_at=datetime('now','-25 hours') WHERE id=?",
		agedCertPEM, agedKeyPEM, agedNotAfter.UTC().Format("2006-01-02 15:04:05"), jobID); err != nil {
		t.Fatalf("age job issuance: %v", err)
	}
	jobs, _, err = service.CheckExpiration()
	if err != nil {
		t.Fatalf("check expiration after aging: %v", err)
	}

	// Then：恢复可续签（迟滞不得变成永久跳过）
	var found bool
	for _, job := range jobs {
		if int64(job.ID) == jobID {
			found = true
		}
	}
	if !found {
		t.Fatalf("job %d not selected after 25h, want renewal candidate", jobID)
	}
}
