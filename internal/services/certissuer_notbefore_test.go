package services

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"testing"
	"time"

	"lazy-balancer-v2/internal/db"
)

// testCertificatePEMWithWindow 生成指定生效窗口的自签测试证书。
func testCertificatePEMWithWindow(t *testing.T, notBefore, notAfter time.Time) string {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 1024)
	if err != nil {
		t.Fatalf("generate test key: %v", err)
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
		t.Fatalf("create test certificate: %v", err)
	}
	return string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}))
}

// 未来时钟证书：部署照常完成，但 NotBefore > now 时必须「证书尚未生效」
// 告警留痕（RecordAuditLog），并登记一次 NotBefore+余量时刻的延迟重载
// （复用证书服务既有定时器族，不新建调度器）。
func TestCertIssuer_deployIssuedCertificate_flagsFutureNotBefore(t *testing.T) {
	// Given：一小时后才生效的证书材料
	jobID, ruleID := seedCertificateJob(t, "downloaded")
	useTemporaryCertDir(t)
	issuer := NewCertIssuer(func() error { return nil })
	notBefore := time.Now().Add(time.Hour)
	notAfter := notBefore.Add(90 * 24 * time.Hour)
	material := issuedCertificate{
		ruleID:     ruleID,
		certPEM:    testCertificatePEMWithWindow(t, notBefore, notAfter),
		keyPEM:     "new-key",
		notAfter:   notAfter,
		providerID: 1,
	}
	scheduled := make(chan time.Duration, 1)
	oldScheduler := notBeforeReloadScheduler
	notBeforeReloadScheduler = func(gotJobID int, gotRuleID string, delay time.Duration) {
		if gotJobID != jobID || gotRuleID != ruleID {
			t.Errorf("reload schedule target=(%d,%q), want (%d,%q)", gotJobID, gotRuleID, jobID, ruleID)
		}
		scheduled <- delay
	}
	t.Cleanup(func() { notBeforeReloadScheduler = oldScheduler })

	// When
	if err := issuer.deployIssuedCertificate(context.Background(), jobID, material); err != nil {
		t.Fatalf("deploy issued certificate: %v", err)
	}

	// Then：登记了一次生效点+余量后的延迟重载（余量 1 分钟口径）
	select {
	case delay := <-scheduled:
		if delay < 59*time.Minute || delay > 62*time.Minute {
			t.Fatalf("reload delay=%v, want NotBefore+余量（约 61 分钟）", delay)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("未来时钟证书未登记生效后延迟重载")
	}
	// And：审计留痕「证书尚未生效」
	var n int
	if err := db.AuditDB.QueryRow(`SELECT COUNT(*) FROM audit_log WHERE action='警告' AND resource='证书任务' AND detail LIKE '%尚未生效%'`).Scan(&n); err != nil {
		t.Fatalf("count not-before audit: %v", err)
	}
	if n != 1 {
		t.Fatalf("not-before audit rows=%d, want 1", n)
	}
}

// 对照形态：NotBefore 已过的正常证书部署不得告警、不得登记延迟重载。
func TestCertIssuer_deployIssuedCertificate_quietWhenNotBeforePast(t *testing.T) {
	// Given：已生效证书材料
	jobID, ruleID := seedCertificateJob(t, "downloaded")
	useTemporaryCertDir(t)
	issuer := NewCertIssuer(func() error { return nil })
	notAfter := time.Now().Add(90 * 24 * time.Hour)
	material := issuedCertificate{
		ruleID:     ruleID,
		certPEM:    testCertificatePEMWithWindow(t, time.Now().Add(-time.Hour), notAfter),
		keyPEM:     "new-key",
		notAfter:   notAfter,
		providerID: 1,
	}
	scheduled := make(chan time.Duration, 1)
	oldScheduler := notBeforeReloadScheduler
	notBeforeReloadScheduler = func(_ int, _ string, delay time.Duration) { scheduled <- delay }
	t.Cleanup(func() { notBeforeReloadScheduler = oldScheduler })

	// When
	if err := issuer.deployIssuedCertificate(context.Background(), jobID, material); err != nil {
		t.Fatalf("deploy issued certificate: %v", err)
	}

	// Then
	select {
	case delay := <-scheduled:
		t.Fatalf("已生效证书登记了延迟重载（delay=%v），want 不登记", delay)
	case <-time.After(200 * time.Millisecond):
	}
	var n int
	if err := db.AuditDB.QueryRow(`SELECT COUNT(*) FROM audit_log WHERE action='警告' AND resource='证书任务' AND detail LIKE '%尚未生效%'`).Scan(&n); err != nil {
		t.Fatalf("count not-before audit: %v", err)
	}
	if n != 0 {
		t.Fatalf("not-before audit rows=%d, want 0（已生效证书不得误报）", n)
	}
}
