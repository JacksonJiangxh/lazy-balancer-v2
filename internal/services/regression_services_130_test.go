package services

// 文件、续期配置读侧直读库值。

import (
	"context"
	"os"
	"testing"
	"time"

	"lazy-balancer-v2/internal/db"
	"lazy-balancer-v2/internal/models"
)

// Given：库内证书有效且证书文件与库内容一致，但私钥文件被写坏（崩溃窗口：
// 先 rename cert、后 rename key 之间断电）。
// When：Issue 走快速路径。
// Then：快速路径判据必须同时比对 key 文件——内容不一致时重新部署双文件，
// 不得因「证书文件一致」直接确认 issued 而把不匹配的 key 永久留在磁盘。
func TestCertIssuer_Issue_fastPath_repairsMismatchedKeyFile(t *testing.T) {
	jobID, ruleID := seedCertificateJob(t, "downloaded")
	useTemporaryCertDir(t)
	certPEM := testCertificatePEM(t, time.Now().Add(90*24*time.Hour))
	const keyPEM = "stored-key-pem"
	if _, err := db.DB.Exec("UPDATE cert_jobs SET cert_pem=?, key_pem=?, ca_provider_id=1 WHERE id=?", certPEM, keyPEM, jobID); err != nil {
		t.Fatalf("seed certificate material: %v", err)
	}
	if _, err := db.DB.Exec("UPDATE lb_rules SET ca_provider_id=1 WHERE caddy_id=?", ruleID); err != nil {
		t.Fatalf("seed rule CA provider: %v", err)
	}
	// 证书文件与库内一致，私钥文件是陈旧内容（崩溃窗口残留）。
	if err := WriteCertFiles(ruleID, certPEM, "stale-key-on-disk"); err != nil {
		t.Fatalf("seed mismatched key file: %v", err)
	}
	reloads := 0
	issuer := NewCertIssuer(func() error {
		reloads++
		return nil
	})

	// When
	err := issuer.Issue(context.Background(), jobID, ruleID, "example.com", models.CAProvider{ID: 1})

	// Then
	if err != nil {
		t.Fatalf("Issue fast path: %v", err)
	}
	certPath, keyPath := CertFilePaths(ruleID)
	diskCert, certErr := os.ReadFile(certPath)
	diskKey, keyErr := os.ReadFile(keyPath)
	if certErr != nil || keyErr != nil {
		t.Fatalf("read deployed files: cert=%v key=%v", certErr, keyErr)
	}
	if string(diskKey) != keyPEM {
		t.Fatalf("key file=%q, want %q（私钥不匹配必须重新部署）", diskKey, keyPEM)
	}
	if string(diskCert) != certPEM {
		t.Fatalf("cert file=%q, want 库内证书", diskCert)
	}
	if reloads != 1 {
		t.Fatalf("reloads=%d, want 1（重新部署后须重载一次）", reloads)
	}
	var status string
	if err := db.DB.QueryRow("SELECT status FROM cert_jobs WHERE id=?", jobID).Scan(&status); err != nil {
		t.Fatal(err)
	}
	if status != "issued" {
		t.Fatalf("status=%q, want issued", status)
	}
}

// Given：库内 cert_renewal_attempts 为有效值。
// When：GetCertRenewalAttempts 读取。
// Then：直读库值（不得被写死兜底常量覆盖）。
func TestGetCertRenewalAttempts_readsStoredValue(t *testing.T) {
	oldDB := db.DB
	if err := db.Initialize(t.TempDir()); err != nil {
		t.Fatalf("initialize db: %v", err)
	}
	t.Cleanup(func() {
		_ = db.Close()
		db.DB = oldDB
	})
	if _, err := db.DB.Exec("UPDATE global_config SET cert_renewal_attempts=9 WHERE id=1"); err != nil {
		t.Fatalf("seed attempts: %v", err)
	}
	if got := GetCertRenewalAttempts(); got != 9 {
		t.Fatalf("GetCertRenewalAttempts=%d, want 9（读侧直读库值）", got)
	}
	if _, err := db.DB.Exec("UPDATE global_config SET cert_renewal_days=17 WHERE id=1"); err != nil {
		t.Fatalf("seed days: %v", err)
	}
	if got := GetCertRenewalDays(); got != 17 {
		t.Fatalf("GetCertRenewalDays=%d, want 17", got)
	}
}
