package handlers

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"lazy-balancer-v2/internal/db"
	"lazy-balancer-v2/internal/services"
)

// 导入后「规则仍在但已无任何可用证书材料」的残留 ACME 证书/私钥文件必须
// 被清理（导入剪枝只动 DB 行；与 DeleteRule/orphanACME「失去材料即删私钥」
// 同约定）。手动证书材料在库、或存在域名适用的 issued/downloaded 任务材料的
// 规则不受影响。
func TestCleanupRulesWithoutUsableCertMaterial(t *testing.T) {
	newBackupTestHandlers(t)
	certDir := t.TempDir()
	t.Cleanup(services.SetCertDirForTest(certDir))

	if _, err := db.DB.Exec(`
		INSERT INTO lb_rules (caddy_id,name,domain,protocol,listen_port,enabled,enable_tls,tls_source,tls_cert,tls_key) VALUES
		('lb_mat_manual','manual','manual.example.test','http',8080,1,1,'manual','CERT','KEY'),
		('lb_mat_lost','lost','lost.example.test','http',8081,1,0,'', '', ''),
		('lb_mat_kept','kept','kept.example.test','http',8082,1,1,'acme_dns','',''),
		('lb_mat_olddom','olddom','new.example.test','http',8083,1,1,'acme_dns','','');
		INSERT INTO cert_jobs (rule_id,domain,status,cert_pem,key_pem) VALUES
		('lb_mat_kept','kept.example.test','issued','CERT','KEY'),
		('lb_mat_olddom','old.example.test','issued','CERT','KEY')`); err != nil {
		t.Fatalf("seed rules/jobs: %v", err)
	}
	for _, id := range []string{"lb_mat_manual", "lb_mat_lost", "lb_mat_kept", "lb_mat_olddom"} {
		if err := services.WriteCertFiles(id, "CERT", "KEY"); err != nil {
			t.Fatalf("write cert files for %s: %v", id, err)
		}
	}

	// When
	cleaned := cleanupRulesWithoutUsableCertMaterial(context.Background())

	// Then：失去材料的规则（关 TLS / 任务材料域名不适用）文件被清理；
	// manual 有证与材料适用的规则保留
	if cleaned != 2 {
		t.Fatalf("cleaned=%d, want 2（lb_mat_lost + lb_mat_olddom）", cleaned)
	}
	exists := func(id string) bool {
		_, certErr := os.Stat(filepath.Join(certDir, id+".crt"))
		_, keyErr := os.Stat(filepath.Join(certDir, id+".key"))
		return certErr == nil || keyErr == nil
	}
	for id, want := range map[string]bool{
		"lb_mat_manual": true,
		"lb_mat_kept":   true,
		"lb_mat_lost":   false,
		"lb_mat_olddom": false,
	} {
		if got := exists(id); got != want {
			t.Fatalf("rule %s files exist=%v, want %v", id, got, want)
		}
	}
}
