package handlers

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"lazy-balancer-v2/internal/db"
	"lazy-balancer-v2/internal/services"
)

// Given 导入已提交（事务落地）但请求 ctx 已被取消——前端超时/用户关页/网关
// 断连的真实形态。
// When 提交后清理（消失规则产物 / 孤儿证书任务行）执行。
// Then 清理必须照常完成：已不在库内的规则私钥、孤儿 cert_jobs 行都要删掉。
// 旧实现直接消费请求 ctx，取消后在 currentRuleIDs 处早退，整段清理一次不执行
// ——数据卷里保留管理员以为已随规则删除的 ACME 私钥。
func TestImportCommitCleanupSurvivesCanceledRequestContext(t *testing.T) {
	newBackupTestHandlers(t)
	certDir := t.TempDir()
	t.Cleanup(services.SetCertDirForTest(certDir))

	// 库中只剩 lb_clean_keep；lb_clean_gone 已被导入整体替换掉。
	if _, err := db.DB.Exec(`
		INSERT INTO lb_rules (caddy_id,name,domain,protocol,listen_port,enabled,enable_tls,tls_source,tls_cert,tls_key) VALUES
		('lb_clean_keep','keep','keep.example.test','http',8180,1,1,'manual','CERT','KEY');
		INSERT INTO cert_jobs (rule_id,domain,status,cert_pem,key_pem) VALUES
		('lb_clean_gone','gone.example.test','issued','CERT','KEY')`); err != nil {
		t.Fatalf("seed rules/jobs: %v", err)
	}
	if err := services.WriteCertFiles("lb_clean_gone", "CERT", "KEY"); err != nil {
		t.Fatalf("write gone rule cert files: %v", err)
	}

	canceled, cancel := context.WithCancel(context.Background())
	cancel() // 请求生命周期已结束（客户端断开）
	session := &configImportSession{
		ctx:                  canceled,
		replaceRuleArtifacts: true,
		existingRuleIDs:      []string{"lb_clean_keep", "lb_clean_gone"},
	}

	// When
	session.cleanupDisappearedRuleArtifacts()

	// Then ① 消失规则的证书/私钥文件已清理
	for _, suffix := range []string{".crt", ".key"} {
		if _, err := os.Stat(filepath.Join(certDir, "lb_clean_gone"+suffix)); err == nil {
			t.Fatalf("消失规则 %s 的私钥材料残留（清理受请求 ctx 取消影响）", "lb_clean_gone"+suffix)
		}
	}
	// Then ② 孤儿 cert_jobs 行已清理
	var orphans int
	if err := db.DB.QueryRow(`SELECT COUNT(*) FROM cert_jobs WHERE rule_id='lb_clean_gone'`).Scan(&orphans); err != nil {
		t.Fatalf("count orphan jobs: %v", err)
	}
	if orphans != 0 {
		t.Fatalf("孤儿证书任务行 %d 条残留（清理被请求取消短路）", orphans)
	}
}
