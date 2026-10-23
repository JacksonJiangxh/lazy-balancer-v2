package services

import (
	"database/sql"
	"errors"
	"testing"
	"time"
)

// 部署失败的状态回写本身失败（瞬时 DB 故障/CAS 冲突）时，任务行与内存调度
// 必须仍可收敛：窗口列由独立簿记 UPDATE 推进（30s 补扫只收非 NULL 窗口），
// 重试 timer 与 DB 状态解耦登记。否则行停在「downloaded + 窗口 NULL」，
// 补扫/对账/恢复都不收，HTTPS 规则静默不可用直到重启或升主。

const deploymentWritebackRuleID = "lb_deploy_writeback"

func seedDeploymentWritebackJob(t *testing.T) (database *sql.DB, jobID int) {
	t.Helper()
	_, database = newClusterTestService(t)
	if _, err := database.Exec(`INSERT INTO lb_rules (caddy_id,name,domain,protocol,listen_port,enabled,enable_tls,tls_source)
		VALUES (?, 'deploy-writeback', 'writeback.example.com', 'http', 8443, 1, 1, 'acme_dns')`, deploymentWritebackRuleID); err != nil {
		t.Fatalf("seed rule: %v", err)
	}
	result, err := database.Exec(`INSERT INTO cert_jobs (rule_id,domain,status,ca_provider_id,cert_pem,key_pem,expires_at,deployment_available_after,updated_at)
		VALUES (?, 'writeback.example.com', 'downloaded', 0, 'cert', 'key', datetime('now','+60 days'), NULL, datetime('now'))`, deploymentWritebackRuleID)
	if err != nil {
		t.Fatalf("seed job: %v", err)
	}
	id, err := result.LastInsertId()
	if err != nil {
		t.Fatalf("read job id: %v", err)
	}
	return database, int(id)
}

func deploymentTestMaterial() issuedCertificate {
	return issuedCertificate{
		ruleID:     deploymentWritebackRuleID,
		certPEM:    "cert",
		keyPEM:     "key",
		notAfter:   time.Now().Add(60 * 24 * time.Hour),
		providerID: 0,
	}
}

// waitDeploymentRetry 等待异步重试登记（deploymentFailed 起独立 goroutine）。
func waitDeploymentRetry(t *testing.T, scheduled <-chan int) int {
	t.Helper()
	select {
	case id := <-scheduled:
		return id
	case <-time.After(2 * time.Second):
		t.Fatal("deployment failure did not register a retry")
		return 0
	}
}

func TestCertIssuer_deploymentFailed_registersRetryWhenWritebackFails(t *testing.T) {
	// Given：部署失败回写本身失败（瞬时 DB 故障/CAS 冲突）
	database, jobID := seedDeploymentWritebackJob(t)
	original := deploymentFailureWriteback
	deploymentFailureWriteback = func(jobTransitionExecutor, int, []string, string, map[string]any) error {
		return errors.New("database is locked")
	}
	t.Cleanup(func() { deploymentFailureWriteback = original })

	scheduled := make(chan int, 1)
	issuer := &CertIssuer{deploymentRetry: func(id int, _ issuedCertificate, _ time.Duration) error {
		scheduled <- id
		return nil
	}}

	// When
	err := issuer.deploymentFailed(jobID, deploymentTestMaterial(), "写文件失败", errors.New("disk full"))

	// Then：仍返回部署类错误
	var deployErr *certificateDeploymentError
	if !errors.As(err, &deployErr) {
		t.Fatalf("error=%v, want certificateDeploymentError", err)
	}

	// 重试 timer 与回写解耦：必须照常登记（回调会重读行状态，胜者已推进时自然 no-op）
	if got := waitDeploymentRetry(t, scheduled); got != jobID {
		t.Fatalf("scheduled job=%d, want %d", got, jobID)
	}

	// 窗口列由独立簿记 UPDATE 推进——补扫的 downloaded 分支只收非 NULL 窗口
	var status, message string
	var availableAfter sql.NullString
	if err := database.QueryRow("SELECT status, COALESCE(message,''), deployment_available_after FROM cert_jobs WHERE id=?", jobID).Scan(&status, &message, &availableAfter); err != nil {
		t.Fatalf("read job: %v", err)
	}
	if !availableAfter.Valid || availableAfter.String == "" {
		t.Fatalf("deployment_available_after=%v, want advanced by best-effort writeback", availableAfter)
	}
	if status != "downloaded" {
		t.Fatalf("status=%q, want downloaded", status)
	}
	if len(message) == 0 {
		t.Fatal("message empty, want deployment failure reason persisted")
	}
}

func TestCertIssuer_deploymentFailedFrom_acceptsIssuedForFastPath(t *testing.T) {
	// 快速重部署链的进度写（issued→downloaded）可能未落库，失败回写必须能
	// 从 issued 收敛；常规部署链保持原 from 集合（并发胜者已提交 issued 时
	// 不得把成功结果拉回部署生命周期）。
	database, jobID := seedDeploymentWritebackJob(t)
	if _, err := database.Exec("UPDATE cert_jobs SET status='issued', deployment_available_after=NULL WHERE id=?", jobID); err != nil {
		t.Fatalf("mark issued: %v", err)
	}

	scheduled := make(chan int, 2)
	issuer := &CertIssuer{deploymentRetry: func(id int, _ issuedCertificate, _ time.Duration) error {
		scheduled <- id
		return nil
	}}

	// When：常规链（不含 issued）——CAS 冲突，行不得被改动
	_ = issuer.deploymentFailed(jobID, deploymentTestMaterial(), "重载失败", errors.New("caddy 503"))

	var status string
	var availableAfter sql.NullString
	if err := database.QueryRow("SELECT status, deployment_available_after FROM cert_jobs WHERE id=?", jobID).Scan(&status, &availableAfter); err != nil {
		t.Fatalf("read job: %v", err)
	}
	if status != "issued" || availableAfter.Valid {
		t.Fatalf("status=%q window=%v, want issued with NULL window（并发胜者状态不得被拉回）", status, availableAfter)
	}

	// When：快速重部署链（含 issued）——必须回落到可重试的部署生命周期
	_ = issuer.deploymentFailedFrom(jobID, deploymentTestMaterial(), "重载失败", errors.New("caddy 503"), deploymentFailureFromStatuses(true))

	if err := database.QueryRow("SELECT status, deployment_available_after FROM cert_jobs WHERE id=?", jobID).Scan(&status, &availableAfter); err != nil {
		t.Fatalf("read job: %v", err)
	}
	if status != "downloaded" {
		t.Fatalf("status=%q, want downloaded after fast-path failure writeback", status)
	}
	if !availableAfter.Valid || availableAfter.String == "" {
		t.Fatalf("deployment_available_after=%v, want retry window", availableAfter)
	}
}

func TestCertificateService_rescanPicksUpNullDeploymentWindowAfterSettle(t *testing.T) {
	// Given：部署失败回写未落库（窗口 NULL）且已过沉降阈值
	database, jobID := seedDeploymentWritebackJob(t)
	if _, err := database.Exec("UPDATE cert_jobs SET updated_at=datetime('now','-1 hour') WHERE id=?", jobID); err != nil {
		t.Fatalf("age job: %v", err)
	}
	service := NewCertificateService()
	resetCertificateServiceForTest(t)
	scheduled := make(chan int, 4)
	service.deploymentRetry = func(id int, _ issuedCertificate, _ time.Duration) error {
		scheduled <- id
		return nil
	}

	// When
	rescheduled, err := service.rescanDroppedDeploymentRetries()

	// Then：必须被补扫接管
	if err != nil {
		t.Fatalf("rescan: %v", err)
	}
	if rescheduled != 1 {
		t.Fatalf("rescheduled=%d, want 1", rescheduled)
	}
	if got := waitDeploymentRetry(t, scheduled); got != jobID {
		t.Fatalf("scheduled job=%d, want %d", got, jobID)
	}

	// Given：同一行退回「窗口 NULL 且刚更新」——部署正在主路径执行的正常形态
	if _, err := database.Exec("UPDATE cert_jobs SET deployment_available_after=NULL, updated_at=datetime('now') WHERE id=?", jobID); err != nil {
		t.Fatalf("reset window: %v", err)
	}

	// When：沉降阈值内补扫
	rescheduled, err = service.rescanDroppedDeploymentRetries()

	// Then：不得与主部署路径抢同一任务
	if err != nil {
		t.Fatalf("rescan fresh: %v", err)
	}
	if rescheduled != 0 {
		t.Fatalf("rescheduled=%d, want 0（沉降阈值内的 NULL 窗口属主路径执行中）", rescheduled)
	}
	select {
	case id := <-scheduled:
		t.Fatalf("fresh NULL-window job %d scheduled too early", id)
	case <-time.After(50 * time.Millisecond):
	}
}
