package handlers

// disabled 永久拒绝状态码、批量零目标文案。

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/gin-gonic/gin"

	"lazy-balancer-v2/internal/db"
	"lazy-balancer-v2/internal/services"
)

// Given：downloaded 任务（证书已签发落库，仅部署未完成，已过 2 分钟守卫）。
// When：手动重试。
// Then：走部署重排快速路径——任务保持 downloaded、证书材料不丢、
// deployment_available_after 被推到 now；不得转 queued 触发整轮重签。
func TestRetryCertJob_downloadedJobReschedulesDeployment(t *testing.T) {
	h := newBackupTestHandlers(t)
	service := services.NewCertificateService()
	t.Cleanup(service.Stop)
	services.ResetCAQueueManagerForTest()
	services.InitCAQueueManager(func() error { return nil }, t.TempDir())
	services.GetCAQueueManager().Start()
	t.Cleanup(services.ResetCAQueueManagerForTest)
	if _, err := db.DB.Exec(`INSERT INTO lb_rules (caddy_id,name,protocol,domain,listen_port,enabled,enable_tls,tls_source)
		VALUES ('lb_dl','dl','http','dl.example.test',8080,1,1,'acme_dns');
		INSERT INTO cert_jobs (rule_id,domain,status,message,cert_pem,key_pem,updated_at,deployment_available_after)
		VALUES ('lb_dl','dl.example.test','downloaded','部署失败 [attempt=1/10]: boom','CERT-PEM','KEY-PEM',datetime('now','-10 minutes'),datetime('now','+5 minutes'))`); err != nil {
		t.Fatalf("seed downloaded job: %v", err)
	}
	router := gin.New()
	router.POST("/jobs/:id/retry", h.RetryCertJob)
	response := httptest.NewRecorder()
	router.ServeHTTP(response, httptest.NewRequest(http.MethodPost, "/jobs/1/retry", nil))

	if response.Code != http.StatusOK {
		t.Fatalf("status=%d body=%s, want 200", response.Code, response.Body.String())
	}
	if !strings.Contains(response.Body.String(), "Deployment retry triggered") {
		t.Fatalf("body=%s, want 部署重排语义", response.Body.String())
	}
	var status, message, certPEM, keyPEM string
	var availableAfter time.Time
	if err := db.DB.QueryRow(`SELECT status, COALESCE(message,''), COALESCE(cert_pem,''), COALESCE(key_pem,''), deployment_available_after
		FROM cert_jobs WHERE id=1`).Scan(&status, &message, &certPEM, &keyPEM, &availableAfter); err != nil {
		t.Fatalf("read job: %v", err)
	}
	if status != "downloaded" {
		t.Fatalf("status=%q, want downloaded（转 queued 会丢弃已签发证书并整轮重签）", status)
	}
	if certPEM != "CERT-PEM" || keyPEM != "KEY-PEM" {
		t.Fatalf("materials=(%q,%q), want 证书材料保留", certPEM, keyPEM)
	}
	if !strings.Contains(message, "部署") {
		t.Fatalf("message=%q, want 部署重排口径", message)
	}
	if time.Until(availableAfter) > 5*time.Second {
		t.Fatalf("deployment_available_after=%v, want 已推到 now（立即重试）", availableAfter)
	}
}

// Given：downloaded 任务但证书材料缺失（脏行/材料未落库）。
// When：手动重试。
// Then：无快速路径可走——维持原语义转 queued 重新签发。
func TestRetryCertJob_downloadedJobWithoutMaterialStillRequeues(t *testing.T) {
	h := newBackupTestHandlers(t)
	services.ResetCAQueueManagerForTest()
	services.InitCAQueueManager(func() error { return nil }, t.TempDir())
	services.GetCAQueueManager().Start()
	t.Cleanup(services.ResetCAQueueManagerForTest)
	if _, err := db.DB.Exec(`INSERT INTO lb_rules (caddy_id,name,protocol,domain,listen_port,enabled,enable_tls,tls_source)
		VALUES ('lb_dl2','dl2','http','dl2.example.test',8080,1,1,'acme_dns');
		INSERT INTO cert_jobs (rule_id,domain,status,updated_at)
		VALUES ('lb_dl2','dl2.example.test','downloaded',datetime('now','-10 minutes'))`); err != nil {
		t.Fatalf("seed downloaded job without material: %v", err)
	}
	router := gin.New()
	router.POST("/jobs/:id/retry", h.RetryCertJob)
	response := httptest.NewRecorder()
	router.ServeHTTP(response, httptest.NewRequest(http.MethodPost, "/jobs/1/retry", nil))

	if response.Code != http.StatusOK {
		t.Fatalf("status=%d body=%s, want 200（重新入队成功）", response.Code, response.Body.String())
	}
	if !strings.Contains(response.Body.String(), "Retry triggered") {
		t.Fatalf("body=%s, want 重新入队语义", response.Body.String())
	}
	// 已知覆盖缺口：不校验 DB 终态——队列管理器可能在响应后毫秒级消费任务并
	// 推进/打回（与 task_certjob_trigger 测试同口径）。「未走部署快速路径」仅由
	// 响应文案（Retry triggered 而非 Deployment retry triggered）确定；DB 侧
	// 断言由 acme_regression_01 的队列执行用例与 certjobs 部署生命周期用例承载。
}

// Given：证书服务已停止，downloaded 任务仍满足部署重排的 DB 条件。
// When/Then：端点必须返回 409 且不得写「已触发部署重试」的成功审计。
func TestRetryCertJob_downloadedJobRejectsStoppedService(t *testing.T) {
	h := newBackupTestHandlers(t)
	if _, err := db.DB.Exec(`INSERT INTO lb_rules (caddy_id,name,protocol,domain,listen_port,enabled,enable_tls,tls_source)
		VALUES ('lb_stopped','stopped','http','stopped.example.test',8080,1,1,'acme_dns');
		INSERT INTO cert_jobs (rule_id,domain,status,message,cert_pem,key_pem,updated_at,deployment_available_after)
		VALUES ('lb_stopped','stopped.example.test','downloaded','等待部署','CERT-PEM','KEY-PEM',datetime('now','-10 minutes'),datetime('now','+5 minutes'))`); err != nil {
		t.Fatalf("seed downloaded job: %v", err)
	}
	service := services.NewCertificateService()
	service.Stop()
	t.Cleanup(service.Stop)
	router := gin.New()
	router.POST("/jobs/:id/retry", h.RetryCertJob)
	response := httptest.NewRecorder()

	router.ServeHTTP(response, httptest.NewRequest(http.MethodPost, "/jobs/1/retry", nil))

	if response.Code != http.StatusConflict {
		t.Fatalf("status=%d body=%s, want 409 stopped certificate service", response.Code, response.Body.String())
	}
	if strings.Contains(response.Body.String(), "Deployment retry triggered") {
		t.Fatalf("body=%s, stopped service must not report a triggered deployment", response.Body.String())
	}
	var successAudits int
	if err := db.AuditDB.QueryRow(`SELECT COUNT(*) FROM audit_log WHERE action='重试' AND resource='证书任务'`).Scan(&successAudits); err != nil {
		t.Fatalf("count retry audits: %v", err)
	}
	if successAudits != 0 {
		t.Fatalf("success audits=%d, want 0 for refused deployment retry", successAudits)
	}
}

// Given：库中没有任何启用状态的 ACME 规则。
// When：批量签发 all=true。
// Then：409 且原因不得为空串（此前响应以冒号结尾，审计 detail 同样空）。
func TestIssueCertificate_batchAllWithNoTargetsExplainsEmptyScope(t *testing.T) {
	h := newBackupTestHandlers(t)
	initIssueQueue(t)
	router := gin.New()
	router.POST("/certificates/issue", h.IssueCertificate)
	response := httptest.NewRecorder()
	router.ServeHTTP(response, httptest.NewRequest(http.MethodPost, "/certificates/issue", strings.NewReader(`{"all":true}`)))

	if response.Code != http.StatusConflict {
		t.Fatalf("status=%d body=%s, want 409", response.Code, response.Body.String())
	}
	var payload struct {
		Message string `json:"message"`
	}
	if err := json.Unmarshal(response.Body.Bytes(), &payload); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	if strings.HasSuffix(payload.Message, "：") || strings.TrimSpace(payload.Message) == "" {
		t.Fatalf("message=%q, want 非空原因（零目标须单列文案）", payload.Message)
	}
	if !strings.Contains(payload.Message, "ACME") {
		t.Fatalf("message=%q, want 点名 ACME 规则缺失", payload.Message)
	}
}
