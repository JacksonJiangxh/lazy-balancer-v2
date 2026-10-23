package handlers

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/gin-gonic/gin"

	"lazy-balancer-v2/internal/db"
)

// 批量签发在 force=true 下真实越过了 CA 冷却，即使最终只部分成功（或中途暂停/
// 全部失败），审计也必须留下「手动越过 CA 冷却」——原实现只把该片段拼进全成功
// 出口，被清空 ca_available_after 的 waiting_ca 行已经真实发生，事后无法从审计
// 区分是否跳过了 CA 退避。
func TestIssueCertificate_batchForceOverrideAuditedOnPartialExit(t *testing.T) {
	h := newBackupTestHandlers(t)
	initIssueQueue(t)
	// 一个冷却中的合法目标（force 后真入队）+ 一个非法域名目标（必然 failed）。
	seedIssueRule(t, "lb_force_ok", "force-ok.example")
	seedIssueRule(t, "lb_force_bad", "*.wildcard.example")
	if _, err := db.DB.Exec(`INSERT INTO cert_jobs (rule_id,domain,status,ca_available_after,updated_at)
		VALUES ('lb_force_ok','force-ok.example','waiting_ca',datetime('now','+1 hour'),datetime('now','-2 hours'))`); err != nil {
		t.Fatalf("seed cooling job: %v", err)
	}
	router := gin.New()
	router.POST("/certificates/issue", h.IssueCertificate)

	response := httptest.NewRecorder()
	router.ServeHTTP(response, httptest.NewRequest(http.MethodPost, "/certificates/issue?force=true", strings.NewReader(`{"all":true}`)))

	if response.Code != http.StatusOK {
		t.Fatalf("status=%d body=%s, want 200 partial", response.Code, response.Body.String())
	}
	if !strings.Contains(response.Body.String(), `"queued":1`) || !strings.Contains(response.Body.String(), `"failed":1`) {
		t.Fatalf("body=%s, want queued=1 + failed=1", response.Body.String())
	}
	var detail string
	if err := db.AuditDB.QueryRow("SELECT detail FROM audit_log WHERE action='触发签发' ORDER BY id DESC LIMIT 1").Scan(&detail); err != nil {
		t.Fatalf("read issue audit: %v", err)
	}
	if !strings.Contains(detail, "手动越过 CA 冷却") {
		t.Fatalf("audit detail=%q, want 手动越过 CA 冷却（部分成功出口同样留痕）", detail)
	}
	if !strings.Contains(detail, "部分成功") {
		t.Fatalf("audit detail=%q, want partial 结果标签", detail)
	}
}

// 对照：未带 force 时同一形态不越权——全部目标被冷却/非法域名挡住时
// queued=0，审计不得出现越过片段。
func TestIssueCertificate_batchWithoutForceDoesNotClaimOverride(t *testing.T) {
	h := newBackupTestHandlers(t)
	initIssueQueue(t)
	seedIssueRule(t, "lb_noforce_ok", "noforce-ok.example")
	seedIssueRule(t, "lb_noforce_bad", "*.wildcard.example")
	if _, err := db.DB.Exec(`INSERT INTO cert_jobs (rule_id,domain,status,ca_available_after,updated_at)
		VALUES ('lb_noforce_ok','noforce-ok.example','waiting_ca',datetime('now','+1 hour'),datetime('now','-2 hours'))`); err != nil {
		t.Fatalf("seed cooling job: %v", err)
	}
	router := gin.New()
	router.POST("/certificates/issue", h.IssueCertificate)

	response := httptest.NewRecorder()
	router.ServeHTTP(response, httptest.NewRequest(http.MethodPost, "/certificates/issue", strings.NewReader(`{"all":true}`)))

	var detail string
	if err := db.AuditDB.QueryRow("SELECT detail FROM audit_log WHERE action='触发签发' ORDER BY id DESC LIMIT 1").Scan(&detail); err != nil {
		t.Fatalf("read issue audit: %v", err)
	}
	if strings.Contains(detail, "手动越过 CA 冷却") {
		t.Fatalf("status=%d audit detail=%q, want no override fragment without force", response.Code, detail)
	}
}
