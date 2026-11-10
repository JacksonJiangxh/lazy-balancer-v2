package handlers

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/gin-gonic/gin"

	"lazy-balancer-v2/internal/db"
)

// 对照：未带 force 时同一形态不越权——全部目标被冷却/非法域名挡住时
// queued=0，审计不得出现越过片段。
// 正面证据（force + partial 留痕）由 certificates_regression_03_test.go 的
// TestIssueCertificate_batchForcePartialKeepsOverrideAudit 覆盖，本文件不再重复
// 同一夹具（双份夹具只会随实现漂移）。
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
