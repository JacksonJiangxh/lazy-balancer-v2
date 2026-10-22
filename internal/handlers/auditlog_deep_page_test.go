package handlers

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/gin-gonic/gin"
)

// 审计列表深翻页防护：阈值内按页码分页，超阈值 400 并给出筛选指引
// （不静默 clamp，避免「越翻越慢还看不到真实位置」）。
func TestListAuditLogs_deepPageRejectedWithGuidance(t *testing.T) {
	router, _ := newAuditLogRouter(t)
	gin.SetMode(gin.TestMode)

	deep := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/audit-logs?page=501&page_size=20", nil)
	router.ServeHTTP(deep, req)
	if deep.Code != http.StatusBadRequest {
		t.Fatalf("deep page status=%d body=%s, want 400", deep.Code, deep.Body.String())
	}
	if !strings.Contains(deep.Body.String(), "筛选") {
		t.Fatalf("deep page message must guide filtering: %s", deep.Body.String())
	}

	ok := httptest.NewRecorder()
	req2 := httptest.NewRequest(http.MethodGet, "/audit-logs?page=2&page_size=20", nil)
	router.ServeHTTP(ok, req2)
	if ok.Code != http.StatusOK {
		t.Fatalf("page=2 status=%d, want 200", ok.Code)
	}
}
