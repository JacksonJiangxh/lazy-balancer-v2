package handlers

import (
	"encoding/json"
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

// 分页语义统一：非整数 400（不得静默回默认）、越界钳到上限（不得静默回默认，
// 让「传 500 只回 20 条」有可预期结果）、深翻页仍显式 400。
func TestListAuditLogs_paginationSemanticsUnified(t *testing.T) {
	router, _ := newAuditLogRouter(t)
	get := func(query string) *httptest.ResponseRecorder {
		recorder := httptest.NewRecorder()
		router.ServeHTTP(recorder, httptest.NewRequest(http.MethodGet, "/audit-logs?"+query, nil))
		return recorder
	}

	clamped := get("page_size=500")
	if clamped.Code != http.StatusOK {
		t.Fatalf("page_size=500 status=%d body=%s, want 200", clamped.Code, clamped.Body.String())
	}
	var payload struct {
		Data struct {
			PageSize int `json:"page_size"`
		} `json:"data"`
	}
	if err := json.Unmarshal(clamped.Body.Bytes(), &payload); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	if payload.Data.PageSize != 100 {
		t.Errorf("page_size=500 → %d, want clamp to cap 100（不得回默认 20）", payload.Data.PageSize)
	}

	for _, query := range []string{"page_size=abc", "page=abc"} {
		if rec := get(query); rec.Code != http.StatusBadRequest {
			t.Errorf("%s status=%d, want 400（非整数分页参数不得静默回默认）", query, rec.Code)
		}
	}

	if rec := get("page=501&page_size=20"); rec.Code != http.StatusBadRequest {
		t.Errorf("page=501 status=%d, want 400（深翻页显式拒绝）", rec.Code)
	}
}
