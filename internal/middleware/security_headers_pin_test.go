package middleware

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

// U7c-2（第 66 轮）：面板页面与 API 响应缺 X-Content-Type-Options/
// X-Frame-Options——点击劫持表面。基线钉：全局中间件恒施加 nosniff+DENY。

func TestSetupRouter_setsSecurityHeadersOnAllResponses(t *testing.T) {
	// Given 完整路由（匿名 /health 即可观测）。
	router := newMiddlewareTestRouter(t)

	// When
	rec := httptest.NewRecorder()
	router.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/health", nil))

	// Then
	if rec.Code != http.StatusOK {
		t.Fatalf("/health status=%d, want 200", rec.Code)
	}
	if got := rec.Header().Get("X-Content-Type-Options"); got != "nosniff" {
		t.Fatalf("X-Content-Type-Options=%q, want nosniff", got)
	}
	if got := rec.Header().Get("X-Frame-Options"); got != "DENY" {
		t.Fatalf("X-Frame-Options=%q, want DENY", got)
	}
}
