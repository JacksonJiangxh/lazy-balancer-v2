package middleware

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/gin-gonic/gin"
)

// U7c-5（第 66 轮审计）：CORS 反射任意 Origin 是有意设计（Authorization 头
// 认证、无 cookie 凭据向量，反射 Origin 不构成渗透面）——本测试为基线钉：
// 反射 Origin + Vary: Origin + 恒不带凭据头，防回归为通配/凭据形态。
func TestCORSMiddleware_reflectsOriginWithoutCredentials(t *testing.T) {
	gin.SetMode(gin.TestMode)
	router := gin.New()
	router.Use(corsMiddleware())
	router.POST("/api/v1/pin", func(c *gin.Context) { c.Status(http.StatusNoContent) })

	const origin = "https://arbitrary.example"

	// 预检 OPTIONS：204 + 反射 Origin + Vary + 无凭据头
	req := httptest.NewRequest(http.MethodOptions, "/api/v1/pin", nil)
	req.Header.Set("Origin", origin)
	req.Header.Set("Access-Control-Request-Method", http.MethodPost)
	rec := httptest.NewRecorder()
	router.ServeHTTP(rec, req)
	if rec.Code != http.StatusNoContent {
		t.Fatalf("preflight status=%d, want 204", rec.Code)
	}
	assertCORSBaseline(t, rec, origin)

	// 实际请求同口径
	req2 := httptest.NewRequest(http.MethodPost, "/api/v1/pin", nil)
	req2.Header.Set("Origin", origin)
	rec2 := httptest.NewRecorder()
	router.ServeHTTP(rec2, req2)
	if rec2.Code != http.StatusNoContent {
		t.Fatalf("actual status=%d, want 204", rec2.Code)
	}
	assertCORSBaseline(t, rec2, origin)
}

func assertCORSBaseline(t *testing.T, rec *httptest.ResponseRecorder, origin string) {
	t.Helper()
	if got := rec.Header().Get("Access-Control-Allow-Origin"); got != origin {
		t.Fatalf("Access-Control-Allow-Origin=%q, want reflection of %q（任意 Origin 反射为有意设计）", got, origin)
	}
	if got := rec.Header().Get("Vary"); got != "Origin" {
		t.Fatalf("Vary=%q, want Origin（缓存按 Origin 区分）", got)
	}
	if got := rec.Header().Get("Access-Control-Allow-Credentials"); got != "" {
		t.Fatalf("Access-Control-Allow-Credentials=%q, must stay absent（无凭据向量是安全前提）", got)
	}
}
