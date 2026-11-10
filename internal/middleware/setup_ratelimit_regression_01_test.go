package middleware

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// 防止初始化接口被暴力尝试创建管理员（POST 建号是爆破相关面，留登录桶）。
func TestSetupRouter_authSetupWriteRouteRateLimited(t *testing.T) {
	// Given
	router := newMiddlewareTestRouter(t)
	withIsolatedRateLimitBuckets(t)
	body := `{"username":"adminuser","password":"adminpass123"}`

	// When：连续 11 次创建管理员请求
	var last *httptest.ResponseRecorder
	for i := 0; i < 11; i++ {
		request := httptest.NewRequest(http.MethodPost, "/api/v1/auth/setup", strings.NewReader(body))
		request.Header.Set("Content-Type", "application/json")
		last = httptest.NewRecorder()
		router.ServeHTTP(last, request)
	}

	// Then：第 11 次被限流拦截
	if last.Code != http.StatusTooManyRequests || !strings.Contains(last.Body.String(), "登录尝试过于频繁") {
		t.Fatalf("11th setup status=%d body=%s, want 429 rate limited", last.Code, last.Body.String())
	}
}

// GET /auth/setup 是登录页挂载即调用的只读探测：限流必须按独立宽桶（60/min/IP）
// 计，不消耗登录预算——否则同一出口 IP 打开 10 次登录页就把登录桶耗尽，正常
// 用户随即收到 429「登录尝试过于频繁」。
func TestSetupRouter_setupStatusUsesIndependentBucket(t *testing.T) {
	// Given
	router := newMiddlewareTestRouter(t)
	withIsolatedRateLimitBuckets(t)

	// When：先把登录桶（10/min）打满
	for range 10 {
		request := httptest.NewRequest(http.MethodPost, "/api/v1/auth/login", strings.NewReader(`{}`))
		request.Header.Set("Content-Type", "application/json")
		router.ServeHTTP(httptest.NewRecorder(), request)
	}

	// Then：只读探测不受登录桶影响
	statusRequest := httptest.NewRequest(http.MethodGet, "/api/v1/auth/setup", nil)
	statusResponse := httptest.NewRecorder()
	router.ServeHTTP(statusResponse, statusRequest)
	if statusResponse.Code == http.StatusTooManyRequests {
		t.Fatalf("setup status after login bucket exhaustion must not be limited (separate bucket): %s", statusResponse.Body.String())
	}

	// And：独立桶自身仍限流（60/min/IP，第 61 次 429）——探测面不允许无限刷
	var last *httptest.ResponseRecorder
	for range 60 {
		last = httptest.NewRecorder()
		router.ServeHTTP(last, httptest.NewRequest(http.MethodGet, "/api/v1/auth/setup", nil))
	}
	if last.Code != http.StatusTooManyRequests || !strings.Contains(last.Body.String(), "初始化状态查询过于频繁") {
		t.Fatalf("61st setup status: status=%d body=%s, want 429 rate limited", last.Code, last.Body.String())
	}
}
