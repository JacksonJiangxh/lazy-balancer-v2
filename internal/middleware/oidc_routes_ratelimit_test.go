package middleware

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// /auth/oidc/status 公开端点此前无限流——每请求 1 次 global_config 读+
// JSON 反序列化，分布式探测可放大 DB 读。独立宽桶 60/min/IP（不消耗登录额度）。
func TestSetupRouter_oidcStatusRouteRateLimited(t *testing.T) {
	// Given
	router := newMiddlewareTestRouter(t)
	withIsolatedRateLimitBuckets(t)

	// When：连续 61 次 OIDC 状态查询
	var last *httptest.ResponseRecorder
	for range 61 {
		last = httptest.NewRecorder()
		router.ServeHTTP(last, httptest.NewRequest(http.MethodGet, "/api/v1/auth/oidc/status", nil))
	}

	// Then：第 61 次被限流拦截（未配置 OIDC 时前 60 次为 200 enabled=false）
	if last.Code != http.StatusTooManyRequests || !strings.Contains(last.Body.String(), "OIDC 状态查询过于频繁") {
		t.Fatalf("61st oidc status: status=%d body=%s, want 429 rate limited", last.Code, last.Body.String())
	}

	// And：独立桶——登录端点不受影响
	request := httptest.NewRequest(http.MethodPost, "/api/v1/auth/login", strings.NewReader(`{}`))
	request.Header.Set("Content-Type", "application/json")
	response := httptest.NewRecorder()
	router.ServeHTTP(response, request)
	if response.Code == http.StatusTooManyRequests {
		t.Fatalf("login after oidc-status exhaustion must not be limited (separate bucket): %s", response.Body.String())
	}
}

// /auth/oidc/login 是未认证公开跳转端点（state 表写入+可能的
// discovery 回源），与 /auth/login 同威胁模型——必须共用同一 IP 限流桶
// （10 次/分钟），否则可被线速打 state 表与 IdP 发现请求。
func TestSetupRouter_oidcLoginRouteRateLimited(t *testing.T) {
	// Given
	router := newMiddlewareTestRouter(t)
	withIsolatedRateLimitBuckets(t)

	// When：连续 11 次 OIDC 登录跳转请求
	var last *httptest.ResponseRecorder
	for range 11 {
		last = httptest.NewRecorder()
		router.ServeHTTP(last, httptest.NewRequest(http.MethodGet, "/api/v1/auth/oidc/login", nil))
	}

	// Then：第 11 次被限流拦截（未配置 OIDC 时前 10 次为 404，不干扰判定）
	if last.Code != http.StatusTooManyRequests || !strings.Contains(last.Body.String(), "登录尝试过于频繁") {
		t.Fatalf("11th oidc login status=%d body=%s, want 429 rate limited", last.Code, last.Body.String())
	}

	// And：与 /auth/login 同桶——oidc/login 耗尽后密码登录同样 429
	request := httptest.NewRequest(http.MethodPost, "/api/v1/auth/login", strings.NewReader(`{}`))
	request.Header.Set("Content-Type", "application/json")
	response := httptest.NewRecorder()
	router.ServeHTTP(response, request)
	if response.Code != http.StatusTooManyRequests {
		t.Fatalf("password login after oidc exhaustion status=%d body=%s, want 429 (shared bucket)", response.Code, response.Body.String())
	}
}
