package middleware

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// /branding 是公开无鉴权端点：每请求至少 1 次 stat+序列化，文件指纹变化后的
// 首个通过门控的请求还会同步做多次 DB 写。挂独立宽桶（120/min/IP）防止匿名
// 线速刷放大该写面，且不消耗登录/其他桶额度。
func TestSetupRouter_brandingRouteRateLimited(t *testing.T) {
	// Given
	router := newMiddlewareTestRouter(t)
	withIsolatedRateLimitBuckets(t)

	// When：连续 121 次品牌配置查询
	var last *httptest.ResponseRecorder
	for range 121 {
		last = httptest.NewRecorder()
		router.ServeHTTP(last, httptest.NewRequest(http.MethodGet, "/api/v1/branding", nil))
	}

	// Then：第 121 次被限流拦截
	if last.Code != http.StatusTooManyRequests || !strings.Contains(last.Body.String(), "品牌配置查询过于频繁") {
		t.Fatalf("121st branding: status=%d body=%s, want 429 rate limited", last.Code, last.Body.String())
	}

	// And：独立桶——登录端点不受影响
	request := httptest.NewRequest(http.MethodPost, "/api/v1/auth/login", strings.NewReader(`{}`))
	request.Header.Set("Content-Type", "application/json")
	response := httptest.NewRecorder()
	router.ServeHTTP(response, request)
	if response.Code == http.StatusTooManyRequests {
		t.Fatalf("login after branding exhaustion must not be limited (separate bucket): %s", response.Body.String())
	}
}
