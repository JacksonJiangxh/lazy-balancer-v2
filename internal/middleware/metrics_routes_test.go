package middleware

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestSetupRouter_registers_authenticated_metrics_dashboard(t *testing.T) {
	// Given
	router := newMiddlewareTestRouter(t)

	// When
	routes := make(map[string]bool)
	for _, route := range router.Routes() {
		routes[route.Method+" "+route.Path] = true
	}

	// Then
	if !routes["GET /api/v1/metrics/dashboard"] {
		t.Fatal("authenticated metrics dashboard route is not registered")
	}
}

// 名称如实反映覆盖面：匿名 → 401；已认证（管理员 API Key）→ 非 401/403
// （此前用例名只承诺「拒绝匿名」，无法证明路由真的可被认证身份使用）。
func TestMetricsDashboard_requiresAuthenticationAndServesAuthenticatedRequest(t *testing.T) {
	router := newMiddlewareTestRouter(t)

	// When 匿名
	response := httptest.NewRecorder()
	router.ServeHTTP(response, httptest.NewRequest(http.MethodGet, "/api/v1/metrics/dashboard", nil))

	// Then 匿名必须 401
	if response.Code != http.StatusUnauthorized {
		t.Fatalf("anonymous status=%d, want %d; body=%s", response.Code, http.StatusUnauthorized, response.Body.String())
	}

	// When 已认证管理员 Key
	key := "lb_sk_metrics-admin-test"
	addClusterRouteTestAPIKey(t, 106, "metrics-admin", "admin", key)
	request := httptest.NewRequest(http.MethodGet, "/api/v1/metrics/dashboard", nil)
	request.Header.Set("X-API-Key", key)
	response = httptest.NewRecorder()
	router.ServeHTTP(response, request)

	// Then 认证身份必须被放行到 handler（401/403 说明守卫/路由接线错了）
	if response.Code == http.StatusUnauthorized || response.Code == http.StatusForbidden {
		t.Fatalf("authenticated status=%d, want non-401/403; body=%s", response.Code, response.Body.String())
	}
}
