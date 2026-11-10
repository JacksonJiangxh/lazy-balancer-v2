package middleware

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

// 面板页面与 API 响应缺 X-Content-Type-Options/
// X-Frame-Options——点击劫持表面。基线钉：全局中间件恒施加 nosniff+DENY。

// 名称如实反映覆盖面：四类代表性响应（健康检查、/ui 壳、公开 branding API、
// 匿名 API 拒绝）都必须带 nosniff+DENY——此前只验 /health 一条。
func TestSetupRouter_setsSecurityHeadersOnRepresentativeResponses(t *testing.T) {
	router := newMiddlewareTestRouter(t)
	cases := []struct {
		name string
		path string
	}{
		{"health", "/health"},
		{"ui-shell", "/ui/index.html"},
		{"public-branding", "/api/v1/branding"},
		{"anonymous-api", "/api/v1/rules"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			rec := httptest.NewRecorder()
			router.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, tc.path, nil))
			if got := rec.Header().Get("X-Content-Type-Options"); got != "nosniff" {
				t.Fatalf("GET %s X-Content-Type-Options=%q, want nosniff", tc.path, got)
			}
			if got := rec.Header().Get("X-Frame-Options"); got != "DENY" {
				t.Fatalf("GET %s X-Frame-Options=%q, want DENY", tc.path, got)
			}
		})
	}
}

// /ui 挂载壳 index.html 与根路径缓存策略对齐——此前
// 仅 GET / 显式 no-cache，/ui 壳由 http.FileServer 直出只有
// （浏览器启发式缓存 10% 规则：升级后旧壳引用已删哈希资产 → 白屏）。
func TestSetupRouter_uiShellIndexNoCacheHeader(t *testing.T) {
	// Given 完整路由（测试 StaticDir 为空目录：/ui 壳响应码非 200，但缓存头
	// 由全局静态中间件在静态处理器之前设置，与响应码无关；裸 /ui 是 gin
	// 尾斜杠 301 重定向，不经中间件链，不在断言面）。
	router := newMiddlewareTestRouter(t)

	for _, path := range []string{"/ui/", "/ui/index.html"} {
		// When
		rec := httptest.NewRecorder()
		router.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, path, nil))

		// Then：壳页面恒 no-cache（与 GET / 同策略）
		if got := rec.Header().Get("Cache-Control"); got != "no-cache" {
			t.Fatalf("GET %s Cache-Control=%q, want no-cache", path, got)
		}
	}

	// And 回归形状：/ui/assets/ 哈希资产保持 immutable 长缓存不变
	rec := httptest.NewRecorder()
	router.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/ui/assets/app-abc123.js", nil))
	if got := rec.Header().Get("Cache-Control"); got != "public, max-age=31536000, immutable" {
		t.Fatalf("GET /ui/assets/... Cache-Control=%q, want immutable", got)
	}
}
