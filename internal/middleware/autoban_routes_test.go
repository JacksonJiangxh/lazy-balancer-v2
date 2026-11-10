package middleware

import (
	"strings"
	"testing"
)

// 「手动立即执行」端点已废除（调度唯一前提=业务启用）。契约必须钉在**生产
// 路由表**上：在自建裸 router 上打不存在的路径只会命中 gin 默认 404，端点被
// 重新挂载时该用例仍然绿。同时给出正向控制（配置读写/状态路由仍在），避免
// 路由表整体为空时负向断言空转。
func TestSetupRouter_autobanRunRouteRemoved(t *testing.T) {
	router := newMiddlewareTestRouter(t)

	routes := make(map[string]bool, len(router.Routes()))
	for _, route := range router.Routes() {
		routes[route.Method+" "+route.Path] = true
	}

	// Given 正向控制：自动封禁配置/状态路由必须已注册。
	for _, want := range []string{
		"GET /api/v1/security/autoban",
		"PUT /api/v1/security/autoban",
		"GET /api/v1/security/autoban/status",
	} {
		if !routes[want] {
			t.Fatalf("正向控制失败：生产路由缺 %q（路由表未装载，负向断言无意义）", want)
		}
	}

	// Then 任何方法都不得再挂 /security/autoban/run。
	for key := range routes {
		if strings.HasSuffix(key, " /api/v1/security/autoban/run") {
			t.Fatalf("废弃端点仍注册：%q", key)
		}
	}
}
