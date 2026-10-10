package services

import (
	"testing"
)

// SetDefaultProxyPorts 注入后渲染层应跟随（ISSUE #7）：兜底站监听口、跳转
// Location 的自引用端口判定均取部署默认口；非法值忽略保出厂默认。
func TestSetDefaultProxyPorts_overridesRenderingDefaults(t *testing.T) {
	t.Cleanup(func() { SetDefaultProxyPorts(80, 443) })

	// When
	SetDefaultProxyPorts(8080, 8443)

	// Then
	if got := DefaultHTTPPort(); got != 8080 {
		t.Fatalf("DefaultHTTPPort() = %d, want 8080", got)
	}
	if got := DefaultHTTPSPort(); got != 8443 {
		t.Fatalf("DefaultHTTPSPort() = %d, want 8443", got)
	}
}

func TestSetDefaultProxyPorts_ignoresInvalidValues(t *testing.T) {
	SetDefaultProxyPorts(80, 443)
	t.Cleanup(func() { SetDefaultProxyPorts(80, 443) })

	// When: 0/负数/越界均忽略（渲染出 :0 比默认口危险得多）
	SetDefaultProxyPorts(0, 70000)

	// Then
	if got := DefaultHTTPPort(); got != 80 {
		t.Fatalf("invalid http port leaked: %d, want 80", got)
	}
	if got := DefaultHTTPSPort(); got != 443 {
		t.Fatalf("invalid https port leaked: %d, want 443", got)
	}
}

// 兜底站与跳转路由落在部署 HTTP 默认口；HTTPS 默认口非出厂值时 Location 带
// 显式端口号 —— 未改端口时逐字节等于旧硬编码行为。
func TestHTTPSRedirectLocation_followsDefaultHTTPSPort(t *testing.T) {
	SetDefaultProxyPorts(80, 443)
	t.Cleanup(func() { SetDefaultProxyPorts(80, 443) })

	if got := httpsRedirectLocation(443); got != "https://{http.request.host}{http.request.uri}" {
		t.Fatalf("出厂 443 应省略端口号，got %q", got)
	}
	if got := httpsRedirectLocation(8443); got != "https://{http.request.host}:8443{http.request.uri}" {
		t.Fatalf("非默认口应带端口号，got %q", got)
	}

	// We：HTTPS 默认口改 8443 后，8443 规则跳转不再自引用端口
	SetDefaultProxyPorts(80, 8443)
	if got := httpsRedirectLocation(8443); got != "https://{http.request.host}{http.request.uri}" {
		t.Fatalf("默认口调整为 8443 后应省略端口号，got %q", got)
	}
	if got := httpsRedirectLocation(443); got != "https://{http.request.host}:443{http.request.uri}" {
		t.Fatalf("非默认口应带端口号，got %q", got)
	}
}

// 兜底站监听口跟随 HTTP_PORT。
func TestGenerateCaddyConfig_defaultSiteFollowsHTTPPort(t *testing.T) {
	SetDefaultProxyPorts(8080, 8443)
	t.Cleanup(func() { SetDefaultProxyPorts(80, 443) })

	useTemporaryCertDir(t)
	_, database := newClusterTestService(t)
	seedGenerationRule(t, database, "lb_port_default", false)

	generated := generateCaddyConfigFromStore(database)
	if message, failed := generated[caddyConfigGenerationErrorKey].(string); failed {
		t.Fatalf("generate config: %s", message)
	}

	apps := mustMap(t, generated["apps"], "apps")
	httpApp := mustMap(t, apps["http"], "http app")
	servers := mustMap(t, httpApp["servers"], "servers")
	if _, ok := servers["http_8080"]; !ok {
		t.Fatalf("HTTP_PORT=8080 时兜底站应在 http_8080，servers=%v", keysOfMap(servers))
	}
	if _, ok := servers["http_80"]; ok {
		t.Fatalf("HTTP_PORT=8080 时不应再出现 http_80")
	}
}

func keysOfMap(m map[string]interface{}) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	return keys
}
