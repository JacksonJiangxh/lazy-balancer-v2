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

// 跳转遮蔽复核的比对方基准跟随 HTTP_PORT：改 HTTP_PORT=8080 后，监听 8080 的
// 规则才作为遮蔽方压制兄弟域名的 HTTPS 跳转（旧硬编码 80 会漏判，跳转被静默
// 覆盖）。ISSUE #7。
func TestGenerateCaddyConfig_redirectShadowFollowsDefaultHTTPPort(t *testing.T) {
	SetDefaultProxyPorts(8080, 8443)
	t.Cleanup(func() { SetDefaultProxyPorts(80, 443) })

	useTemporaryCertDir(t)
	_, database := newClusterTestService(t)

	// 规则 A：TLS + HTTP 跳转，监听 8443 —— 会在 HTTP 默认口生成 terminal 跳转。
	if _, err := database.Exec(`INSERT INTO lb_rules (caddy_id,name,protocol,domain,listen_port,strategy,health_check_path,health_check_interval,enabled,enable_tls,tls_http_redirect)
		VALUES ('lb_redirect','lb_redirect','http','redirect.test',8443,'weighted_round_robin','',10,1,1,1)`); err != nil {
		t.Fatalf("seed redirect rule: %v", err)
	}
	if _, err := database.Exec("INSERT INTO upstreams (rule_id,host,port,enabled,protocol) VALUES ('lb_redirect','127.0.0.1',9000,1,'http')"); err != nil {
		t.Fatalf("seed redirect upstream: %v", err)
	}
	// 规则 B：同域名直接监听 HTTP 默认口（8080）—— 遮蔽方。
	if _, err := database.Exec(`INSERT INTO lb_rules (caddy_id,name,protocol,domain,listen_port,strategy,health_check_path,health_check_interval,enabled)
		VALUES ('lb_plain','lb_plain','http','redirect.test',8080,'weighted_round_robin','',10,1)`); err != nil {
		t.Fatalf("seed plain rule: %v", err)
	}
	if _, err := database.Exec("INSERT INTO upstreams (rule_id,host,port,enabled,protocol) VALUES ('lb_plain','127.0.0.1',9001,1,'http')"); err != nil {
		t.Fatalf("seed plain upstream: %v", err)
	}

	generated := generateCaddyConfigFromStore(database)
	if message, failed := generated[caddyConfigGenerationErrorKey].(string); failed {
		t.Fatalf("generate config: %s", message)
	}

	// 8080 服务器不应包含指向 redirect.test 的跳转路由（被同域名 8080 规则遮蔽）。
	apps := mustMap(t, generated["apps"], "apps")
	httpApp := mustMap(t, apps["http"], "http app")
	servers := mustMap(t, httpApp["servers"], "servers")
	server := mustMap(t, servers["http_8080"], "http_8080")
	routes, _ := server["routes"].([]interface{})
	for _, route := range routes {
		routeMap, ok := route.(map[string]interface{})
		if !ok {
			continue
		}
		hosts, ok := routeMap["match"].([]interface{})
		if !ok || len(hosts) == 0 {
			continue
		}
		firstMatch, ok := hosts[0].(map[string]interface{})
		if !ok {
			continue
		}
		if matched, ok := firstMatch["host"].([]string); ok && len(matched) == 1 && matched[0] == "redirect.test" {
			if _, isRedirect := routeMap["handle"].([]interface{}); isRedirect {
				// 同域名 8080 规则自身是反代，不是 static_response 跳转；跳转若出现即为遮蔽漏判。
				for _, h := range routeMap["handle"].([]interface{}) {
					if handler, ok := h.(map[string]interface{}); ok && handler["handler"] == "static_response" {
						t.Fatalf("HTTP_PORT=8080 时同域名 8080 规则应遮蔽 8443 跳转，但 8080 仍生成跳转路由: %v", handler)
					}
				}
			}
		}
	}
}
