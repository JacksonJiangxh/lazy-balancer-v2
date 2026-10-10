package services

import (
	"fmt"
	"testing"
)

// upstreamHostPlanOf 构建 HTTP 处理链并投影回源 Host 计划：
// host = reverse_proxy headers.request.set.Host；override = lb_upstream_host 处理器（无则 nil）。
func upstreamHostPlanOf(t *testing.T, rule SingleRuleConfig, upstreams []UpstreamConfig) (host []string, override map[string]interface{}) {
	t.Helper()
	chain, err := buildHTTPHandleChain(rule, upstreams)
	if err != nil {
		t.Fatalf("buildHTTPHandleChain: %v", err)
	}
	for _, raw := range chain {
		entry, ok := raw.(map[string]interface{})
		if !ok {
			continue
		}
		switch entry["handler"] {
		case "lb_upstream_host":
			override = entry
		case "reverse_proxy":
			headers, ok := entry["headers"].(map[string]interface{})
			if !ok {
				continue
			}
			request, ok := headers["request"].(map[string]interface{})
			if !ok {
				continue
			}
			set, ok := request["set"].(map[string]interface{})
			if !ok {
				continue
			}
			if hosts, ok := set["Host"].([]string); ok {
				host = hosts
			}
		}
	}
	return host, override
}

// reverseProxyServerNameOf 返回 reverse_proxy transport.tls.server_name（无 TLS 段返回 nil）。
func reverseProxyServerNameOf(t *testing.T, rule SingleRuleConfig, upstreams []UpstreamConfig) interface{} {
	t.Helper()
	chain, err := buildHTTPHandleChain(rule, upstreams)
	if err != nil {
		t.Fatalf("buildHTTPHandleChain: %v", err)
	}
	for _, raw := range chain {
		entry, ok := raw.(map[string]interface{})
		if !ok || entry["handler"] != "reverse_proxy" {
			continue
		}
		transport, ok := entry["transport"].(map[string]interface{})
		if !ok {
			return nil
		}
		tls, ok := transport["tls"].(map[string]interface{})
		if !ok {
			return nil
		}
		return tls["server_name"]
	}
	return nil
}

// Given: 上游未设置自定义回源 Host 且规则级后端域名为空（全回退态）
// When: 构建 HTTP 处理链
// Then: Host 下发 {http.reverse_proxy.upstream.hostport}（每上游用自身地址），
// 不发射 lb_upstream_host 处理器
func TestUpstreamHostFallback_usesHostportPlaceholder(t *testing.T) {
	rule := SingleRuleConfig{CaddyID: "lb_uh_fallback", Protocol: "http", ListenPort: 80}
	upstreams := []UpstreamConfig{
		{Host: "10.0.0.1", Port: 8080, Weight: 1, Enabled: true},
		{Host: "10.0.0.2", Port: 8080, Weight: 1, Enabled: true},
	}

	host, override := upstreamHostPlanOf(t, rule, upstreams)
	if len(host) != 1 || host[0] != "{http.reverse_proxy.upstream.hostport}" {
		t.Fatalf("host=%v; want [{http.reverse_proxy.upstream.hostport}]", host)
	}
	if override != nil {
		t.Fatalf("lb_upstream_host must not be emitted in full-fallback mode: %#v", override)
	}
}

// Given: 规则级后端域名非空（全统一态）
// When: 构建 HTTP 处理链
// Then: Host 为规则级静态值（现状语义保持），不发射处理器
func TestUpstreamHostRuleLevelStatic(t *testing.T) {
	rule := SingleRuleConfig{CaddyID: "lb_uh_rule", Protocol: "http", ListenPort: 80, HostHeader: "backend.internal"}
	upstreams := []UpstreamConfig{
		{Host: "10.0.0.1", Port: 8080, Weight: 1, Enabled: true},
		{Host: "10.0.0.2", Port: 8080, Weight: 1, Enabled: true},
	}

	host, override := upstreamHostPlanOf(t, rule, upstreams)
	if len(host) != 1 || host[0] != "backend.internal" {
		t.Fatalf("host=%v; want [backend.internal]", host)
	}
	if override != nil {
		t.Fatalf("lb_upstream_host must not be emitted for uniform value: %#v", override)
	}
}

// Given: 全部上游自定义了同一回源 Host（规则级为空）
// When: 构建 HTTP 处理链
// Then: 折叠为静态统一值（无需处理器）
func TestUpstreamHostAllCustomSameValueFoldsToStatic(t *testing.T) {
	rule := SingleRuleConfig{CaddyID: "lb_uh_same", Protocol: "http", ListenPort: 80}
	upstreams := []UpstreamConfig{
		{Host: "10.0.0.1", Port: 8080, Weight: 1, Enabled: true, HostHeader: "origin.example.com"},
		{Host: "10.0.0.2", Port: 8080, Weight: 1, Enabled: true, HostHeader: "origin.example.com"},
	}

	host, override := upstreamHostPlanOf(t, rule, upstreams)
	if len(host) != 1 || host[0] != "origin.example.com" {
		t.Fatalf("host=%v; want [origin.example.com]", host)
	}
	if override != nil {
		t.Fatalf("uniform custom value must fold to static: %#v", override)
	}
}

// Given: 部分上游自定义回源 Host、部分回退（混合态）
// When: 构建 HTTP 处理链
// Then: Host 走 {lb.upstream_host}，处理器映射仅收录自定义上游（键=dial），
// 回退上游由处理器未命中兜底回自身地址
func TestUpstreamHostMixedPartialOverride(t *testing.T) {
	rule := SingleRuleConfig{CaddyID: "lb_uh_mixed", Protocol: "http", ListenPort: 80}
	upstreams := []UpstreamConfig{
		{Host: "10.0.0.1", Port: 8080, Weight: 1, Enabled: true, HostHeader: "origin-a.example.com"},
		{Host: "10.0.0.2", Port: 8080, Weight: 1, Enabled: true},
	}

	host, override := upstreamHostPlanOf(t, rule, upstreams)
	if len(host) != 1 || host[0] != "{lb.upstream_host}" {
		t.Fatalf("host=%v; want [{lb.upstream_host}]", host)
	}
	if override == nil {
		t.Fatal("lb_upstream_host handler must be emitted in mixed mode")
	}
	if override["handler"] != "lb_upstream_host" {
		t.Fatalf("handler=%v", override["handler"])
	}
	hosts, ok := override["hosts"].(map[string]string)
	if !ok {
		t.Fatalf("hosts payload type=%T", override["hosts"])
	}
	if len(hosts) != 1 || hosts["10.0.0.1:8080"] != "origin-a.example.com" {
		t.Fatalf("hosts=%v; want only 10.0.0.1:8080→origin-a.example.com", hosts)
	}
}

// Given: 上游间自定义值不同，且规则级后端域名存在（兜底值参与有效集合）
// When: 构建 HTTP 处理链
// Then: 处理器映射收录全部覆盖项（含规则级兜底的上游），键为 net.JoinHostPort 口径
func TestUpstreamHostMixedDistinctValuesWithRuleFallback(t *testing.T) {
	rule := SingleRuleConfig{CaddyID: "lb_uh_distinct", Protocol: "http", ListenPort: 80, HostHeader: "base.internal"}
	upstreams := []UpstreamConfig{
		{Host: "10.0.0.1", Port: 8080, Weight: 1, Enabled: true, HostHeader: "a.internal"},
		{Host: "10.0.0.2", Port: 8080, Weight: 1, Enabled: true},
		{Host: "2001:db8::1", Port: 8443, Weight: 1, Enabled: true, HostHeader: "v6.internal"},
	}

	host, override := upstreamHostPlanOf(t, rule, upstreams)
	if len(host) != 1 || host[0] != "{lb.upstream_host}" {
		t.Fatalf("host=%v; want [{lb.upstream_host}]", host)
	}
	if override == nil {
		t.Fatal("lb_upstream_host handler must be emitted in mixed mode")
	}
	hosts, ok := override["hosts"].(map[string]string)
	if !ok {
		t.Fatalf("hosts payload type=%T", override["hosts"])
	}
	want := map[string]string{
		"10.0.0.1:8080":      "a.internal",
		"10.0.0.2:8080":      "base.internal", // 未自定义 → 规则级兜底（覆盖项入表）
		"[2001:db8::1]:8443": "v6.internal",   // IPv6 键 = net.JoinHostPort 口径
	}
	if len(hosts) != len(want) {
		t.Fatalf("hosts=%v; want %v", hosts, want)
	}
	for key, value := range want {
		if hosts[key] != value {
			t.Fatalf("hosts[%q]=%q; want %q (all=%v)", key, hosts[key], value, hosts)
		}
	}
}

// Given: 混合态且存在 HTTPS 上游
// When: 构建 HTTP 处理链
// Then: TLS server_name 走 {lb.upstream_sni}（逐上游惰性解析，SNI 无端口）
func TestUpstreamHostMixedTLSsniLazyPlaceholder(t *testing.T) {
	rule := SingleRuleConfig{CaddyID: "lb_uh_sni_mixed", Protocol: "http", ListenPort: 80}
	upstreams := []UpstreamConfig{
		{Host: "10.0.0.1", Port: 8443, Weight: 1, Enabled: true, Protocol: "https", HostHeader: "origin-a.example.com"},
		{Host: "10.0.0.2", Port: 8443, Weight: 1, Enabled: true, Protocol: "https"},
	}

	serverName := reverseProxyServerNameOf(t, rule, upstreams)
	if serverName != "{lb.upstream_sni}" {
		t.Fatalf("server_name=%v; want {lb.upstream_sni}", serverName)
	}
}

// Given: 统一静态回源 Host 且存在 HTTPS 上游
// When: 构建 HTTP 处理链
// Then: server_name 与 Host 同源（上游级统一值时不再回落到空的规则级域名）
func TestUpstreamHostUniformTLSsniFollowsHost(t *testing.T) {
	rule := SingleRuleConfig{CaddyID: "lb_uh_sni_same", Protocol: "http", ListenPort: 80}
	upstreams := []UpstreamConfig{
		{Host: "10.0.0.1", Port: 8443, Weight: 1, Enabled: true, Protocol: "https", HostHeader: "origin.example.com"},
		{Host: "10.0.0.2", Port: 8443, Weight: 1, Enabled: true, Protocol: "https", HostHeader: "origin.example.com"},
	}

	serverName := reverseProxyServerNameOf(t, rule, upstreams)
	if serverName != "origin.example.com" {
		t.Fatalf("server_name=%v; want origin.example.com", serverName)
	}
}

// Given: 统一静态回源 Host 带端口且存在 HTTPS 上游
// When: 构建 HTTP 处理链
// Then: Host 头保留端口原样、SNI 剥离端口（SNI 不得含端口）
func TestUpstreamHostUniformSNIStripsPort(t *testing.T) {
	rule := SingleRuleConfig{CaddyID: "lb_uh_sni_port", Protocol: "http", ListenPort: 80}
	upstreams := []UpstreamConfig{
		{Host: "10.0.0.1", Port: 8443, Weight: 1, Enabled: true, Protocol: "https", HostHeader: "origin.example.com:8443"},
	}

	host, _ := upstreamHostPlanOf(t, rule, upstreams)
	if len(host) != 1 || host[0] != "origin.example.com:8443" {
		t.Fatalf("host=%v; want [origin.example.com:8443]", host)
	}
	if serverName := reverseProxyServerNameOf(t, rule, upstreams); serverName != "origin.example.com" {
		t.Fatalf("server_name=%v; want origin.example.com (port stripped)", serverName)
	}
}

// Given: 全回退态且存在 HTTPS 上游
// When: 构建 HTTP 处理链
// Then: server_name 维持现状（空串=交给 Caddy 以 dial host 兜底）
func TestUpstreamHostFallbackTLSsniStaysEmpty(t *testing.T) {
	rule := SingleRuleConfig{CaddyID: "lb_uh_sni_fallback", Protocol: "http", ListenPort: 80}
	upstreams := []UpstreamConfig{
		{Host: "10.0.0.1", Port: 8443, Weight: 1, Enabled: true, Protocol: "https"},
	}

	serverName := reverseProxyServerNameOf(t, rule, upstreams)
	if serverName != "" {
		t.Fatalf("server_name=%v; want empty (Caddy dial-host default)", serverName)
	}
}

// Given: DynamicDNS 单上游（保存链强制）且未自定义
// When: 构建 HTTP 处理链
// Then: 全回退占位符（逐解析 IP 用自身地址），不发射混合处理器
func TestUpstreamHostDynamicDNSSingleUpstreamPlaceholder(t *testing.T) {
	rule := SingleRuleConfig{CaddyID: "lb_uh_ddns", Protocol: "http", ListenPort: 80, DynamicDNS: true}
	upstreams := []UpstreamConfig{
		{Host: "backend.example.com", Port: 80, Weight: 1, Enabled: true},
	}

	host, override := upstreamHostPlanOf(t, rule, upstreams)
	if len(host) != 1 || host[0] != "{http.reverse_proxy.upstream.hostport}" {
		t.Fatalf("host=%v; want [{http.reverse_proxy.upstream.hostport}]", host)
	}
	if override != nil {
		t.Fatalf("dynamic DNS single upstream must stay in fallback mode: %#v", override)
	}
}

// Given: 上游级统一回源 Host（规则级为空）且启用主动健康检查
// When: 构建 HTTP 处理链
// Then: 健康检查 Host 与代理请求同源（上游级统一值；健康检查 headers 为
// handler 级，无法逐上游，统一态保持一致性）
func TestUpstreamHostActiveHealthCheckFollowsUniformHost(t *testing.T) {
	rule := SingleRuleConfig{
		CaddyID: "lb_uh_hc", Protocol: "http", ListenPort: 80,
		EnableActiveHealthCheck: true, HealthCheckPath: "/healthz",
	}
	upstreams := []UpstreamConfig{
		{Host: "10.0.0.1", Port: 8080, Weight: 1, Enabled: true, HostHeader: "origin.example.com"},
	}

	chain, err := buildHTTPHandleChain(rule, upstreams)
	if err != nil {
		t.Fatalf("buildHTTPHandleChain: %v", err)
	}
	for _, raw := range chain {
		entry, ok := raw.(map[string]interface{})
		if !ok || entry["handler"] != "reverse_proxy" {
			continue
		}
		hc, ok := entry["health_checks"].(map[string]interface{})
		if !ok {
			t.Fatal("health_checks missing")
		}
		active, ok := hc["active"].(map[string]interface{})
		if !ok {
			t.Fatal("active health check missing")
		}
		headers, ok := active["headers"].(map[string]interface{})
		if !ok {
			t.Fatalf("active.headers missing: %#v", active)
		}
		hosts, ok := headers["Host"].([]string)
		if !ok || len(hosts) != 1 || hosts[0] != "origin.example.com" {
			t.Fatalf("active.headers.Host=%v; want [origin.example.com]", headers["Host"])
		}
		return
	}
	t.Fatal("reverse_proxy not found in chain")
}

// Given: 被禁用的上游带自定义回源 Host（不参与负载池）
// When: 构建 HTTP 处理链
// Then: 计划仅由启用上游决定（禁用行不进入混合判定与映射表）
func TestUpstreamHostDisabledUpstreamIgnored(t *testing.T) {
	rule := SingleRuleConfig{CaddyID: "lb_uh_disabled", Protocol: "http", ListenPort: 80}
	upstreams := []UpstreamConfig{
		{Host: "10.0.0.1", Port: 8080, Weight: 1, Enabled: true},
		{Host: "10.0.0.9", Port: 8080, Weight: 1, Enabled: false, HostHeader: "ghost.internal"},
	}

	host, override := upstreamHostPlanOf(t, rule, upstreams)
	if len(host) != 1 || host[0] != "{http.reverse_proxy.upstream.hostport}" {
		t.Fatalf("host=%v; want [{http.reverse_proxy.upstream.hostport}]", host)
	}
	if override != nil {
		t.Fatalf("disabled upstream must not influence the plan: %#v", override)
	}
}

// pathRuleChainOf 取自定义路由链（@id = <caddyID>_path_<index>）的 handle 列表。
func pathRuleChainOf(t *testing.T, rule SingleRuleConfig, pathIndex int) []interface{} {
	t.Helper()
	routes, _, err := generateHTTPRouteObjects(rule)
	if err != nil {
		t.Fatalf("generateHTTPRouteObjects: %v", err)
	}
	wantID := fmt.Sprintf("%s_path_%d", rule.CaddyID, pathIndex)
	for _, route := range routes {
		if route["@id"] != wantID {
			continue
		}
		handle, ok := route["handle"].([]interface{})
		if !ok {
			t.Fatalf("route %s handle type=%T", wantID, route["handle"])
		}
		return handle
	}
	t.Fatalf("route %s not found", wantID)
	return nil
}

// chainHostPlanOf 从处理链投影回源 Host 下发（同 upstreamHostPlanOf，但作用于链）。
func chainHostPlanOf(t *testing.T, chain []interface{}) (host []string, override map[string]interface{}) {
	t.Helper()
	for _, raw := range chain {
		entry, ok := raw.(map[string]interface{})
		if !ok {
			continue
		}
		switch entry["handler"] {
		case "lb_upstream_host":
			override = entry
		case "reverse_proxy":
			headers, _ := entry["headers"].(map[string]interface{})
			request, _ := headers["request"].(map[string]interface{})
			set, _ := request["set"].(map[string]interface{})
			if hosts, ok := set["Host"].([]string); ok {
				host = hosts
			}
		}
	}
	return host, override
}

// Given: 自定义路由自带上游且其上游配置了回源 Host（2026-10-10 用户裁定）
// When: 渲染该路径规则的代理链
// Then: Host 取该上游的回源 Host（优先于规则级「后端域名」），与主链同口径
func TestPathRuleUpstreamHost_prefersPathUpstreamHost(t *testing.T) {
	rule := SingleRuleConfig{
		CaddyID: "lb_pr_host", Protocol: "http", ListenPort: 80,
		HostHeader: "base.internal", CustomRoutesEnabled: true,
		Upstreams: []UpstreamConfig{
			{Host: "10.0.0.9", Port: 9000, Weight: 1, Enabled: true},
		},
		PathRules: []PathRuleConfig{{
			SortOrder: 0, MatchType: "prefix", Path: "/api",
			Upstreams: []UpstreamConfig{
				{Host: "10.0.0.1", Port: 8080, Weight: 1, Enabled: true, HostHeader: "api.internal"},
			},
		}},
	}

	host, override := chainHostPlanOf(t, pathRuleChainOf(t, rule, 0))
	if len(host) != 1 || host[0] != "api.internal" {
		t.Fatalf("host=%v; want [api.internal]（自定义路由上游回源 Host 优先于规则级）", host)
	}
	if override != nil {
		t.Fatalf("uniform path value must fold to static: %#v", override)
	}
}

// Given: 自定义路由自带上游未配回源 Host，规则级「后端域名」非空
// When: 渲染该路径规则的代理链
// Then: Host 回退规则级（第二级）
func TestPathRuleUpstreamHost_fallsBackToRuleLevel(t *testing.T) {
	rule := SingleRuleConfig{
		CaddyID: "lb_pr_host_fb", Protocol: "http", ListenPort: 80,
		HostHeader: "base.internal", CustomRoutesEnabled: true,
		Upstreams: []UpstreamConfig{
			{Host: "10.0.0.9", Port: 9000, Weight: 1, Enabled: true},
		},
		PathRules: []PathRuleConfig{{
			SortOrder: 0, MatchType: "prefix", Path: "/api",
			Upstreams: []UpstreamConfig{
				{Host: "10.0.0.1", Port: 8080, Weight: 1, Enabled: true},
			},
		}},
	}

	host, _ := chainHostPlanOf(t, pathRuleChainOf(t, rule, 0))
	if len(host) != 1 || host[0] != "base.internal" {
		t.Fatalf("host=%v; want [base.internal]（第二级回退：规则级后端域名）", host)
	}
}

// Given: 自定义路由自带上游未配回源 Host，规则级也为空
// When: 渲染该路径规则的代理链
// Then: Host 走上游自身地址占位符（第三级：回源域名）
func TestPathRuleUpstreamHost_fallsBackToUpstreamDial(t *testing.T) {
	rule := SingleRuleConfig{
		CaddyID: "lb_pr_host_dial", Protocol: "http", ListenPort: 80,
		CustomRoutesEnabled: true,
		Upstreams: []UpstreamConfig{
			{Host: "10.0.0.9", Port: 9000, Weight: 1, Enabled: true},
		},
		PathRules: []PathRuleConfig{{
			SortOrder: 0, MatchType: "prefix", Path: "/api",
			Upstreams: []UpstreamConfig{
				{Host: "10.0.0.1", Port: 8080, Weight: 1, Enabled: true},
			},
		}},
	}

	host, _ := chainHostPlanOf(t, pathRuleChainOf(t, rule, 0))
	if len(host) != 1 || host[0] != "{http.reverse_proxy.upstream.hostport}" {
		t.Fatalf("host=%v; want [{http.reverse_proxy.upstream.hostport}]（第三级回退：上游自身地址）", host)
	}
}

// Given: 自定义路由回退到规则默认上游（upstreams 为空 → 继承主上游），
// 主上游自带回源 Host
// When: 渲染该路径规则的代理链
// Then: 与主链同源——继承后的上游集合照常三级回退（上游自身 host_header 生效）
func TestPathRuleUpstreamHost_inheritedUpstreamsKeepTheirHostHeader(t *testing.T) {
	rule := SingleRuleConfig{
		CaddyID: "lb_pr_host_inherit", Protocol: "http", ListenPort: 80,
		HostHeader: "base.internal", CustomRoutesEnabled: true,
		Upstreams: []UpstreamConfig{
			{Host: "10.0.0.1", Port: 8080, Weight: 1, Enabled: true, HostHeader: "origin.internal"},
		},
		PathRules: []PathRuleConfig{{
			SortOrder: 0, MatchType: "prefix", Path: "/api",
			Upstreams: []UpstreamConfig{
				{Host: "10.0.0.1", Port: 8080, Weight: 1, Enabled: true, HostHeader: "origin.internal"},
			},
		}},
	}

	host, _ := chainHostPlanOf(t, pathRuleChainOf(t, rule, 0))
	if len(host) != 1 || host[0] != "origin.internal" {
		t.Fatalf("host=%v; want [origin.internal]", host)
	}
}

// Given: 自定义路由 + 链式回退策略，路径上游携带回源 Host
// When: 渲染该路径规则的链
// Then: chain_proxy 的车道 host 取该上游的回源 Host（与 reverse_proxy 链同源口径）
func TestPathRuleUpstreamHost_chainFallbackHonoursHostHeader(t *testing.T) {
	rule := SingleRuleConfig{
		CaddyID: "lb_pr_host_chain", Protocol: "http", ListenPort: 80,
		HostHeader: "base.internal", CustomRoutesEnabled: true,
		Upstreams: []UpstreamConfig{
			{Host: "10.0.0.9", Port: 9000, Weight: 1, Enabled: true},
		},
		PathRules: []PathRuleConfig{{
			SortOrder: 0, MatchType: "prefix", Path: "/api",
			Upstreams: []UpstreamConfig{
				{Host: "10.0.0.1", Port: 8080, Weight: 1, Enabled: true, HostHeader: "api.internal"},
			},
		}},
	}
	rule.Strategy = "chain_fallback"

	var lanes []interface{}
	for _, raw := range pathRuleChainOf(t, rule, 0) {
		entry, ok := raw.(map[string]interface{})
		if !ok || entry["handler"] != "chain_proxy" {
			continue
		}
		lanes, _ = entry["upstreams"].([]interface{})
	}
	if len(lanes) != 1 {
		t.Fatalf("chain_proxy lanes=%v; want exactly one（自定义路由单上游）", lanes)
	}
	lane, ok := lanes[0].(map[string]interface{})
	if !ok {
		t.Fatalf("lane payload type=%T", lanes[0])
	}
	if lane["host"] != "api.internal" {
		t.Fatalf("lane host=%v; want api.internal（chain 车道同三级回退口径）", lane["host"])
	}
}
