package services

import (
	"encoding/json"
	"fmt"
	"strings"
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
// Host 值兼容两种形态：直接构造的 []string 与 JSON 往返后的 []interface{}。
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
			switch hosts := set["Host"].(type) {
			case []string:
				host = hosts
			case []interface{}:
				for _, value := range hosts {
					if text, ok := value.(string); ok {
						host = append(host, text)
					}
				}
			}
		}
	}
	return host, override
}

// ── 自定义路由上游的回源 Host（2026-10-10 用户裁定）────────────────────────
// 规则设定不新增任何字段：回源 Host 全在内部逻辑里。判定分两类：
//   ① 地址在「上游服务器」列表里 → 按该地址所属规则的上游集合整体解析
//      （逐上游 host_header > 规则级 host_header > 自身地址）；
//   ② 地址不在列表里 → 只有规则级一档，仍空用自身地址。
// 两类都不透传客户端 Host。

// scenarioRule 用户举例的规则：域名 A.com、规则级回源域名 B.com、三条上游
// （IP 无逐上游 Host、C.com/D.com 各带自己的逐上游 Host）。
func scenarioRule(pathRules []PathRuleConfig) SingleRuleConfig {
	return SingleRuleConfig{
		CaddyID: "lb_pr_scenario", Protocol: "http", Domain: "A.com", ListenPort: 80,
		HostHeader: "B.com", CustomRoutesEnabled: true,
		Upstreams: []UpstreamConfig{
			{Host: "192.168.42.2", Port: 40080, Weight: 1, Enabled: true},
			{Host: "C.com", Port: 443, Weight: 1, Enabled: true, Protocol: "https", HostHeader: "C.com"},
			{Host: "D.com", Port: 443, Weight: 1, Enabled: true, Protocol: "https", HostHeader: "D.com"},
		},
		PathRules: pathRules,
	}
}

// Given: 上游服务器列表里 C.com 自带逐上游回源 Host，自定义路由 /img/ 指向它
// When: 解析该路径上游的回源 Host 计划（/img/ → https://C.com）
// Then: 用 C.com 自己的逐上游值（第一级，压过规则级 B.com）
func TestPathRuleUpstreamHost_listedUpstreamKeepsItsOwnHost(t *testing.T) {
	rule := scenarioRule([]PathRuleConfig{{
		SortOrder: 0, MatchType: "prefix", Path: "/img/",
		Upstreams: []UpstreamConfig{{Host: "C.com", Port: 443, Weight: 1, Enabled: true, Protocol: "https"}},
	}})
	seedPathRuleUpstreamHosts(&rule)

	host, override := chainHostPlanOf(t, pathRuleChainOf(t, rule, 0))
	if len(host) != 1 || host[0] != "C.com" {
		t.Fatalf("host=%v; want [C.com]（逐上游回源 Host）", host)
	}
	if override != nil {
		t.Fatalf("uniform value must fold to static: %#v", override)
	}
}

// Given: 上游服务器列表里 192.168.42.2 的回源 Host 留空，自定义路由 / 指向它
// When: 解析该路径上游的回源 Host 计划
// Then: 回退规则级 B.com（第二级）
func TestPathRuleUpstreamHost_listedUpstreamWithoutHostFallsBackToRule(t *testing.T) {
	rule := scenarioRule([]PathRuleConfig{{
		SortOrder: 0, MatchType: "prefix", Path: "/",
		Upstreams: []UpstreamConfig{{Host: "192.168.42.2", Port: 40080, Weight: 1, Enabled: true}},
	}})
	seedPathRuleUpstreamHosts(&rule)

	host, _ := chainHostPlanOf(t, pathRuleChainOf(t, rule, 0))
	if len(host) != 1 || host[0] != "B.com" {
		t.Fatalf("host=%v; want [B.com]（回退规则级后端域名）", host)
	}
}

// Given: 自定义路由 /api 指向 X.com（不在上游服务器列表里）
// When: 解析该路径上游的回源 Host 计划
// Then: 用规则级 B.com（外部地址只有规则级一档）
func TestPathRuleUpstreamHost_unlistedUpstreamUsesRuleLevelHost(t *testing.T) {
	rule := scenarioRule([]PathRuleConfig{{
		SortOrder: 0, MatchType: "prefix", Path: "/api",
		Upstreams: []UpstreamConfig{{Host: "X.com", Port: 443, Weight: 1, Enabled: true, Protocol: "https"}},
	}})
	seedPathRuleUpstreamHosts(&rule)

	host, _ := chainHostPlanOf(t, pathRuleChainOf(t, rule, 0))
	if len(host) != 1 || host[0] != "B.com" {
		t.Fatalf("host=%v; want [B.com]（不在上游列表 → 规则级）", host)
	}
}

// Given: 规则级后端域名为空（基础设置留空），自定义路由分别指向列表内无逐上游
// Host 的地址与列表外的地址
// When: 解析两条路径的回源 Host 计划
// Then: 都落到「上游自身地址」占位符（第三级），绝不透传客户端 Host
func TestPathRuleUpstreamHost_emptyRuleLevelFallsBackToDial(t *testing.T) {
	rule := scenarioRule([]PathRuleConfig{
		{
			SortOrder: 0, MatchType: "prefix", Path: "/",
			Upstreams: []UpstreamConfig{{Host: "192.168.42.2", Port: 40080, Weight: 1, Enabled: true}},
		},
		{
			SortOrder: 1, MatchType: "prefix", Path: "/api",
			Upstreams: []UpstreamConfig{{Host: "X.com", Port: 443, Weight: 1, Enabled: true, Protocol: "https"}},
		},
	})
	rule.HostHeader = ""
	seedPathRuleUpstreamHosts(&rule)

	for index, want := range []string{"/", "/api"} {
		host, _ := chainHostPlanOf(t, pathRuleChainOf(t, rule, index))
		if len(host) != 1 || host[0] != "{http.reverse_proxy.upstream.hostport}" {
			t.Fatalf("path %s host=%v; want 上游自身地址占位符", want, host)
		}
	}
}

// Given: 存储行里残留着外部（旧版前端/导入负载）写入的 host_header
// When: 解析自定义路由上游
// Then: 该字段被忽略——真相来自上游服务器列表（配置一致性优先，避免脏值生效）
func TestPathRuleUpstreamHost_ignoresPersistedForeignValue(t *testing.T) {
	raw := `[{"address":"X.com","port":443,"weight":1,"protocol":"https","host_header":"evil.internal"}]`
	upstreams, err := decodePathUpstreamsWithResolver(raw, nil, "B.com")
	if err != nil {
		t.Fatalf("decode: %v", err)
	}
	if len(upstreams) != 1 || upstreams[0].HostHeader != "" {
		t.Fatalf("upstreams=%+v; want 行内值被忽略", upstreams)
	}
	// 无解析上下文的调用方（无规则上下文）同样不动该值
	plain, err := decodePathUpstreams(raw)
	if err != nil {
		t.Fatalf("decode plain: %v", err)
	}
	if plain[0].HostHeader != "" {
		t.Fatalf("plain host_header=%q; want empty（行内值不参与渲染）", plain[0].HostHeader)
	}
}

// seedPathRuleUpstreamHosts 复刻渲染期对 path_rules 上游行的内部推导（测试直连
// 渲染入口时用；生产链路由 generateCaddyConfigFromStore 的 pathResolver 完成）——
// 同一份上游集合 + 同一 resolveUpstreamHostPlan，保证测试与生产口径不分叉。
func seedPathRuleUpstreamHosts(rule *SingleRuleConfig) {
	registry := make(map[string]upstreamRow, len(rule.Upstreams))
	for _, u := range rule.Upstreams {
		registry[upstreamHostKey(u.Host, u.Port)] = upstreamRow{
			RuleID: rule.CaddyID, Host: u.Host, Port: u.Port, Weight: u.Weight, Enabled: u.Enabled,
			Protocol: u.Protocol, HostHeader: u.HostHeader,
		}
	}
	resolver := &pathUpstreamHostResolver{
		hoisted: func(host string, port int) (string, bool) {
			if _, ok := registry[upstreamHostKey(host, port)]; !ok {
				return "", false
			}
			plan := resolveUpstreamHostPlan(SingleRuleConfig{HostHeader: rule.HostHeader}, rule.Upstreams)
			return hostPlanValueFor(plan, host, port)
		},
		orphan: func(ruleHostHeader string) string { return strings.TrimSpace(ruleHostHeader) },
	}
	for pathIndex := range rule.PathRules {
		upstreams := rule.PathRules[pathIndex].Upstreams
		for upstreamIndex, u := range upstreams {
			u.HostHeader = strings.TrimSpace(resolver.hostFor(u.Host, u.Port, rule.HostHeader))
			upstreams[upstreamIndex] = u
		}
	}
}

// Given: 用户举例的完整形态——规则级 B.com + 三条上游（IP 无逐上游 Host、
// C.com/D.com 各带自己的逐上游 Host）+ 四条自定义路由（含一条指向列表外的 X.com）
// When: 走真实链路生成配置（DB → pathResolver → 渲染）
// Then: /img/ 回源 Host=C.com、/ 与 /api=B.com、/admin=D.com（全内部推导，
// 规则设定里没有任何回源 Host 字段）
func TestPathRuleUpstreamHost_endToEndScenario(t *testing.T) {
	_, database := newClusterTestService(t)
	seedGenerationRule(t, database, "lb_e2e_host", true)
	if _, err := database.Exec(`UPDATE lb_rules SET domain='A.com', host_header='B.com', listen_port=18471 WHERE caddy_id='lb_e2e_host'`); err != nil {
		t.Fatalf("update rule: %v", err)
	}
	if _, err := database.Exec(`DELETE FROM upstreams WHERE rule_id='lb_e2e_host'`); err != nil {
		t.Fatalf("clear upstreams: %v", err)
	}
	for _, upstream := range []struct {
		host, protocol, hostHeader string
		port                       int
	}{
		{"192.168.42.2", "http", "", 40080},
		{"C.com", "https", "C.com", 443},
		{"D.com", "https", "D.com", 443},
	} {
		if _, err := database.Exec(`INSERT INTO upstreams (rule_id,host,port,enabled,protocol,host_header) VALUES (?,?,?,1,?,?)`,
			"lb_e2e_host", upstream.host, upstream.port, upstream.protocol, upstream.hostHeader); err != nil {
			t.Fatalf("seed upstream %s: %v", upstream.host, err)
		}
	}
	pathRules := []struct {
		path, host, protocol string
		port                 int
	}{
		{"/img/", "C.com", "https", 443},
		{"/", "192.168.42.2", "http", 40080},
		{"/admin", "D.com", "https", 443},
		{"/api", "X.com", "https", 443},
	}
	for index, pathRule := range pathRules {
		upstreamsJSON := fmt.Sprintf(`[{"address":%q,"port":%d,"weight":100,"protocol":%q}]`, pathRule.host, pathRule.port, pathRule.protocol)
		if _, err := database.Exec(`INSERT INTO path_rules (rule_id,sort_order,match_type,path,upstream_path,upstreams_json,updated_at)
			VALUES (?,?, 'prefix', ?, '', ?, datetime('now'))`, "lb_e2e_host", index, pathRule.path, upstreamsJSON); err != nil {
			t.Fatalf("seed path rule %s: %v", pathRule.path, err)
		}
	}

	generated := generateCaddyConfigFromStore(database)
	if message, failed := generated[caddyConfigGenerationErrorKey].(string); failed {
		t.Fatalf("generation failed: %s", message)
	}
	routes := renderedHTTPRoutesFromGenerated(t, generated)

	// 逐路径断言回源 Host（按 @id = lb_e2e_host_path_<index> 定位，与 sort_order 同序）
	wantHosts := []string{"C.com", "B.com", "D.com", "B.com"}
	for index, wantHost := range wantHosts {
		routeID := fmt.Sprintf("lb_e2e_host_path_%d", index)
		route := renderedRouteByID(t, routes, routeID)
		host, _ := chainHostPlanOf(t, renderedHandleChain(t, route))
		if len(host) != 1 || host[0] != wantHost {
			t.Fatalf("path %s（%s）host=%v; want [%s]", pathRules[index].path, routeID, host, wantHost)
		}
	}
}

// renderedRouteByID 按 @id 取生成配置里的路由（JSON 往返后 handle 为 []interface{}）。
func renderedRouteByID(t *testing.T, routes []map[string]interface{}, id string) map[string]interface{} {
	t.Helper()
	for _, route := range routes {
		if route["@id"] == id {
			return route
		}
	}
	t.Fatalf("route %s not found in generated config", id)
	return nil
}

// renderedHandleChain 取路由的处理链（JSON 往返形态）。
func renderedHandleChain(t *testing.T, route map[string]interface{}) []interface{} {
	t.Helper()
	handle, ok := route["handle"].([]interface{})
	if !ok {
		t.Fatalf("route %v handle type=%T", route["@id"], route["handle"])
	}
	return handle
}

func handleChainOf(route map[string]interface{}) []interface{} {
	handle, _ := route["handle"].([]interface{})
	return handle
}

// renderedHTTPRoutesFromGenerated 从整份生成配置里取 HTTP 路由（按端口取全部 server）。
func renderedHTTPRoutesFromGenerated(t *testing.T, generated map[string]interface{}) []map[string]interface{} {
	t.Helper()
	body, err := json.Marshal(generated["apps"])
	if err != nil {
		t.Fatalf("marshal apps: %v", err)
	}
	var apps struct {
		HTTP struct {
			Servers map[string]struct {
				Routes []map[string]interface{} `json:"routes"`
			} `json:"servers"`
		} `json:"http"`
	}
	if err := json.Unmarshal(body, &apps); err != nil {
		t.Fatalf("unmarshal apps: %v", err)
	}
	routes := make([]map[string]interface{}, 0)
	for _, server := range apps.HTTP.Servers {
		routes = append(routes, server.Routes...)
	}
	return routes
}

// Given: 同一地址既出现在 A 规则上游集合里（带逐上游 Host），又作为 B 规则的
// 自定义路由上游（B 自己的上游集合里没有它）
// When: 解析 B 规则该路径的回源 Host
// Then: 按「配置属于 A」取值——跨规则复用一个地址时，回源 Host 跟随该地址的
// 上游定义，而不是当前规则的规则级值
func TestPathRuleUpstreamHost_crossRuleAddressFollowsItsOwner(t *testing.T) {
	registry := map[string]upstreamRow{
		"shared.example:8080": {RuleID: "lb_owner", Host: "shared.example", Port: 8080, Weight: 1, Enabled: true, HostHeader: "owner.internal"},
	}
	resolver := &pathUpstreamHostResolver{
		hoisted: func(host string, port int) (string, bool) {
			row, ok := registry[upstreamHostKey(host, port)]
			if !ok {
				return "", false
			}
			plan := resolveUpstreamHostPlan(SingleRuleConfig{},
				[]UpstreamConfig{{Host: row.Host, Port: row.Port, Weight: 1, Enabled: true, HostHeader: row.HostHeader}})
			return hostPlanValueFor(plan, host, port)
		},
		orphan: func(ruleHostHeader string) string { return strings.TrimSpace(ruleHostHeader) },
	}
	raw := `[{"address":"shared.example","port":8080,"weight":100,"protocol":"http"}]`
	upstreams, err := decodePathUpstreamsWithResolver(raw, resolver, "borrower.internal")
	if err != nil {
		t.Fatalf("decode: %v", err)
	}
	if len(upstreams) != 1 || upstreams[0].HostHeader != "owner.internal" {
		t.Fatalf("upstreams=%+v; want owner.internal（按地址所属上游取值）", upstreams)
	}
}

// Given: 自定义路由 /img/ 指向列表内两台各自带逐上游 Host 的上游（混合态）
// When: 解析该路径的回源 Host 计划
// Then: 走混合态（lb_upstream_host + {lb.upstream_host}），逐上游取值不丢
func TestPathRuleUpstreamHost_mixedUpstreamsFoldIntoOverrideMap(t *testing.T) {
	rule := scenarioRule([]PathRuleConfig{{
		SortOrder: 0, MatchType: "prefix", Path: "/img/",
		Upstreams: []UpstreamConfig{
			{Host: "C.com", Port: 443, Weight: 1, Enabled: true, Protocol: "https"},
			{Host: "D.com", Port: 443, Weight: 1, Enabled: true, Protocol: "https"},
		},
	}})
	seedPathRuleUpstreamHosts(&rule)

	host, override := chainHostPlanOf(t, pathRuleChainOf(t, rule, 0))
	if len(host) != 1 || host[0] != "{lb.upstream_host}" {
		t.Fatalf("host=%v; want [{lb.upstream_host}]", host)
	}
	hosts, ok := override["hosts"].(map[string]string)
	if !ok {
		t.Fatalf("override hosts type=%T", override["hosts"])
	}
	if hosts["C.com:443"] != "C.com" || hosts["D.com:443"] != "D.com" {
		t.Fatalf("override hosts=%v; want 逐上游值各归各位", hosts)
	}
}

// Given: 自定义路由 + chain_fallback 策略，路径上游地址在上游服务器列表里
// When: 渲染该路径的链
// Then: chain_proxy 车道 host 取推导出的回源 Host（与 reverse_proxy 链同口径）
func TestPathRuleUpstreamHost_chainFallbackHonoursDerivedHost(t *testing.T) {
	rule := scenarioRule([]PathRuleConfig{{
		SortOrder: 0, MatchType: "prefix", Path: "/img/",
		Upstreams: []UpstreamConfig{{Host: "C.com", Port: 443, Weight: 1, Enabled: true, Protocol: "https"}},
	}})
	rule.Strategy = "chain_fallback"
	seedPathRuleUpstreamHosts(&rule)

	var lanes []interface{}
	for _, raw := range pathRuleChainOf(t, rule, 0) {
		entry, ok := raw.(map[string]interface{})
		if !ok || entry["handler"] != "chain_proxy" {
			continue
		}
		lanes, _ = entry["upstreams"].([]interface{})
	}
	if len(lanes) != 1 {
		t.Fatalf("chain_proxy lanes=%v; want one", lanes)
	}
	lane, _ := lanes[0].(map[string]interface{})
	if lane["host"] != "C.com" {
		t.Fatalf("lane host=%v; want C.com", lane["host"])
	}
}
