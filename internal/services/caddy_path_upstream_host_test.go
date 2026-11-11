package services

import (
	"encoding/json"
	"fmt"
	"strings"
	"testing"
)

// 自定义路由上游的回源 Host 内部推导（**董事长核心自研第 4 项 P 组**，
// TASK-2026-1111-02 恢复；董事长 2026-10-10 裁定 `0c8ec276`：
// 「自定义路由的规则设定不该出现任何额外字段，回源 Host 全程是内部逻辑」）。
//
// 判定分两类：
//   - hoisted：地址在「上游服务器」列表里 → 按该地址所属规则的上游集合整体
//     解析（逐上游 origin_domain > 规则级 host_header > 自身地址）；
//   - orphan：地址不在列表里 → 只有规则级一档，仍空用自身地址。
//
// 两类都**绝不透传客户端 Host**（P4）。上游 map 方案没有这一层，是自研独有能力。
// 归属登记见 docs/self-developed-features.zh-CN.md 第 4 项。

// scenarioUpstreams 用户举例形态的三条上游（IP 无逐上游值 + C/D 各带自己的值）。
func scenarioUpstreams() []UpstreamConfig {
	return []UpstreamConfig{
		{Host: "192.168.42.2", Port: 40080, Weight: 1, Enabled: true},
		{Host: "C.com", Port: 443, Weight: 1, Enabled: true, Protocol: "https", OriginDomain: "C.com"},
		{Host: "D.com", Port: 443, Weight: 1, Enabled: true, Protocol: "https", OriginDomain: "D.com"},
	}
}

// seedPathRuleUpstreamHosts 复刻渲染期对 path_rules 上游行的内部推导：用与生产
// 同源的 pathUpstreamHostResolver + resolveUpstreamHostPlan 填行内 OriginDomain，
// 保证测试与生产口径不分叉（测试直连渲染入口时不经过 DB 加载段）。
func seedPathRuleUpstreamHosts(rule *SingleRuleConfig) {
	ruleHost := rule.HostHeader
	registry := make(map[string]struct{}, len(rule.Upstreams))
	for _, u := range rule.Upstreams {
		registry[upstreamHostKey(u.Host, u.Port)] = struct{}{}
	}
	plan := resolveUpstreamHostPlan(SingleRuleConfig{HostHeader: ruleHost}, rule.Upstreams)
	resolver := &pathUpstreamHostResolver{
		hoisted: func(host string, port int) (string, bool) {
			if _, ok := registry[upstreamHostKey(host, port)]; !ok {
				return "", false
			}
			return hostPlanValueFor(plan, host, port)
		},
		orphan: func(h string) string { return strings.TrimSpace(h) },
	}
	for pathIndex := range rule.PathRules {
		ups := rule.PathRules[pathIndex].Upstreams
		for i := range ups {
			ups[i].OriginDomain = strings.TrimSpace(resolver.hostFor(ups[i].Host, ups[i].Port, ruleHost))
		}
		rule.PathRules[pathIndex].Upstreams = ups
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

// pathRuleChainHostSet 取指定自定义路由链的回源 Host 下发。
func pathRuleChainHostSet(t *testing.T, rule SingleRuleConfig, pathIndex int) ([]string, map[string]interface{}) {
	t.Helper()
	chain := pathRuleChainOf(t, rule, pathIndex)
	var host []string
	var override map[string]interface{}
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
			host, _ = set["Host"].([]string)
		}
	}
	return host, override
}

// Given: 上游服务器列表里 C.com 自带逐上游回源 Host，自定义路由 /img/ 指向它
// When: 解析该路径上游的回源 Host 计划
// Then (P1 hoisted 第一档): 用 C.com 自己的逐上游值（压过规则级 B.com）
func TestPathRuleUpstreamHost_listedUpstreamKeepsItsOwnHost(t *testing.T) {
	rule := baseOriginRule("lb_p_img")
	rule.HostHeader = "B.com"
	rule.CustomRoutesEnabled = true
	rule.Upstreams = scenarioUpstreams()
	rule.PathRules = []PathRuleConfig{{
		SortOrder: 0, MatchType: "prefix", Path: "/img/",
		Upstreams: []UpstreamConfig{{Host: "C.com", Port: 443, Weight: 1, Enabled: true, Protocol: "https"}},
	}}
	seedPathRuleUpstreamHosts(&rule)

	host, override := pathRuleChainHostSet(t, rule, 0)
	if len(host) != 1 || host[0] != "C.com" {
		t.Fatalf("host=%v; want [C.com]（逐上游回源 Host，第一档）", host)
	}
	if override != nil {
		t.Fatalf("统一值必须折叠为静态，不得发射 handler: %#v", override)
	}
}

// Given: 上游列表里 192.168.42.2 的回源 Host 留空，自定义路由 / 指向它
// When: 解析该路径上游的回源 Host
// Then (P1 hoisted 第二档): 回退规则级 B.com
func TestPathRuleUpstreamHost_listedUpstreamWithoutHostFallsBackToRule(t *testing.T) {
	rule := baseOriginRule("lb_p_root")
	rule.HostHeader = "B.com"
	rule.CustomRoutesEnabled = true
	rule.Upstreams = scenarioUpstreams()
	rule.PathRules = []PathRuleConfig{{
		SortOrder: 0, MatchType: "prefix", Path: "/",
		Upstreams: []UpstreamConfig{{Host: "192.168.42.2", Port: 40080, Weight: 1, Enabled: true}},
	}}
	seedPathRuleUpstreamHosts(&rule)

	host, _ := pathRuleChainHostSet(t, rule, 0)
	if len(host) != 1 || host[0] != "B.com" {
		t.Fatalf("host=%v; want [B.com]（回退规则级后端域名）", host)
	}
}

// Given: 自定义路由 /admin 指向 D.com（列表内，带自己的逐上游值）
// When: 解析该路径上游的回源 Host
// Then (P1 hoisted): 用 D.com 自己的值（不被规则级 B.com 覆盖）
func TestPathRuleUpstreamHost_listedUpstreamAdminUsesOwnHost(t *testing.T) {
	rule := baseOriginRule("lb_p_admin")
	rule.HostHeader = "B.com"
	rule.CustomRoutesEnabled = true
	rule.Upstreams = scenarioUpstreams()
	rule.PathRules = []PathRuleConfig{{
		SortOrder: 0, MatchType: "prefix", Path: "/admin",
		Upstreams: []UpstreamConfig{{Host: "D.com", Port: 443, Weight: 1, Enabled: true, Protocol: "https"}},
	}}
	seedPathRuleUpstreamHosts(&rule)

	host, _ := pathRuleChainHostSet(t, rule, 0)
	if len(host) != 1 || host[0] != "D.com" {
		t.Fatalf("host=%v; want [D.com]", host)
	}
}

// Given: 自定义路由 /api 指向 X.com（**不在**上游服务器列表里）
// When: 解析该路径上游的回源 Host
// Then (P1 orphan): 用规则级 B.com（外部地址只有规则级一档）
func TestPathRuleUpstreamHost_unlistedUpstreamUsesRuleLevelHost(t *testing.T) {
	rule := baseOriginRule("lb_p_api")
	rule.HostHeader = "B.com"
	rule.CustomRoutesEnabled = true
	rule.Upstreams = scenarioUpstreams()
	rule.PathRules = []PathRuleConfig{{
		SortOrder: 0, MatchType: "prefix", Path: "/api",
		Upstreams: []UpstreamConfig{{Host: "X.com", Port: 443, Weight: 1, Enabled: true, Protocol: "https"}},
	}}
	seedPathRuleUpstreamHosts(&rule)

	host, _ := pathRuleChainHostSet(t, rule, 0)
	if len(host) != 1 || host[0] != "B.com" {
		t.Fatalf("host=%v; want [B.com]（不在上游列表 → 规则级）", host)
	}
}

// Given: 规则级后端域名为空（基础设置留空），两条自定义路由分别指向列表内无
// 逐上游 Host 的地址与列表外的地址
// When: 解析两条路径的回源 Host
// Then (P4): 都落到「上游自身地址」占位符（第三档），**绝不透传客户端 Host**
func TestPathRuleUpstreamHost_emptyRuleLevelFallsBackToDial(t *testing.T) {
	rule := baseOriginRule("lb_p_empty")
	rule.CustomRoutesEnabled = true
	rule.Upstreams = scenarioUpstreams()
	rule.PathRules = []PathRuleConfig{
		{
			SortOrder: 0, MatchType: "prefix", Path: "/",
			Upstreams: []UpstreamConfig{{Host: "192.168.42.2", Port: 40080, Weight: 1, Enabled: true}},
		},
		{
			SortOrder: 1, MatchType: "prefix", Path: "/api",
			Upstreams: []UpstreamConfig{{Host: "X.com", Port: 443, Weight: 1, Enabled: true, Protocol: "https"}},
		},
	}
	seedPathRuleUpstreamHosts(&rule)

	for index, want := range []string{"/", "/api"} {
		host, _ := pathRuleChainHostSet(t, rule, index)
		if len(host) != 1 || host[0] != "{http.reverse_proxy.upstream.hostport}" {
			t.Fatalf("path %s host=%v; want 上游自身地址占位符", want, host)
		}
		for _, h := range host {
			if strings.Contains(h, "http.request.") {
				t.Fatalf("path %s host=%v 含客户端请求占位符——绝不透传客户端 Host", want, host)
			}
		}
	}
}

// Given: 存储行里残留外部写入的 host_header（备份导入 / API 直写）
// When: 解析自定义路由上游
// Then (P2): 该字段被忽略——真相来自上游服务器列表（配置一致性优先）
func TestPathRuleUpstreamHost_ignoresPersistedForeignValue(t *testing.T) {
	raw := `[{"address":"X.com","port":443,"weight":1,"protocol":"https","host_header":"evil.internal"}]`
	upstreams, err := decodePathUpstreamsWithResolver(raw, nil, "B.com")
	if err != nil {
		t.Fatalf("decode: %v", err)
	}
	if len(upstreams) != 1 || upstreams[0].OriginDomain != "" {
		t.Fatalf("upstreams=%+v; want 行内值被忽略（resolver=nil 时留空）", upstreams)
	}
	// 无解析上下文的调用方（无规则上下文）同样不动该值。
	plain, err := decodePathUpstreams(raw)
	if err != nil {
		t.Fatalf("decode plain: %v", err)
	}
	if plain[0].OriginDomain != "" {
		t.Fatalf("plain origin_domain=%q; want empty（行内值不参与渲染）", plain[0].OriginDomain)
	}
}

// Given: 自定义路由 /img/ 指向列表内两台各自带逐上游值的上游（混合态）
// When: 解析该路径的回源 Host 计划
// Then (P1 + P3): 走混合态（lb_upstream_host + {lb.upstream_host}），逐上游值
// 各归各位，单行推导出的值经 handler 下发
func TestPathRuleUpstreamHost_mixedUpstreamsFoldIntoOverrideMap(t *testing.T) {
	rule := baseOriginRule("lb_p_mixed")
	rule.CustomRoutesEnabled = true
	rule.Upstreams = scenarioUpstreams()
	rule.PathRules = []PathRuleConfig{{
		SortOrder: 0, MatchType: "prefix", Path: "/img/",
		Upstreams: []UpstreamConfig{
			{Host: "C.com", Port: 443, Weight: 1, Enabled: true, Protocol: "https"},
			{Host: "D.com", Port: 443, Weight: 1, Enabled: true, Protocol: "https"},
		},
	}}
	seedPathRuleUpstreamHosts(&rule)

	host, override := pathRuleChainHostSet(t, rule, 0)
	if len(host) != 1 || host[0] != "{lb.upstream_host}" {
		t.Fatalf("host=%v; want [{lb.upstream_host}]", host)
	}
	if override == nil {
		t.Fatal("混合态必须发射 lb_upstream_host handler")
	}
	hosts, ok := override["hosts"].(map[string]string)
	if !ok {
		t.Fatalf("override hosts type=%T", override["hosts"])
	}
	if hosts["C.com:443"] != "C.com" || hosts["D.com:443"] != "D.com" {
		t.Fatalf("override hosts=%v; want 逐上游值各归各位", hosts)
	}
}

// Given: 同一地址既出现在 A 规则上游集合里（带逐上游值），又作为 B 规则的自定义
// 路由上游（B 自己的上游集合里没有它）
// When: 解析 B 规则该路径的回源 Host
// Then (P1 跨规则): 按「配置属于 A」取值——回源 Host 跟随该地址的上游定义
func TestPathRuleUpstreamHost_crossRuleAddressFollowsItsOwner(t *testing.T) {
	ownerRule := &ruleWithUpstreams{
		rule: lbRule{CaddyID: "lb_owner", Protocol: "http", HostHeader: ""},
		upstreams: []upstream{
			{Host: "shared.example", Port: 8080, Weight: 1, Enabled: true, OriginDomain: "owner.internal"},
		},
	}
	borrowerRule := &ruleWithUpstreams{
		rule:      lbRule{CaddyID: "lb_borrower", Protocol: "http", HostHeader: "borrower.internal"},
		upstreams: []upstream{{Host: "other.example", Port: 8080, Weight: 1, Enabled: true}},
	}
	resolver := buildPathUpstreamHostResolver(map[string]*ruleWithUpstreams{
		"lb_owner":    ownerRule,
		"lb_borrower": borrowerRule,
	})
	raw := `[{"address":"shared.example","port":8080,"weight":100,"protocol":"http"}]`
	upstreams, err := decodePathUpstreamsWithResolver(raw, resolver, "borrower.internal")
	if err != nil {
		t.Fatalf("decode: %v", err)
	}
	if len(upstreams) != 1 || upstreams[0].OriginDomain != "owner.internal" {
		t.Fatalf("upstreams=%+v; want owner.internal（按地址所属上游取值）", upstreams)
	}
}

// Given: 自定义路由 + chain_fallback 策略，路径上游地址在上游列表里（带逐上游值）
// When: 渲染该路径的链
// Then (P2 与链式回退同口径): chain_proxy 车道的 host 取推导出的回源 Host
// ——链式回退（自研第 1 项）与本能力（第 4 项）不打架
func TestPathRuleUpstreamHost_chainFallbackHonoursDerivedHost(t *testing.T) {
	rule := baseOriginRule("lb_p_chain")
	rule.HostHeader = "B.com"
	rule.Strategy = "chain_fallback"
	rule.CustomRoutesEnabled = true
	rule.Upstreams = scenarioUpstreams()
	rule.PathRules = []PathRuleConfig{{
		SortOrder: 0, MatchType: "prefix", Path: "/img/",
		Upstreams: []UpstreamConfig{{Host: "C.com", Port: 443, Weight: 1, Enabled: true, Protocol: "https"}},
	}}
	seedPathRuleUpstreamHosts(&rule)

	chain := pathRuleChainOf(t, rule, 0)
	found := false
	for _, raw := range chain {
		entry, ok := raw.(map[string]interface{})
		if !ok || entry["handler"] != "chain_proxy" {
			continue
		}
		found = true
		ups, ok := entry["upstreams"].([]interface{})
		if !ok || len(ups) != 1 {
			t.Fatalf("chain_proxy upstreams=%#v", entry["upstreams"])
		}
		lane := ups[0].(map[string]interface{})
		if lane["host"] != "C.com" {
			t.Fatalf("chain lane host=%#v; want C.com（推导出的回源 Host）", lane["host"])
		}
	}
	if !found {
		t.Fatalf("chain_proxy handler missing in chain: %#v", chain)
	}
}

// Given: 完整用户举例场景——规则级 B.com + 三条上游 + 四条自定义路由（含一条
// 指向列表外的 X.com）
// When: 走**真实生成链路**（DB → pathResolver → 渲染）
// Then (P2 端到端): /img/=C.com、/=B.com、/admin=D.com、/api=B.com——全内部
// 推导，规则设定里没有任何回源 Host 字段
func TestPathRuleUpstreamHost_endToEndScenario(t *testing.T) {
	_, database := newClusterTestService(t)
	seedGenerationRule(t, database, "lb_e2e_host", true)
	if _, err := database.Exec(`UPDATE lb_rules SET domain='A.com', host_header='B.com', listen_port=18471 WHERE caddy_id='lb_e2e_host'`); err != nil {
		t.Fatalf("update rule: %v", err)
	}
	if _, err := database.Exec(`DELETE FROM upstreams WHERE rule_id='lb_e2e_host'`); err != nil {
		t.Fatalf("clear upstreams: %v", err)
	}
	for _, u := range []struct {
		host, protocol, originDomain string
		port                         int
	}{
		{"192.168.42.2", "http", "", 40080},
		{"C.com", "https", "C.com", 443},
		{"D.com", "https", "D.com", 443},
	} {
		if _, err := database.Exec(`INSERT INTO upstreams (rule_id,host,port,weight,enabled,protocol,origin_domain) VALUES (?,?,?,1,1,?,?)`,
			"lb_e2e_host", u.host, u.port, u.protocol, u.originDomain); err != nil {
			t.Fatalf("seed upstream %s: %v", u.host, err)
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
	for index, pr := range pathRules {
		upstreamsJSON := fmt.Sprintf(`[{"address":%q,"port":%d,"weight":100,"protocol":%q}]`, pr.host, pr.port, pr.protocol)
		if _, err := database.Exec(`INSERT INTO path_rules (rule_id,sort_order,match_type,path,upstream_path,upstreams_json,response_mode,response_status,response_body,response_content_type,redirect_to,updated_at)
			VALUES (?,?, 'prefix', ?, '', ?, 'proxy', 0, '', '', '', datetime('now'))`, "lb_e2e_host", index, pr.path, upstreamsJSON); err != nil {
			t.Fatalf("seed path rule %s: %v", pr.path, err)
		}
	}

	generated := generateCaddyConfigFromStore(database)
	if message, failed := generated[caddyConfigGenerationErrorKey].(string); failed {
		t.Fatalf("generation failed: %s", message)
	}
	routes := renderedHTTPRoutesFromGenerated(t, generated)

	wantHosts := []string{"C.com", "B.com", "D.com", "B.com"}
	for index, wantHost := range wantHosts {
		routeID := fmt.Sprintf("lb_e2e_host_path_%d", index)
		route := renderedRouteByID(t, routes, routeID)
		host, override := chainHostPlanOf(t, renderedHandleChain(t, route))
		if override != nil {
			t.Fatalf("path %s（%s）不应发射 handler（单上游统一态）: %#v", pathRules[index].path, routeID, override)
		}
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

// chainHostPlanOf 从处理链投影回源 Host 下发与 lb_upstream_host 处理器。
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
