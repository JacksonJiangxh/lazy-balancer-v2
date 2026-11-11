package services

import (
	"encoding/json"
	"fmt"
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
//
// ── 测试口径（TASK-2026-1111-02 r2 · 风控 P1-2 整改）─────────────────────────
//
// r1 的 P 组用 `seedPathRuleUpstreamHosts` **手工复刻**渲染期推导（自建 registry +
// plan + resolver）为 `PathRule.Upstreams` 填行内值，随后直连 `generateHTTPRouteObjects`。
// 生产填值点是 `generateCaddyConfigFromStore` 里的
//   `buildPathUpstreamHostResolver(rulesByID)` → `decodePathUpstreamsWithResolver(...)`
// （caddy.go:2228/2252），与 helper 是两段**独立代码**——helper 对不保证生产对，
// 且两者一旦漂移，钉测仍然全绿（假绿面）。本文件因此：
//
//   1. **删除替身**：不再有任何手工复刻推导的 helper；
//   2. 每个用例统一走 `renderPathRulesThroughProduction`——**播种真实 DB 行**
//      （lb_rules.host_header + upstreams.origin_domain + path_rules.upstreams_json）
//      → `generateCaddyConfigFromStore`（生产链路，含 resolver 构建与逐行推导）
//      → 取渲染产物断言。
//
// 这样每条用例都真实经过生产填值点；生产推导改了而测试没跟上，用例必红。

// scenarioDBUpstreams 用户举例形态的三条上游（IP 无逐上游值 + C/D 各带自己的值）。
func scenarioDBUpstreams() []struct {
	host, protocol, originDomain string
	port                         int
} {
	return []struct {
		host, protocol, originDomain string
		port                         int
	}{
		{"192.168.42.2", "http", "", 40080},
		{"C.com", "https", "C.com", 443},
		{"D.com", "https", "D.com", 443},
	}
}

// scenarioDBPathRules 自定义路由形态：路径 + 指向的地址（**不含任何回源 Host
// 字段**——前端不携带，推导全在渲染期）。
type scenarioDBPathRule struct {
	path, host, protocol string
	port                 int
}

// renderPathRulesThroughProduction 在生产链路上渲染一个「规则级 hostHeader +
// 上游集合 + 自定义路由」的完整规则，返回 `<caddyID>_path_<i>` 各条路由的
// （回源 Host 下发, lb_upstream_host 处理器）。
//
// 关键：本函数**不做任何推导**——推导只发生在 `generateCaddyConfigFromStore`
// 内部（生产填值点）。测试只负责播种与取产物。
func renderPathRulesThroughProduction(
	t *testing.T,
	caddyID, ruleHostHeader string,
	upstreams []struct {
		host, protocol, originDomain string
		port                         int
	},
	pathRules []scenarioDBPathRule,
	strategy string,
) []pathRenderResult {
	t.Helper()
	_, database := newClusterTestService(t)
	seedGenerationRule(t, database, caddyID, true)
	if _, err := database.Exec(
		`UPDATE lb_rules SET domain='A.com', host_header=?, listen_port=18471, strategy=? WHERE caddy_id=?`,
		ruleHostHeader, strategy, caddyID); err != nil {
		t.Fatalf("update rule: %v", err)
	}
	if _, err := database.Exec(`DELETE FROM upstreams WHERE rule_id=?`, caddyID); err != nil {
		t.Fatalf("clear upstreams: %v", err)
	}
	for _, u := range upstreams {
		if _, err := database.Exec(
			`INSERT INTO upstreams (rule_id,host,port,weight,enabled,protocol,origin_domain) VALUES (?,?,?,1,1,?,?)`,
			caddyID, u.host, u.port, u.protocol, u.originDomain); err != nil {
			t.Fatalf("seed upstream %s: %v", u.host, err)
		}
	}
	for index, pr := range pathRules {
		upstreamsJSON := fmt.Sprintf(`[{"address":%q,"port":%d,"weight":100,"protocol":%q}]`, pr.host, pr.port, pr.protocol)
		if _, err := database.Exec(`INSERT INTO path_rules (rule_id,sort_order,match_type,path,upstream_path,upstreams_json,response_mode,response_status,response_body,response_content_type,redirect_to,updated_at)
			VALUES (?,?, 'prefix', ?, '', ?, 'proxy', 0, '', '', '', datetime('now'))`, caddyID, index, pr.path, upstreamsJSON); err != nil {
			t.Fatalf("seed path rule %s: %v", pr.path, err)
		}
	}

	generated := generateCaddyConfigFromStore(database)
	if message, failed := generated[caddyConfigGenerationErrorKey].(string); failed {
		t.Fatalf("generation failed: %s", message)
	}
	routes := renderedHTTPRoutesFromGenerated(t, generated)

	results := make([]pathRenderResult, 0, len(pathRules))
	for index := range pathRules {
		routeID := fmt.Sprintf("%s_path_%d", caddyID, index)
		route := renderedRouteByID(t, routes, routeID)
		host, override := chainHostPlanOf(t, renderedHandleChain(t, route))
		results = append(results, pathRenderResult{routeID: routeID, host: host, override: override})
	}
	return results
}

// pathRenderResult 一条自定义路由的渲染产物投影。
type pathRenderResult struct {
	routeID  string
	host     []string       // reverse_proxy headers.request.set.Host
	override map[string]any // lb_upstream_host 处理器（非混合态为 nil）
}

// assertStaticHost 断言该路由折叠为静态 Host（不发射 handler）。
func (r pathRenderResult) assertStaticHost(t *testing.T, want string) {
	t.Helper()
	if r.override != nil {
		t.Fatalf("%s 统一值必须折叠为静态，不得发射 handler: %#v", r.routeID, r.override)
	}
	if len(r.host) != 1 || r.host[0] != want {
		t.Fatalf("%s host=%v; want [%s]", r.routeID, r.host, want)
	}
}

// assertNeverClientHost 断言下发值里不含任何客户端请求占位符（P4 硬约束）。
func (r pathRenderResult) assertNeverClientHost(t *testing.T) {
	t.Helper()
	for _, h := range r.host {
		if containsSubstring([]byte(h), "http.request.") {
			t.Fatalf("%s host=%v 含客户端请求占位符——绝不透传客户端 Host", r.routeID, r.host)
		}
	}
}

// Given: 上游服务器列表里 C.com 自带逐上游回源 Host，自定义路由 /img/ 指向它
// When: 走**生产链路**（DB → buildPathUpstreamHostResolver →
// decodePathUpstreamsWithResolver → 渲染）解析该路径上游
// Then (P1 hoisted 第一档): 用 C.com 自己的逐上游值（压过规则级 B.com）
//
// 本用例覆盖生产填值点：`resolver.hostFor` 的 hoisted 分支被真实调用。
func TestPathRuleUpstreamHost_listedUpstreamKeepsItsOwnHost(t *testing.T) {
	got := renderPathRulesThroughProduction(t, "lb_p_img", "B.com", scenarioDBUpstreams(),
		[]scenarioDBPathRule{{"/img/", "C.com", "https", 443}}, "weighted_round_robin")

	got[0].assertStaticHost(t, "C.com")
	got[0].assertNeverClientHost(t)
}

// Given: 上游列表里 192.168.42.2 的回源 Host 留空，自定义路由 / 指向它
// When: 走生产链路解析该路径上游
// Then (P1 hoisted 第二档): 回退规则级 B.com
//
// 本用例覆盖生产填值点：hoisted 分支取到「上游级空 → 规则级」的第二档值。
func TestPathRuleUpstreamHost_listedUpstreamWithoutHostFallsBackToRule(t *testing.T) {
	got := renderPathRulesThroughProduction(t, "lb_p_root", "B.com", scenarioDBUpstreams(),
		[]scenarioDBPathRule{{"/", "192.168.42.2", "http", 40080}}, "weighted_round_robin")

	got[0].assertStaticHost(t, "B.com")
	got[0].assertNeverClientHost(t)
}

// Given: 自定义路由 /admin 指向 D.com（列表内，带自己的逐上游值）
// When: 走生产链路解析该路径上游
// Then (P1 hoisted): 用 D.com 自己的值（不被规则级 B.com 覆盖）
func TestPathRuleUpstreamHost_listedUpstreamAdminUsesOwnHost(t *testing.T) {
	got := renderPathRulesThroughProduction(t, "lb_p_admin", "B.com", scenarioDBUpstreams(),
		[]scenarioDBPathRule{{"/admin", "D.com", "https", 443}}, "weighted_round_robin")

	got[0].assertStaticHost(t, "D.com")
	got[0].assertNeverClientHost(t)
}

// Given: 自定义路由 /api 指向 X.com（**不在**上游服务器列表里）
// When: 走生产链路解析该路径上游
// Then (P1 orphan): 用规则级 B.com（外部地址只有规则级一档）
//
// 本用例覆盖生产填值点：hoisted 未命中 → orphan 分支（只取规则级）。
//
// 除渲染产物外，另直接断言 **resolver 层**的派生值（见函数末段）：渲染层对
// 「行内值为空」还会再做一次规则级兜底（caddy.go 的 resolveUpstreamHostPlan），
// 因此只看渲染产物**无法区分**「orphan 派生正确」与「orphan 派生为空、被渲染层
// 兜住」——两者产物相同。派生值断言把这条缝补上。
func TestPathRuleUpstreamHost_unlistedUpstreamUsesRuleLevelHost(t *testing.T) {
	got := renderPathRulesThroughProduction(t, "lb_p_api", "B.com", scenarioDBUpstreams(),
		[]scenarioDBPathRule{{"/api", "X.com", "https", 443}}, "weighted_round_robin")

	got[0].assertStaticHost(t, "B.com")
	got[0].assertNeverClientHost(t)

	// resolver 层（生产同一对函数）：表外地址 → 只取规则级。
	resolver := buildPathUpstreamHostResolver(map[string]*ruleWithUpstreams{
		"lb_p_api": {
			rule: lbRule{CaddyID: "lb_p_api", Protocol: "http", HostHeader: "B.com"},
			upstreams: []upstream{
				{Host: "192.168.42.2", Port: 40080, Weight: 1, Enabled: true, Protocol: "http"},
				{Host: "C.com", Port: 443, Weight: 1, Enabled: true, Protocol: "https", OriginDomain: "C.com"},
				{Host: "D.com", Port: 443, Weight: 1, Enabled: true, Protocol: "https", OriginDomain: "D.com"},
			},
		},
	})
	derived, err := decodePathUpstreamsWithResolver(
		`[{"address":"X.com","port":443,"weight":100,"protocol":"https"}]`, resolver, "B.com")
	if err != nil {
		t.Fatalf("decode: %v", err)
	}
	if derived[0].OriginDomain != "B.com" {
		t.Fatalf("resolver 派生 origin_domain=%q; want B.com（orphan 只取规则级）", derived[0].OriginDomain)
	}
}

// Given: 规则级后端域名为空（基础设置留空），两条自定义路由分别指向列表内无
// 逐上游 Host 的地址与列表外的地址
// When: 走生产链路解析两条路径
// Then (P4 第三档): 都落到「上游自身地址」占位符，
// **绝不透传客户端 Host**
//
// 用例名与断言对象对齐（r2 · P2-2）：本用例断言的是**渲染层**的替换语义
// （行内派生值为空 → 链尾 Host 用 {http.reverse_proxy.upstream.hostport}），
// 不是 resolver 派生值本身。派生值为空这一点由
// `TestPathRuleUpstreamHost_emptyRuleLevelDerivesEmptyUpstreamDomain` 单独覆盖。
func TestPathRuleUpstreamHost_emptyRuleLevelChainFallsBackToDial(t *testing.T) {
	got := renderPathRulesThroughProduction(t, "lb_p_empty", "", scenarioDBUpstreams(),
		[]scenarioDBPathRule{
			{"/", "192.168.42.2", "http", 40080}, // hoisted，上游级/规则级皆空
			{"/api", "X.com", "https", 443},      // orphan，规则级空
		}, "weighted_round_robin")

	for _, result := range got {
		result.assertStaticHost(t, "{http.reverse_proxy.upstream.hostport}")
		result.assertNeverClientHost(t)
	}
}

// Given: 规则级与上游级都为空的自定义路由上游
// When: 走生产链路的 resolver 层（decodePathUpstreamsWithResolver，生产填值点
// 的同一个函数）
// Then (P4 派生语义): 派生出的行内 OriginDomain 为空串（表示「用自身地址」），
// 而不是占位符文本——占位符是渲染层的替换形态，见上一条用例。
//
// 本用例测的是 **resolver 层**；渲染层的端到端口径由
// `TestPathRuleUpstreamHost_emptyRuleLevelChainFallsBackToDial` 覆盖。
func TestPathRuleUpstreamHost_emptyRuleLevelDerivesEmptyUpstreamDomain(t *testing.T) {
	_, database := newClusterTestService(t)
	ruleID := "lb_p_derive"
	seedGenerationRule(t, database, ruleID, true)
	// 规则级留空、上游级留空——这是「三级回退第三档」的配置形态。
	if _, err := database.Exec(`UPDATE lb_rules SET host_header='' WHERE caddy_id=?`, ruleID); err != nil {
		t.Fatalf("clear host_header: %v", err)
	}
	if _, err := database.Exec(`UPDATE upstreams SET origin_domain='' WHERE rule_id=?`, ruleID); err != nil {
		t.Fatalf("clear origin_domain: %v", err)
	}

	// 生产填值点：同一个 buildPathUpstreamHostResolver + decodePathUpstreamsWithResolver。
	plan := resolveUpstreamHostPlan(SingleRuleConfig{HostHeader: ""}, []UpstreamConfig{
		{Host: "192.168.42.2", Port: 40080, Weight: 1, Enabled: true, Protocol: "http"},
	})
	if !plan.usePlaceholder {
		t.Fatalf("plan=%+v; 上游级与规则级皆空必须落 usePlaceholder", plan)
	}
	resolver := buildPathUpstreamHostResolver(map[string]*ruleWithUpstreams{
		ruleID: {
			rule:      lbRule{CaddyID: ruleID, Protocol: "http", HostHeader: ""},
			upstreams: []upstream{{Host: "192.168.42.2", Port: 40080, Weight: 1, Enabled: true, Protocol: "http"}},
		},
	})
	for _, raw := range []string{
		`[{"address":"192.168.42.2","port":40080,"weight":100,"protocol":"http"}]`, // hoisted
		`[{"address":"X.com","port":443,"weight":100,"protocol":"https"}]`,         // orphan
	} {
		upstreams, err := decodePathUpstreamsWithResolver(raw, resolver, "")
		if err != nil {
			t.Fatalf("decode %s: %v", raw, err)
		}
		if len(upstreams) != 1 {
			t.Fatalf("upstreams=%+v; want 1", upstreams)
		}
		if upstreams[0].OriginDomain != "" {
			t.Fatalf("raw=%s origin_domain=%q; want 空串（派生语义=用自身地址）",
				raw, upstreams[0].OriginDomain)
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

// Given: 同一路径的两台上游分属不同取值（一台有逐上游值、一台只有规则级）
// When: 走生产链路渲染该路径（需在同一 upstreams_json 里放两台）
// Then (P1 + P3): 混合态发射 lb_upstream_host，映射里两台各取自己的有效值
//
// 生产填值点：`decodePathUpstreamsWithResolver` 逐行调用 resolver（两条行各一次）。
func TestPathRuleUpstreamHost_mixedPathEmitsOverrideMap(t *testing.T) {
	_, database := newClusterTestService(t)
	ruleID := "lb_p_mixedpath"
	seedGenerationRule(t, database, ruleID, true)
	if _, err := database.Exec(
		`UPDATE lb_rules SET domain='A.com', host_header='B.com', listen_port=18471 WHERE caddy_id=?`, ruleID); err != nil {
		t.Fatalf("update rule: %v", err)
	}
	if _, err := database.Exec(`DELETE FROM upstreams WHERE rule_id=?`, ruleID); err != nil {
		t.Fatalf("clear upstreams: %v", err)
	}
	// 三台上游：C/D 带逐上游值，192.168.42.2 无（回退规则级 B.com）。
	for _, u := range scenarioDBUpstreams() {
		if _, err := database.Exec(
			`INSERT INTO upstreams (rule_id,host,port,weight,enabled,protocol,origin_domain) VALUES (?,?,?,1,1,?,?)`,
			ruleID, u.host, u.port, u.protocol, u.originDomain); err != nil {
			t.Fatalf("seed upstream %s: %v", u.host, err)
		}
	}
	// 同一路径指向 C.com 与 192.168.42.2：有效值分别为 C.com / B.com → 混合态。
	upstreamsJSON := `[{"address":"C.com","port":443,"weight":100,"protocol":"https"},` +
		`{"address":"192.168.42.2","port":40080,"weight":100,"protocol":"http"}]`
	if _, err := database.Exec(`INSERT INTO path_rules (rule_id,sort_order,match_type,path,upstream_path,upstreams_json,response_mode,response_status,response_body,response_content_type,redirect_to,updated_at)
		VALUES (?,0,'prefix','/img/','',?,'proxy',0,'','','',datetime('now'))`, ruleID, upstreamsJSON); err != nil {
		t.Fatalf("seed path rule: %v", err)
	}

	generated := generateCaddyConfigFromStore(database)
	if message, failed := generated[caddyConfigGenerationErrorKey].(string); failed {
		t.Fatalf("generation failed: %s", message)
	}
	route := renderedRouteByID(t, renderedHTTPRoutesFromGenerated(t, generated), ruleID+"_path_0")
	host, override := chainHostPlanOf(t, renderedHandleChain(t, route))

	if len(host) != 1 || host[0] != "{lb.upstream_host}" {
		t.Fatalf("host=%v; want [{lb.upstream_host}]", host)
	}
	if override == nil {
		t.Fatal("混合态必须发射 lb_upstream_host handler")
	}
	hostsRaw, ok := override["hosts"]
	if !ok {
		t.Fatalf("override hosts missing: %#v", override)
	}
	hosts, ok := hostsRaw.(map[string]string)
	if !ok {
		// JSON 往返后可能是 map[string]interface{}。
		generic, genericOK := hostsRaw.(map[string]any)
		if !genericOK {
			t.Fatalf("override hosts type=%T", hostsRaw)
		}
		hosts = make(map[string]string, len(generic))
		for k, v := range generic {
			text, _ := v.(string)
			hosts[k] = text
		}
	}
	if hosts["C.com:443"] != "C.com" {
		t.Fatalf("hosts[C.com:443]=%q; want C.com（第一档）", hosts["C.com:443"])
	}
	if hosts["192.168.42.2:40080"] != "B.com" {
		t.Fatalf("hosts[192.168.42.2:40080]=%q; want B.com（第二档规则级）", hosts["192.168.42.2:40080"])
	}
}

// Given: 同一地址既出现在 A 规则上游集合里（带逐上游值），又作为 B 规则的自定义
// 路由上游（B 自己的上游集合里没有它）
// When: 走生产链路解析 B 规则该路径的回源 Host
// Then (P1 跨规则): 按「配置属于 A」取值——回源 Host 跟随该地址的上游定义
//
// 生产填值点：buildPathUpstreamHostResolver 的跨规则索引（rulesByID 全量）。
func TestPathRuleUpstreamHost_crossRuleAddressFollowsItsOwner(t *testing.T) {
	// 手工构造 resolver 依赖的**包级类型**（不是复刻推导逻辑：直接调用生产
	// buildPathUpstreamHostResolver + decodePathUpstreamsWithResolver，与
	// caddy.go:2228/2252 完全同一对函数）。本用例测 resolver 层的跨规则归属；
	// 端到端（DB → 渲染）由 listedUpstream*/mixedPath* 等用例覆盖。
	resolver := buildPathUpstreamHostResolver(map[string]*ruleWithUpstreams{
		"lb_owner": {
			rule:      lbRule{CaddyID: "lb_owner", Protocol: "http", HostHeader: ""},
			upstreams: []upstream{{Host: "shared.example", Port: 8080, Weight: 1, Enabled: true, OriginDomain: "owner.internal"}},
		},
		"lb_borrower": {
			rule:      lbRule{CaddyID: "lb_borrower", Protocol: "http", HostHeader: "borrower.internal"},
			upstreams: []upstream{{Host: "other.example", Port: 8080, Weight: 1, Enabled: true}},
		},
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
// When: 走生产链路渲染该路径的链
// Then (P2 与链式回退同口径): chain_proxy 车道的 host 取推导出的回源 Host
// ——链式回退（自研第 1 项）与本能力（第 4 项）不打架
func TestPathRuleUpstreamHost_chainFallbackHonoursDerivedHost(t *testing.T) {
	_, database := newClusterTestService(t)
	ruleID := "lb_p_chain"
	seedGenerationRule(t, database, ruleID, true)
	if _, err := database.Exec(
		`UPDATE lb_rules SET domain='A.com', host_header='B.com', listen_port=18471, strategy='chain_fallback' WHERE caddy_id=?`,
		ruleID); err != nil {
		t.Fatalf("update rule: %v", err)
	}
	if _, err := database.Exec(`DELETE FROM upstreams WHERE rule_id=?`, ruleID); err != nil {
		t.Fatalf("clear upstreams: %v", err)
	}
	for _, u := range scenarioDBUpstreams() {
		if _, err := database.Exec(
			`INSERT INTO upstreams (rule_id,host,port,weight,enabled,protocol,origin_domain) VALUES (?,?,?,1,1,?,?)`,
			ruleID, u.host, u.port, u.protocol, u.originDomain); err != nil {
			t.Fatalf("seed upstream %s: %v", u.host, err)
		}
	}
	if _, err := database.Exec(`INSERT INTO path_rules (rule_id,sort_order,match_type,path,upstream_path,upstreams_json,response_mode,response_status,response_body,response_content_type,redirect_to,updated_at)
		VALUES (?,0,'prefix','/img/','','[{"address":"C.com","port":443,"weight":100,"protocol":"https"}]','proxy',0,'','','',datetime('now'))`, ruleID); err != nil {
		t.Fatalf("seed path rule: %v", err)
	}

	generated := generateCaddyConfigFromStore(database)
	if message, failed := generated[caddyConfigGenerationErrorKey].(string); failed {
		t.Fatalf("generation failed: %s", message)
	}
	route := renderedRouteByID(t, renderedHTTPRoutesFromGenerated(t, generated), ruleID+"_path_0")
	chain := renderedHandleChain(t, route)

	found := false
	for _, raw := range chain {
		entry, ok := raw.(map[string]any)
		if !ok || entry["handler"] != "chain_proxy" {
			continue
		}
		found = true
		ups, ok := entry["upstreams"].([]any)
		if !ok || len(ups) != 1 {
			t.Fatalf("chain_proxy upstreams=%#v", entry["upstreams"])
		}
		lane, _ := ups[0].(map[string]any)
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
	got := renderPathRulesThroughProduction(t, "lb_e2e_host", "B.com", scenarioDBUpstreams(),
		[]scenarioDBPathRule{
			{"/img/", "C.com", "https", 443},
			{"/", "192.168.42.2", "http", 40080},
			{"/admin", "D.com", "https", 443},
			{"/api", "X.com", "https", 443},
		}, "weighted_round_robin")

	wantHosts := []string{"C.com", "B.com", "D.com", "B.com"}
	for index, wantHost := range wantHosts {
		got[index].assertStaticHost(t, wantHost)
		got[index].assertNeverClientHost(t)
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
