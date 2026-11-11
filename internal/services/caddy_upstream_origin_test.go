package services

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// 逐上游回源 Host 渲染（**董事长核心自研第 4 项**，TASK-2026-1111-02 恢复）：
// 四态计划 resolveUpstreamHostPlan（staticHost / usePlaceholder / overrideMap /
// sniTarget）+ 混合态由 caddygeoip 模块的 http.handlers.lb_upstream_host 处理器
// 在请求期惰性下发 {lb.upstream_host}/{lb.upstream_sni}。
//
// 与上游 map 方案的关键区别（也是本文件 H2/H4 钉测的由来）：
//   - 上游方案在「纯 http 池 + 规则级为空」时回退 {http.request.hostport}
//     = **客户端 Host**（用户域名被发给未配回源域名的上游）；
//   - 自研方案任何回退态都不用 {http.request.hostport}——全回退恒用
//     {http.reverse_proxy.upstream.hostport}（= 该上游自身 dial 地址）。
//
// 归属登记见 docs/self-developed-features.zh-CN.md 第 4 项。

// findMapHandler 在 handle 链中定位内建 map 处理器（自研方案恒不存在）。
// 保留本辅助函数是为了「map 方案零残留」的反向断言。
func findMapHandler(chain []interface{}) map[string]interface{} {
	for _, h := range chain {
		m, ok := h.(map[string]interface{})
		if ok && m["handler"] == "map" {
			return m
		}
	}
	return nil
}

// findUpstreamHostHandler 在 handle 链中定位自研 lb_upstream_host 处理器（不存在返回 nil）。
func findUpstreamHostHandler(chain []interface{}) map[string]interface{} {
	for _, h := range chain {
		m, ok := h.(map[string]interface{})
		if ok && m["handler"] == "lb_upstream_host" {
			return m
		}
	}
	return nil
}

// lastReverseProxy 返回链尾 reverse_proxy 处理器（链构造契约：恒为末位）。
func lastReverseProxy(t *testing.T, chain []interface{}) map[string]interface{} {
	t.Helper()
	last, ok := chain[len(chain)-1].(map[string]interface{})
	if !ok || last["handler"] != "reverse_proxy" {
		t.Fatalf("last handler must be reverse_proxy, got %#v", chain[len(chain)-1])
	}
	return last
}

// reverseProxyHostSet 取 reverse_proxy headers.request.set.Host。
func reverseProxyHostSet(t *testing.T, proxy map[string]interface{}) []string {
	t.Helper()
	headers, ok := proxy["headers"].(map[string]interface{})
	if !ok {
		t.Fatalf("headers missing: %#v", proxy)
	}
	request, ok := headers["request"].(map[string]interface{})
	if !ok {
		t.Fatalf("headers.request missing: %#v", headers)
	}
	set, ok := request["set"].(map[string]interface{})
	if !ok {
		return nil
	}
	hosts, _ := set["Host"].([]string)
	return hosts
}

// baseOriginRule 构造一个最小可渲染 HTTP 规则（数值列取生产形态默认值）。
func baseOriginRule(caddyID string) SingleRuleConfig {
	return SingleRuleConfig{
		HealthCheckInterval: 10, HealthCheckTimeout: 2,
		HealthCheckUnhealthyThreshold: 3, HealthCheckHealthyThreshold: 2,
		GlobalRequestBodyMaxSizeMB: 128,
		CaddyID:                    caddyID, Protocol: "http", ListenPort: 80,
	}
}

// Given: 上游 A 配置逐上游回源 Host、上游 B 留空（混合态）
// When: 构建 HTTP handle 链
// Then (H3): 发射 lb_upstream_host 处理器（覆盖链中 reverse_proxy **之前**），
// Host 走 {lb.upstream_host}，且**不发射**内建 map 处理器
func TestBuildHTTPHandleChain_mixedEmitsUpstreamHostHandler(t *testing.T) {
	rule := baseOriginRule("lb_origin")
	rule.HostHeader = "backend.example.com"
	upstreams := []UpstreamConfig{
		{Host: "10.0.0.1", Port: 8080, Weight: 1, Enabled: true, OriginDomain: "origin-a.example.com"},
		{Host: "10.0.0.2", Port: 8080, Weight: 1, Enabled: true},
	}

	chain, err := buildHTTPHandleChain(rule, upstreams)
	if err != nil {
		t.Fatalf("buildHTTPHandleChain: %v", err)
	}

	// H3 位置契约：lb_upstream_host 必须在 reverse_proxy 之前。
	overrideIdx, proxyIdx := -1, -1
	for i, raw := range chain {
		entry, ok := raw.(map[string]interface{})
		if !ok {
			continue
		}
		switch entry["handler"] {
		case "lb_upstream_host":
			overrideIdx = i
		case "reverse_proxy":
			proxyIdx = i
		}
	}
	if overrideIdx < 0 {
		t.Fatalf("lb_upstream_host handler must be emitted in mixed mode, chain=%#v", chain)
	}
	if proxyIdx < 0 {
		t.Fatalf("reverse_proxy missing, chain=%#v", chain)
	}
	if overrideIdx > proxyIdx {
		t.Fatalf("lb_upstream_host (idx=%d) must precede reverse_proxy (idx=%d)", overrideIdx, proxyIdx)
	}
	if m := findMapHandler(chain); m != nil {
		t.Fatalf("内建 map 处理器必须零发射（自研方案不依赖 http.handlers.map），got %#v", m)
	}

	// H1 三级回退第二档：映射收录**全部有效值非空**的上游——A 命中第一档
	// （自己的 origin_domain），B 命中第二档（回退规则级 host_header）。只收录
	// 第一档会让 B 被处理器未命中兜底到自身地址，规则级回退在那台机上失效。
	h := findUpstreamHostHandler(chain)
	hosts, ok := h["hosts"].(map[string]string)
	if !ok {
		t.Fatalf("lb_upstream_host.hosts type=%T", h["hosts"])
	}
	if len(hosts) != 2 ||
		hosts["10.0.0.1:8080"] != "origin-a.example.com" ||
		hosts["10.0.0.2:8080"] != "backend.example.com" {
		t.Fatalf("hosts=%#v, want A→origin-a.example.com（第一档）、B→backend.example.com（第二档规则级）", hosts)
	}

	proxy := lastReverseProxy(t, chain)
	got := reverseProxyHostSet(t, proxy)
	if len(got) != 1 || got[0] != "{lb.upstream_host}" {
		t.Fatalf("Host set=%#v, want [{lb.upstream_host}]", got)
	}
}

// Given: 规则级后端域名带端口（存量合法形态——Host 头允许 host:port）
// When: 无逐上游回源 Host，https 上游，构建链
// Then (H5): Host 头保留端口原样；SNI 剥离端口（SNI 无端口语义，RFC 6066）
func TestBuildHTTPHandleChain_staticSNIStripsHostHeaderPort(t *testing.T) {
	rule := baseOriginRule("lb_sniport")
	rule.ListenPort = 443
	rule.HostHeader = "backend.example.com:8443"
	upstreams := []UpstreamConfig{
		{Host: "10.0.0.1", Port: 8443, Weight: 1, Enabled: true, Protocol: "https"},
	}

	chain, err := buildHTTPHandleChain(rule, upstreams)
	if err != nil {
		t.Fatalf("buildHTTPHandleChain: %v", err)
	}
	proxy := lastReverseProxy(t, chain)
	tls := proxy["transport"].(map[string]interface{})["tls"].(map[string]interface{})
	if tls["server_name"] != "backend.example.com" {
		t.Fatalf("tls.server_name=%#v, want backend.example.com（剥端口）", tls["server_name"])
	}
	got := reverseProxyHostSet(t, proxy)
	if len(got) != 1 || got[0] != "backend.example.com:8443" {
		t.Fatalf("Host set=%#v, want [backend.example.com:8443]（Host 头保留端口）", got)
	}
}

// Given: 单上游带逐上游回源 Host 且带端口，https 上游（静态统一态）
// When: 构建链
// Then (H5 静态路径): Host 头=原值（含端口），SNI=剥端口值；不发射处理器
func TestBuildHTTPHandleChain_staticCustomHostSNIStripsPort(t *testing.T) {
	rule := baseOriginRule("lb_static_sni")
	rule.ListenPort = 443
	upstreams := []UpstreamConfig{
		{Host: "10.0.0.1", Port: 8443, Weight: 1, Enabled: true, Protocol: "https", OriginDomain: "origin.example.com:9443"},
	}

	chain, err := buildHTTPHandleChain(rule, upstreams)
	if err != nil {
		t.Fatalf("buildHTTPHandleChain: %v", err)
	}
	if h := findUpstreamHostHandler(chain); h != nil {
		t.Fatalf("静态统一态不得发射 lb_upstream_host，got %#v", h)
	}
	proxy := lastReverseProxy(t, chain)
	got := reverseProxyHostSet(t, proxy)
	if len(got) != 1 || got[0] != "origin.example.com:9443" {
		t.Fatalf("Host set=%#v, want [origin.example.com:9443]", got)
	}
	tls := proxy["transport"].(map[string]interface{})["tls"].(map[string]interface{})
	if tls["server_name"] != "origin.example.com" {
		t.Fatalf("tls.server_name=%#v, want origin.example.com（剥端口）", tls["server_name"])
	}
}

// Given: 全回退态（上游与规则级都没有回源 Host）——**TLS 池与纯 http 池都必须**
// When: 构建链
// Then (H2/H4): Host 恒为 {http.reverse_proxy.upstream.hostport}，
// 绝不出现 {http.request.hostport}（客户端 Host）
func TestBuildHTTPHandleChain_fullFallbackNeverUsesClientHost(t *testing.T) {
	for _, tc := range []struct {
		name     string
		protocol string
		port     int
	}{
		{"纯 http 池（上游方案的缺陷分支）", "http", 8080},
		{"https 池", "https", 8443},
	} {
		t.Run(tc.name, func(t *testing.T) {
			rule := baseOriginRule("lb_fallback")
			upstreams := []UpstreamConfig{
				{Host: "10.0.0.1", Port: tc.port, Weight: 1, Enabled: true, Protocol: tc.protocol},
				{Host: "10.0.0.2", Port: tc.port, Weight: 1, Enabled: true, Protocol: tc.protocol},
			}

			chain, err := buildHTTPHandleChain(rule, upstreams)
			if err != nil {
				t.Fatalf("buildHTTPHandleChain: %v", err)
			}
			if h := findUpstreamHostHandler(chain); h != nil {
				t.Fatalf("全回退态不得发射 lb_upstream_host，got %#v", h)
			}
			if m := findMapHandler(chain); m != nil {
				t.Fatalf("内建 map 处理器必须零发射，got %#v", m)
			}
			proxy := lastReverseProxy(t, chain)
			got := reverseProxyHostSet(t, proxy)
			if len(got) != 1 || got[0] != "{http.reverse_proxy.upstream.hostport}" {
				t.Fatalf("Host set=%#v, want [{http.reverse_proxy.upstream.hostport}]", got)
			}
			for _, value := range got {
				if strings.Contains(value, "http.request.") {
					t.Fatalf("Host set=%#v 含客户端请求占位符——绝不允许透传客户端 Host", got)
				}
			}
		})
	}
}

// Given: 混合态 + https 上游
// When: 构建链
// Then (H5): transport.tls.server_name 走 {lb.upstream_sni}（处理器侧剥端口）
func TestBuildHTTPHandleChain_mixedSNIUsesPlaceholder(t *testing.T) {
	rule := baseOriginRule("lb_mixed_sni")
	rule.ListenPort = 443
	upstreams := []UpstreamConfig{
		{Host: "10.0.0.1", Port: 8443, Weight: 1, Enabled: true, Protocol: "https", OriginDomain: "a.example.com"},
		{Host: "10.0.0.2", Port: 8443, Weight: 1, Enabled: true, Protocol: "https", OriginDomain: "b.example.com"},
	}

	chain, err := buildHTTPHandleChain(rule, upstreams)
	if err != nil {
		t.Fatalf("buildHTTPHandleChain: %v", err)
	}
	proxy := lastReverseProxy(t, chain)
	tls, ok := proxy["transport"].(map[string]interface{})["tls"].(map[string]interface{})
	if !ok {
		t.Fatalf("transport.tls missing: %#v", proxy["transport"])
	}
	if tls["server_name"] != "{lb.upstream_sni}" {
		t.Fatalf("tls.server_name=%#v, want {lb.upstream_sni}", tls["server_name"])
	}
}

// Given: 规则级后端域名非空、全部上游未自定义（全统一静态态）
// When: 构建链
// Then (H6): Host 直接下发静态值，不发射 handler、不发映射
func TestBuildHTTPHandleChain_ruleLevelStaticNoHandler(t *testing.T) {
	rule := baseOriginRule("lb_rule_static")
	rule.HostHeader = "backend.example.com"
	upstreams := []UpstreamConfig{
		{Host: "10.0.0.1", Port: 8080, Weight: 1, Enabled: true},
		{Host: "10.0.0.2", Port: 8080, Weight: 1, Enabled: true},
	}

	chain, err := buildHTTPHandleChain(rule, upstreams)
	if err != nil {
		t.Fatalf("buildHTTPHandleChain: %v", err)
	}
	if h := findUpstreamHostHandler(chain); h != nil {
		t.Fatalf("全统一静态态不得发射 lb_upstream_host，got %#v", h)
	}
	proxy := lastReverseProxy(t, chain)
	got := reverseProxyHostSet(t, proxy)
	if len(got) != 1 || got[0] != "backend.example.com" {
		t.Fatalf("Host set=%#v, want [backend.example.com]", got)
	}
}

// Given: 全部上游自定义了同一回源 Host（规则级为空）
// When: 构建链
// Then (H6): 折叠为静态统一值（无需处理器）
func TestBuildHTTPHandleChain_allCustomSameValueFoldsToStatic(t *testing.T) {
	rule := baseOriginRule("lb_same")
	upstreams := []UpstreamConfig{
		{Host: "10.0.0.1", Port: 8080, Weight: 1, Enabled: true, OriginDomain: "origin.example.com"},
		{Host: "10.0.0.2", Port: 8080, Weight: 1, Enabled: true, OriginDomain: "origin.example.com"},
	}

	chain, err := buildHTTPHandleChain(rule, upstreams)
	if err != nil {
		t.Fatalf("buildHTTPHandleChain: %v", err)
	}
	if h := findUpstreamHostHandler(chain); h != nil {
		t.Fatalf("统一自定义值必须折叠为静态，不得发射 handler，got %#v", h)
	}
	proxy := lastReverseProxy(t, chain)
	got := reverseProxyHostSet(t, proxy)
	if len(got) != 1 || got[0] != "origin.example.com" {
		t.Fatalf("Host set=%#v, want [origin.example.com]", got)
	}
}

// Given: 上游自定义值含首尾空白（带外写入形态）
// When: 构建链
// Then (H1): 计划按 TrimSpace 后的值判定，不产生「看似混合实则统一」的假混合态
func TestBuildHTTPHandleChain_originDomainTrimSpace(t *testing.T) {
	rule := baseOriginRule("lb_trim")
	upstreams := []UpstreamConfig{
		{Host: "10.0.0.1", Port: 8080, Weight: 1, Enabled: true, OriginDomain: "  origin.example.com  "},
		{Host: "10.0.0.2", Port: 8080, Weight: 1, Enabled: true, OriginDomain: "origin.example.com"},
	}

	chain, err := buildHTTPHandleChain(rule, upstreams)
	if err != nil {
		t.Fatalf("buildHTTPHandleChain: %v", err)
	}
	if h := findUpstreamHostHandler(chain); h != nil {
		t.Fatalf("TrimSpace 后取值一致应折叠为静态，got %#v", h)
	}
	got := reverseProxyHostSet(t, lastReverseProxy(t, chain))
	if len(got) != 1 || got[0] != "origin.example.com" {
		t.Fatalf("Host set=%#v, want [origin.example.com]", got)
	}
}

// Given: 被禁用的上游带逐上游回源 Host（不参与负载池）
// When: 构建链
// Then (H1): 计划仅由启用上游决定（禁用行不进入混合判定与映射表）
func TestBuildHTTPHandleChain_disabledUpstreamIgnored(t *testing.T) {
	rule := baseOriginRule("lb_disabled")
	upstreams := []UpstreamConfig{
		{Host: "10.0.0.1", Port: 8080, Weight: 1, Enabled: true},
		{Host: "10.0.0.9", Port: 8080, Weight: 1, Enabled: false, OriginDomain: "ghost.internal"},
	}

	chain, err := buildHTTPHandleChain(rule, upstreams)
	if err != nil {
		t.Fatalf("buildHTTPHandleChain: %v", err)
	}
	if h := findUpstreamHostHandler(chain); h != nil {
		t.Fatalf("禁用上游不得影响计划，got %#v", h)
	}
	got := reverseProxyHostSet(t, lastReverseProxy(t, chain))
	if len(got) != 1 || got[0] != "{http.reverse_proxy.upstream.hostport}" {
		t.Fatalf("Host set=%#v, want [{http.reverse_proxy.upstream.hostport}]", got)
	}
}

// Given: DynamicDNS 单上游且未自定义（保存链强制单启用上游）
// When: 构建链
// Then: 全回退占位符（逐解析 IP 用自身地址），不发射处理器
func TestBuildHTTPHandleChain_dynamicDNSSingleUpstreamPlaceholder(t *testing.T) {
	rule := baseOriginRule("lb_ddns")
	rule.DynamicDNS = true
	upstreams := []UpstreamConfig{
		{Host: "backend.example.com", Port: 80, Weight: 1, Enabled: true},
	}

	chain, err := buildHTTPHandleChain(rule, upstreams)
	if err != nil {
		t.Fatalf("buildHTTPHandleChain: %v", err)
	}
	if h := findUpstreamHostHandler(chain); h != nil {
		t.Fatalf("dynamic_dns 单上游须留在全回退态，got %#v", h)
	}
	got := reverseProxyHostSet(t, lastReverseProxy(t, chain))
	if len(got) != 1 || got[0] != "{http.reverse_proxy.upstream.hostport}" {
		t.Fatalf("Host set=%#v, want [{http.reverse_proxy.upstream.hostport}]", got)
	}
}

// Given: 上游对端身份由逐上游回源 Host 决定（origin.example.com），规则级为空
// When: 构建链并检查主动健康检查段
// Then: **健康检查 Host 的来源与回源 Host 计划解耦**（既定语义：probe Host 只由
// health_check_host / host_header 决定，不读上游行的 origin_domain）——
// 两者皆空时不发射 headers 键。本用例是该语义的钉子：恢复自研实现后**不得**
// 把 probe Host 改成读逐上游值（那会让 handler 级 probe 语义与上游自研版不一致，
// 且 probe 无法逐上游）。上游已修能力 health_check_host 由下一个用例覆盖。
func TestBuildHTTPHandleChain_activeHealthCheckHostUnchangedByOriginDomain(t *testing.T) {
	rule := baseOriginRule("lb_hc_uniform")
	rule.EnableActiveHealthCheck = true
	rule.HealthCheckPath = "/healthz"
	upstreams := []UpstreamConfig{
		{Host: "10.0.0.1", Port: 8080, Weight: 1, Enabled: true, OriginDomain: "origin.example.com"},
	}

	chain, err := buildHTTPHandleChain(rule, upstreams)
	if err != nil {
		t.Fatalf("buildHTTPHandleChain: %v", err)
	}
	proxy := lastReverseProxy(t, chain)
	hc, ok := proxy["health_checks"].(map[string]interface{})
	if !ok {
		t.Fatalf("health_checks missing: %#v", proxy)
	}
	active, ok := hc["active"].(map[string]interface{})
	if !ok {
		t.Fatalf("health_checks.active missing: %#v", hc)
	}
	if headers, hasHeaders := active["headers"].(map[string]interface{}); hasHeaders {
		t.Fatalf("两者皆空时 active.headers 必须不发射（probe Host 不读逐上游值），got %#v", headers)
	}
	// 正向：代理请求侧确实用了该逐上游值（同一规则两处语义各自正确）。
	got := reverseProxyHostSet(t, proxy)
	if len(got) != 1 || got[0] != "origin.example.com" {
		t.Fatalf("Host set=%#v, want [origin.example.com]", got)
	}
}

// Given: 主动健康检查开启 + 健康检查域名已配（规则级后端域名亦配）
// When: 构建链
// Then: health_checks.active.headers.Host=健康检查域名（优先级高于后端域名）
// ——**上游已修能力 health_check_host 必须保留**（派活禁止事项 5）
func TestBuildHTTPHandleChain_healthCheckHostOverridesProbeHost(t *testing.T) {
	upstreams := []UpstreamConfig{{Host: "10.0.0.1", Port: 8080, Weight: 1, Enabled: true}}
	for _, tc := range []struct {
		name            string
		hostHeader      string
		healthCheckHost string
		wantHost        string
		wantAbsent      bool
	}{
		{"健康检查域名优先于后端域名", "backend.example.com", "probe.example.com", "probe.example.com", false},
		{"留空跟随后端域名（现状钉）", "backend.example.com", "", "backend.example.com", false},
		{"两者皆空不发射 headers 键（现状钉）", "", "", "", true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			rule := baseOriginRule("lb_hc")
			rule.HostHeader = tc.hostHeader
			rule.HealthCheckHost = tc.healthCheckHost
			rule.EnableActiveHealthCheck = true
			chain, err := buildHTTPHandleChain(rule, upstreams)
			if err != nil {
				t.Fatalf("buildHTTPHandleChain: %v", err)
			}
			proxy := lastReverseProxy(t, chain)
			healthChecks, ok := proxy["health_checks"].(map[string]interface{})
			if !ok {
				t.Fatalf("health_checks missing: %#v", proxy)
			}
			active, ok := healthChecks["active"].(map[string]interface{})
			if !ok {
				t.Fatalf("health_checks.active missing: %#v", healthChecks)
			}
			headers, hasHeaders := active["headers"].(map[string]interface{})
			if tc.wantAbsent {
				if hasHeaders {
					t.Fatalf("active.headers must stay absent, got %#v", headers)
				}
				return
			}
			if !hasHeaders {
				t.Fatalf("active.headers missing, want Host=%q", tc.wantHost)
			}
			host, ok := headers["Host"].([]string)
			if !ok || len(host) != 1 || host[0] != tc.wantHost {
				t.Fatalf("active headers Host=%#v, want [%s]", headers["Host"], tc.wantHost)
			}
		})
	}
}

// ── H2 机械扫描钉子 ────────────────────────────────────────────────────────
//
// Given: 全仓**可执行渲染产物**源码（Go / 前端 / 脚本）
// When: 机械扫描「{http.request.hostport} 被当作回源 Host 回退」的代码形态
// Then: 除注释与本钉测自身外，**零出现**——上游 map 方案的缺陷载体不得以任何
// 形式复活（H2 要求）。
//
// 扫描面（为什么这样划）：
//   - `.go` / `.ts` / `.js` / `.vue` / `.sh` / `.yml` / `.yaml`：会真正变成配置或
//     代码的载体，出现即红；
//   - `.md` **不扫**：`docs/upstream-origin-host-compare.zh-CN.md` 与本仓库其余
//     文档需要引用该占位符来解释「官方版缺陷在哪」——那是资产不是缺陷；把它们
//     逼成不能提名字反而降低可追溯性（R1/R3 的防复发依赖这些文档）；
//   - `.npc-teams/` 不扫：任务档案要记录缺陷原文；
//   - 注释行跳过：同上，可追溯的「禁用理由」合法——**但注释判定按扩展名分派**
//     （见 isCommentedLineForExt）：`.yml`/`.yaml` 不享受注释豁免，因为 YAML 块
//     标量（`|` / `>`）的内容行不以 `#` 开头，若按行首 `#` 豁免，块标量里嵌的
//     配置片段会被当作注释跳过——H2 的机械保证在该形态下失效（r1 风控 P2-2）。
//     代价：yml 里写 `# ...` 的说明性注释也会命中，需改写措辞（有意从严：
//     宁可让人改注释，不留绕过面）。
func TestUpstreamHost_noClientHostFallbackAnywhere(t *testing.T) {
	root, err := filepath.Abs("../..")
	if err != nil {
		t.Fatalf("abs root: %v", err)
	}
	const needle = "{http.request.hostport}"

	var offenders []string
	skipDirs := map[string]bool{
		"node_modules": true, ".git": true, "dist": true, "testdata": true, ".npc-teams": true,
	}
	err = filepath.Walk(root, func(path string, info os.FileInfo, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		name := info.Name()
		if info.IsDir() {
			if skipDirs[name] {
				return filepath.SkipDir
			}
			return nil
		}
		// 只扫可执行载体；.md 等文档（解释缺陷用）不在扫描面。
		switch filepath.Ext(name) {
		case ".go", ".ts", ".js", ".vue", ".sh", ".yml", ".yaml":
		default:
			return nil
		}
		// 钉测本体豁免：**断言「该占位符不得出现」的测试文件自己必须写出它**。
		// 按「文件内出现该 needle 的断言语句 + 文件名以 _test.go 结尾」无法机械
		// 区分「断言用」与「生产用」，故显式列白 —— 但清单必须最小且带理由，
		// 新增成员即代码评审可见（比模糊规则更安全）。
		switch name {
		case "caddy_upstream_origin_test.go",
			// 本文件：H2 扫描器与全部 H 组钉子（needle 常量定义在此）。
			"caddy_emit_config_validate_test.go",
			// 产物层断言：整份生成配置里零出现（H2 在产物层再兜一次）。
			"caddy_decode_generated_config_test.go":
			// Caddy 解码链侧：读产物后先断言零出现，再走模块加载。
			return nil
		}
		body, readErr := os.ReadFile(path)
		if readErr != nil {
			return readErr
		}
		for i, line := range strings.Split(string(body), "\n") {
			if !strings.Contains(line, needle) {
				continue
			}
			trimmed := strings.TrimSpace(line)
			if isCommentedLineForExt(filepath.Ext(name), trimmed) {
				continue // 注释/文档说明：可追溯的「禁用理由」，非缺陷载体
			}
			rel, _ := filepath.Rel(root, path)
			offenders = append(offenders, rel+":"+itoaLine(i+1)+"  "+trimmed)
		}
		return nil
	})
	if err != nil {
		t.Fatalf("walk: %v", err)
	}
	if len(offenders) != 0 {
		t.Fatalf("发现把 {http.request.hostport} 用作回源 Host 回退的非注释代码（上游缺陷形态，H2 禁止）:\n%s",
			strings.Join(offenders, "\n"))
	}
}

// itoaLine 小工具（避免为了一个整数格式化引入额外 import 依赖歧义）。
func itoaLine(n int) string {
	if n == 0 {
		return "0"
	}
	var digits []byte
	for n > 0 {
		digits = append([]byte{byte('0' + n%10)}, digits...)
		n /= 10
	}
	return string(digits)
}

// isCommentedLineForExt 按**文件扩展名**判定一行是否为注释（可豁免）。
//
// 为什么必须按扩展名分派（r1 风控 P2-2）：Go / TS / Vue / Shell 的行首
// `//` `*` `/*` `#` 是注释；但 YAML 的块标量（`|` / `>`）内容行**不以 `#` 开头**，
// 若对 `.yml`/`.yaml` 也套行首 `#` 豁免，块标量里嵌入的配置片段会被当作注释
// 跳过 → H2「全仓零出现」的机械保证在该形态下失效。
// 故 `.yml`/`.yaml` **不做注释豁免**（YAML 有意义的载荷一律在扫描面内）。
func isCommentedLineForExt(ext, trimmed string) bool {
	switch ext {
	case ".yml", ".yaml":
		// 意图明确：不豁免。YAML 的行内注释无法与块标量内容机械区分，
		// 一律按载荷处理（见上方注释的代价说明）。
		return false
	}
	return strings.HasPrefix(trimmed, "//") || strings.HasPrefix(trimmed, "*") ||
		strings.HasPrefix(trimmed, "/*") || strings.HasPrefix(trimmed, "#")
}

// Given: 各扩展名的注释豁免规则
// When: 对同样的行内容求值
// Then: `.yml`/`.yaml` 一律不豁免（块标量绕过面封死）；其余载体按惯例豁免注释
func TestUpstreamHost_commentExemptionByExtension(t *testing.T) {
	cases := []struct {
		name    string
		ext     string
		line    string
		want    bool
		comment string
	}{
		{"go 行注释", ".go", "// 说明", true, ""},
		{"go 块注释首行", ".go", "/* 说明 */", true, ""},
		{"go 块注释续行", ".go", "* 续行", true, ""},
		{"go 可执行行", ".go", `host = "{http.request.hostport}"`, false, ""},
		{"shell 注释", ".sh", "# 说明", true, ""},
		{"ts 注释", ".ts", "// 说明", true, ""},
		{"vue 注释", ".vue", "# 说明", true, ""},
		{"yaml 行内注释形态也不豁免", ".yml", "# 说明", false,
			"YAML 的行内注释与块标量内容无法机械区分，全按载荷处理"},
		{"yaml 块标量内容行", ".yaml", "  host: \"{http.request.hostport}\"", false,
			"块标量（| / >）内容行不以 # 开头——这正是 r1 的绕过面"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := isCommentedLineForExt(tc.ext, strings.TrimSpace(tc.line)); got != tc.want {
				t.Fatalf("isCommentedLineForExt(%q, %q)=%v, want %v %s",
					tc.ext, tc.line, got, tc.want, tc.comment)
			}
		})
	}
}

// Given: H2 扫描器的钉测本体豁免清单
// When: 逐项核对
// Then: ①清单条目恰为预期的三个（多一个都算悄悄放宽，须评审）；
// ②每个文件确实存在于仓库内（改名/删除后清单不能静默残留）；
// ③除这三份以外，没有任何 `*_test.go` 同时含该占位符又不在清单里。
// ——这条把「豁免清单」本身也纳入机械校验，防止它成为绕过面。
func TestUpstreamHost_needleExemptionListIsMinimal(t *testing.T) {
	allow := []string{
		"caddy_upstream_origin_test.go",
		"caddy_emit_config_validate_test.go",
		"caddy_decode_generated_config_test.go",
	}
	want := len(allow)
	if want != 3 {
		t.Fatalf("豁免清单变更（%d 项）——新增豁免必须在评审中显式确认", want)
	}

	root, err := filepath.Abs("../..")
	if err != nil {
		t.Fatalf("abs root: %v", err)
	}
	allowed := make(map[string]bool, len(allow))
	for _, name := range allow {
		allowed[name] = true
	}

	seen := map[string]bool{}
	const needle = "{http.request.hostport}"
	err = filepath.Walk(root, func(path string, info os.FileInfo, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		name := info.Name()
		if info.IsDir() {
			switch name {
			case "node_modules", ".git", "dist", "testdata", ".npc-teams":
				return filepath.SkipDir
			}
			return nil
		}
		if filepath.Ext(name) != ".go" || !strings.HasSuffix(name, "_test.go") {
			return nil
		}
		body, readErr := os.ReadFile(path)
		if readErr != nil {
			return readErr
		}
		// 只看**非注释行**：注释里提缺陷原文是合法资产（主扫描器也放行）。
		hasPayload := false
		for _, line := range strings.Split(string(body), "\n") {
			if !strings.Contains(line, needle) {
				continue
			}
			if isCommentedLineForExt(filepath.Ext(name), strings.TrimSpace(line)) {
				continue
			}
			hasPayload = true
			break
		}
		if !hasPayload {
			return nil
		}
		if allowed[name] {
			seen[name] = true
			return nil
		}
		rel, _ := filepath.Rel(root, path)
		t.Fatalf("测试文件 %s 在**非注释行**含该占位符但不在豁免清单内——要么它是钉测本体（加进清单并说明理由），要么它把缺陷写进了测试", rel)
		return nil
	})
	if err != nil {
		t.Fatalf("walk: %v", err)
	}
	for _, name := range allow {
		if !seen[name] {
			t.Fatalf("豁免清单里的 %s 在仓库中不存在（改名/删除后必须同步清理清单）", name)
		}
	}
}

// Given: 一份带块标量的 YAML 文本（内容行不以 `#` 开头）
// When: 用扫描器的行判定过一遍
// Then: 块标量里的 {http.request.hostport} **被判定为载荷**（不再被当注释跳过）
// ——这是 P2-2 的端到端复核：证明绕过面确实封死了，而不只是规则函数改对了。
func TestUpstreamHost_yamlBlockScalarIsScanned(t *testing.T) {
	const needle = "{http.request.hostport}"
	yamlText := strings.Join([]string{
		"caddy:",
		"  route: |",
		"    handle:",
		`      - headers: {request: {set: {Host: ["` + needle + `"]}}}`,
	}, "\n")
	hits := 0
	for _, line := range strings.Split(yamlText, "\n") {
		if !strings.Contains(line, needle) {
			continue
		}
		if isCommentedLineForExt(".yml", strings.TrimSpace(line)) {
			continue // 被误豁免
		}
		hits++
	}
	if hits != 1 {
		t.Fatalf("块标量里的占位符命中数=%d, want 1（0 表示仍被当注释跳过=绕过面未封死）", hits)
	}
}

// Given: 渲染链源码
// When: 机械扫描
// Then: 内建 map 方案的三处形态（originDomains / originDialOrder /
// "http.handlers.map" 发射）在 caddy.go 中**零出现**——替换必须彻底，不得留
// 半套死代码。
func TestUpstreamHost_mapPlanFullyRemoved(t *testing.T) {
	body, err := os.ReadFile("caddy.go")
	if err != nil {
		t.Fatalf("read caddy.go: %v", err)
	}
	source := string(body)
	for _, needle := range []string{"originDomains", "originDialOrder", `"handler":      "map"`, `"handler": "map"`} {
		if idx := strings.Index(source, needle); idx >= 0 {
			line := 1 + strings.Count(source[:idx], "\n")
			t.Fatalf("caddy.go:%d 仍残留上游 map 方案形态 %q——自研替换必须彻底", line, needle)
		}
	}
}

// ── D3 存量数据零丢失 ─────────────────────────────────────────────────────

// Given: 存量库形态——`upstreams.origin_domain` 已有非空值（本任务不做任何迁移）
// When: 走真实生成链路（DB → 渲染）
// Then (D3): 该存量值仍作为该上游的回源 Host 生效；且**绝不**退化为客户端
// Host 回退形态。列名保持 `origin_domain` 不变，故存量库升级后无需二次搬迁。
func TestUpstreamHost_legacyOriginDomainStillEffective(t *testing.T) {
	_, database := newClusterTestService(t)
	seedGenerationRule(t, database, "lb_d3", false)
	if _, err := database.Exec(`UPDATE lb_rules SET domain='legacy.example.com', host_header='', listen_port=18499 WHERE caddy_id='lb_d3'`); err != nil {
		t.Fatalf("update rule: %v", err)
	}
	if _, err := database.Exec(`DELETE FROM upstreams WHERE rule_id='lb_d3'`); err != nil {
		t.Fatalf("clear upstreams: %v", err)
	}
	if _, err := database.Exec(`INSERT INTO upstreams (rule_id,host,port,weight,enabled,protocol,origin_domain) VALUES ('lb_d3','10.9.9.1',8080,1,1,'http','legacy-origin.internal')`); err != nil {
		t.Fatalf("insert upstream: %v", err)
	}

	generated := generateCaddyConfigFromStore(database)
	if msg, failed := generated[caddyConfigGenerationErrorKey].(string); failed {
		t.Fatalf("generation failed: %s", msg)
	}
	var host []string
	for _, route := range renderedHTTPRoutesFromGenerated(t, generated) {
		for _, raw := range renderedHandleChain(t, route) {
			entry, ok := raw.(map[string]interface{})
			if !ok || entry["handler"] != "reverse_proxy" {
				continue
			}
			headers, _ := entry["headers"].(map[string]interface{})
			request, _ := headers["request"].(map[string]interface{})
			set, _ := request["set"].(map[string]interface{})
			values, _ := set["Host"].([]interface{})
			for _, value := range values {
				if text, ok := value.(string); ok {
					host = append(host, text)
				}
			}
		}
	}
	if len(host) != 1 || host[0] != "legacy-origin.internal" {
		t.Fatalf("Host=%v; want [legacy-origin.internal]（存量 origin_domain 必须仍生效）", host)
	}
	for _, h := range host {
		if strings.Contains(h, "http.request.") {
			t.Fatalf("Host=%v 是客户端 Host 回退形态：存量数据未生效", host)
		}
	}
}
