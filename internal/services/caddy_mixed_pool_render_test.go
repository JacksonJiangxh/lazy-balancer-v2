package services

// 混布池渲染分派钉测（JJC-20261118-002 S2）：
//   - uniform 基线（R5 体例）：uniform 池渲染产物与 S2 改造前 HEAD（452553f7）
//     同 fixture 渲染逐字节一致（sha256 常量内嵌，无透传先例同法）——
//     uniform+weighted_round_robin 照走 reverse_proxy、uniform+chain_fallback
//     维持 chain_proxy race 现状，渲染分派不得触碰 uniform 路径；
//   - 混布池触发器：启用池 http/https 混布即整池切 chain 模块承载（不分策略，
//     兜存量脏行——绝不落 reverse_proxy）；mode 推导=chain_fallback→race、
//     其余一律 wrr（含空串归一），以包级常量+单源函数实现
//    （render_anti_fallback_scan_test.go 机械扫描面合规）。
//
// 基线生成方法：git worktree add <dir> 452553f7 → 本文件复制进 worktree 同路径 →
// CADDY_MP_FIXTURE_OUT=<out> go test -run TestMixedPoolRender_uniformBaseline
// ./internal/services → 输出 sha256 写入 mixedUniformBaselineSHA256。

import (
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"os"
	"strings"
	"testing"
)

// mixedUniformBaselineSHA256 是 452553f7（S2 渲染改造前 HEAD）对
// seedMixedPoolUniformFixture 同一 fixture 渲染产物的 sha256（R5 体例）。
const mixedUniformBaselineSHA256 = "b2664c0b6e7076740e822e59a2c46dcd85cd287d6c503122df964a4903f2adcc"

// seedMixedPoolUniformFixture 构造 uniform 池基线 fixture：三条启用 HTTP 规则
// （uniform weighted_round_robin 多上游 / uniform chain_fallback 多上游 /
// uniform 空策略），全部纯 http 上游——不触发混布触发器的渲染面。
func seedMixedPoolUniformFixture(t *testing.T, database *sql.DB) {
	t.Helper()
	seeds := []struct {
		id       string
		port     int
		strategy string
	}{
		{"lb_mp_uniform_wrr", 19601, "weighted_round_robin"},
		{"lb_mp_uniform_chain", 19602, "chain_fallback"},
		{"lb_mp_uniform_empty", 19603, ""},
	}
	for _, s := range seeds {
		if _, err := database.Exec(`INSERT INTO lb_rules (caddy_id,name,description,protocol,domain,listen_port,strategy,enabled)
			VALUES (?,?,'','http',?,?,'',1)`, s.id, s.id, "mp-uniform.test", s.port, s.strategy); err != nil {
			t.Fatalf("seed uniform rule %s: %v", s.id, err)
		}
	}
	for _, s := range seeds {
		if _, err := database.Exec(`INSERT INTO upstreams (rule_id,host,port,weight,enabled,protocol) VALUES
			(?,'10.0.0.1',8001,1,1,'http'),(?,'10.0.0.2',8002,1,1,'http')`, s.id, s.id); err != nil {
			t.Fatalf("seed uniform upstreams %s: %v", s.id, err)
		}
	}
}

// mixedPoolFixtureDigest 用生产渲染链渲染指定种子库，返回 sha256 与产物字节。
func mixedPoolFixtureDigest(t *testing.T, database *sql.DB) (string, []byte) {
	t.Helper()
	cfg := generateCaddyConfigFromStore(database)
	if message, failed := cfg[caddyConfigGenerationErrorKey].(string); failed {
		t.Fatalf("渲染失败: %s", message)
	}
	data, err := json.Marshal(cfg)
	if err != nil {
		t.Fatalf("marshal 渲染产物: %v", err)
	}
	sum := sha256.Sum256(data)
	return hex.EncodeToString(sum[:]), data
}

// TestMixedPoolRender_uniformBaselineByteIdentical uniform 池 R5 零回归：
// 渲染产物与 452553f7 基线逐字节一致（uniform+ wrr → reverse_proxy 现状；
// uniform+chain_fallback → chain_proxy race 现状——分派不得触碰 uniform 路径）。
func TestMixedPoolRender_uniformBaselineByteIdentical(t *testing.T) {
	_, database := newClusterTestService(t)
	seedMixedPoolUniformFixture(t, database)

	digest, data := mixedPoolFixtureDigest(t, database)
	if out := os.Getenv("CADDY_MP_FIXTURE_OUT"); out != "" {
		if err := os.WriteFile(out, data, 0o600); err != nil {
			t.Fatalf("emit fixture: %v", err)
		}
	}
	if strings.HasPrefix(mixedUniformBaselineSHA256, "MIXED_UNIFORM_BASELINE") {
		t.Logf("基线常量未填充：当前 fixture 产物 sha256=%s", digest)
		return
	}
	if digest != mixedUniformBaselineSHA256 {
		t.Fatalf("R5 红线：uniform 池渲染产物与 452553f7 基线不一致\n got sha256=%s\nwant sha256=%s\n产物=%s",
			digest, mixedUniformBaselineSHA256, truncateForLog(data))
	}
}

// findChainProxyHandler 在渲染链中查找 chain_proxy handler（末个命中=终端）。
func findChainProxyHandler(t *testing.T, chain []interface{}) map[string]interface{} {
	t.Helper()
	raw, err := json.Marshal(chain)
	if err != nil {
		t.Fatalf("marshal chain: %v", err)
	}
	var generic interface{}
	if err := json.Unmarshal(raw, &generic); err != nil {
		t.Fatalf("unmarshal chain: %v", err)
	}
	var found map[string]interface{}
	var walk func(v interface{})
	walk = func(v interface{}) {
		switch node := v.(type) {
		case map[string]interface{}:
			if node["handler"] == "chain_proxy" {
				found = node
			}
			for _, child := range node {
				walk(child)
			}
		case []interface{}:
			for _, child := range node {
				walk(child)
			}
		}
	}
	walk(generic)
	return found
}

func mustRenderChain(t *testing.T, rule SingleRuleConfig, ups []UpstreamConfig) []interface{} {
	t.Helper()
	chain, err := buildHTTPHandleChain(rule, ups)
	if err != nil {
		t.Fatalf("buildHTTPHandleChain: %v", err)
	}
	return chain
}

// TestMixedPoolRender_mixedWRR 混布池 + weighted_round_robin → chain_proxy
// mode=wrr；逐上游 scheme（https 发射/静默 http）与 weight 发射；reverse_proxy
// 专属键全不发射。
func TestMixedPoolRender_mixedWRR(t *testing.T) {
	rule := SingleRuleConfig{
		CaddyID:                       "lb_mp_wrr",
		Domain:                        "mp-wrr.test",
		Protocol:                      "http",
		RequestBodyMaxSizeMB:          128,
		HealthCheckInterval:           10,
		HealthCheckTimeout:            2,
		HealthCheckUnhealthyThreshold: 3,
		HealthCheckHealthyThreshold:   2,
		Strategy:                      "weighted_round_robin",
	}
	ups := []UpstreamConfig{
		{Host: "10.0.0.1", Port: 8001, Weight: 3, Protocol: "https", Enabled: true},
		{Host: "10.0.0.2", Port: 8002, Weight: 1, Protocol: "http", Enabled: true},
	}
	chain := mustRenderChain(t, rule, ups)
	proxy := findChainProxyHandler(t, chain)
	if proxy == nil {
		t.Fatal("混布池+wrr 未发射 chain_proxy")
	}
	if proxy["mode"] != "wrr" {
		t.Fatalf("mode=%v, want wrr", proxy["mode"])
	}
	raw, _ := json.Marshal(chain)
	for _, forbidden := range []string{`"load_balancing"`, `"health_checks"`, `"selection_policy"`, `"transport"`} {
		if strings.Contains(string(raw), forbidden) {
			t.Fatalf("chain_proxy(wrr) 不应发射 %s:\n%s", forbidden, raw)
		}
	}
	upsOut := proxy["upstreams"].([]interface{})
	u0 := upsOut[0].(map[string]interface{})
	u1 := upsOut[1].(map[string]interface{})
	if u0["scheme"] != "https" {
		t.Fatalf("https 上游 scheme 缺失: %v", u0)
	}
	if _, ok := u1["scheme"]; ok {
		t.Fatalf("http 上游不应发射 scheme: %v", u1)
	}
	if u0["weight"].(float64) != 3 || u1["weight"].(float64) != 1 {
		t.Fatalf("wrr 权重发射缺失: %v / %v", u0, u1)
	}
}

// TestMixedPoolRender_mixedChainFallbackRace 混布池 + chain_fallback → race
// （既有 :5299 分支与池形态无关，mode 键缺省=竞速现状零变化）。
func TestMixedPoolRender_mixedChainFallbackRace(t *testing.T) {
	rule := SingleRuleConfig{
		CaddyID:                       "lb_mp_race",
		Domain:                        "mp-race.test",
		Protocol:                      "http",
		RequestBodyMaxSizeMB:          128,
		HealthCheckInterval:           10,
		HealthCheckTimeout:            2,
		HealthCheckUnhealthyThreshold: 3,
		HealthCheckHealthyThreshold:   2,
		Strategy:                      "chain_fallback",
	}
	ups := []UpstreamConfig{
		{Host: "10.0.0.1", Port: 8001, Weight: 60, Protocol: "https", Enabled: true},
		{Host: "10.0.0.2", Port: 8002, Weight: 20, Protocol: "http", Enabled: true},
	}
	chain := mustRenderChain(t, rule, ups)
	proxy := findChainProxyHandler(t, chain)
	if proxy == nil {
		t.Fatal("混布池+chain_fallback 未发射 chain_proxy")
	}
	if _, ok := proxy["mode"]; ok {
		t.Fatalf("race 模式 mode 键必须缺省（现状零变化）: %v", proxy)
	}
	upsOut := proxy["upstreams"].([]interface{})
	if upsOut[0].(map[string]interface{})["scheme"] != "https" {
		t.Fatalf("混布 race 车道 https scheme 缺失: %v", upsOut)
	}
}

// TestMixedPoolRender_mixedDisallowedStrategyFallsBackWRR 存量脏行兜底
// （渲染触发器不分策略）：混布 + 不允许策略（cookie，直改 DB 形态）渲染 wrr，
// 绝不落 reverse_proxy（钉测 16a / A20）。
func TestMixedPoolRender_mixedDisallowedStrategyFallsBackWRR(t *testing.T) {
	rule := SingleRuleConfig{
		CaddyID:                       "lb_mp_dirty",
		Domain:                        "mp-dirty.test",
		Protocol:                      "http",
		RequestBodyMaxSizeMB:          128,
		HealthCheckInterval:           10,
		HealthCheckTimeout:            2,
		HealthCheckUnhealthyThreshold: 3,
		HealthCheckHealthyThreshold:   2,
		Strategy:                      "cookie",
	}
	ups := []UpstreamConfig{
		{Host: "10.0.0.1", Port: 8001, Weight: 1, Protocol: "https", Enabled: true},
		{Host: "10.0.0.2", Port: 8002, Weight: 1, Protocol: "http", Enabled: true},
	}
	chain := mustRenderChain(t, rule, ups)
	proxy := findChainProxyHandler(t, chain)
	if proxy == nil {
		t.Fatal("混布脏行未切 chain 模块承载")
	}
	if proxy["mode"] != "wrr" {
		t.Fatalf("脏行 mode=%v, want wrr", proxy["mode"])
	}
	raw, _ := json.Marshal(chain)
	if strings.Contains(string(raw), `"reverse_proxy"`) {
		t.Fatalf("混布池绝不落 reverse_proxy:\n%s", raw)
	}
}

// TestMixedPoolRender_emptyStrategyRendersWRR 混布 + 空策略（单源归一口径）
// 渲染 wrr（钉测 20）。
func TestMixedPoolRender_emptyStrategyRendersWRR(t *testing.T) {
	rule := SingleRuleConfig{
		CaddyID:                       "lb_mp_empty",
		Domain:                        "mp-empty.test",
		Protocol:                      "http",
		RequestBodyMaxSizeMB:          128,
		HealthCheckInterval:           10,
		HealthCheckTimeout:            2,
		HealthCheckUnhealthyThreshold: 3,
		HealthCheckHealthyThreshold:   2,
		Strategy:                      "",
	}
	ups := []UpstreamConfig{
		{Host: "10.0.0.1", Port: 8001, Weight: 1, Protocol: "https", Enabled: true},
		{Host: "10.0.0.2", Port: 8002, Weight: 1, Protocol: "http", Enabled: true},
	}
	chain := mustRenderChain(t, rule, ups)
	proxy := findChainProxyHandler(t, chain)
	if proxy == nil || proxy["mode"] != "wrr" {
		t.Fatalf("混布+空策略渲染分派失败: %v", proxy)
	}
}

// TestMixedPoolRender_uniformKeyFaceDispatch uniform 键面分派（钉测 18，
// 结构断言）：uniform+wrr 仍 reverse_proxy 原生键面；uniform+chain_fallback
// 维持 chain_proxy race 现状。
func TestMixedPoolRender_uniformKeyFaceDispatch(t *testing.T) {
	uniform := SingleRuleConfig{
		CaddyID:                       "lb_mp_uniform",
		Domain:                        "mp-uniform.test",
		Protocol:                      "http",
		RequestBodyMaxSizeMB:          128,
		HealthCheckInterval:           10,
		HealthCheckTimeout:            2,
		HealthCheckUnhealthyThreshold: 3,
		HealthCheckHealthyThreshold:   2,
		Strategy:                      "weighted_round_robin",
	}
	httpUps := []UpstreamConfig{
		{Host: "10.0.0.1", Port: 8001, Weight: 1, Protocol: "http", Enabled: true},
		{Host: "10.0.0.2", Port: 8002, Weight: 1, Protocol: "http", Enabled: true},
	}
	chain := mustRenderChain(t, uniform, httpUps)
	if proxy := findChainProxyHandler(t, chain); proxy != nil {
		t.Fatalf("uniform+wrr 必须照走 reverse_proxy，不得唤起 chain 承载: %v", chain)
	}
	foundRP := false
	for _, h := range chain {
		m, ok := h.(map[string]interface{})
		if !ok {
			continue
		}
		if m["handler"] == "reverse_proxy" {
			foundRP = true
		}
	}
	if !foundRP {
		t.Fatalf("uniform+wrr 未发射 reverse_proxy: %v", chain)
	}

	race := SingleRuleConfig{
		CaddyID:                       "lb_mp_uniform_race",
		Domain:                        "mp-uniform-race.test",
		Protocol:                      "http",
		RequestBodyMaxSizeMB:          128,
		HealthCheckInterval:           10,
		HealthCheckTimeout:            2,
		HealthCheckUnhealthyThreshold: 3,
		HealthCheckHealthyThreshold:   2,
		Strategy:                      "chain_fallback",
	}
	chain = mustRenderChain(t, race, httpUps)
	proxy := findChainProxyHandler(t, chain)
	if proxy == nil {
		t.Fatal("uniform+chain_fallback 维持 chain_proxy race 现状失败")
	}
	if _, ok := proxy["mode"]; ok {
		t.Fatalf("uniform+chain_fallback race 现状不得发射 mode 键: %v", proxy)
	}
}

// TestMixedPoolRender_pathPoolMixed 路径池混布两策略渲染（钉测 19）：路径池
// 经同一 buildHTTPHandleChain 渲染——wrr 发 mode/weight，race 维持现状键面；
// 逐上游 host 同口径（origin_domain）。
func TestMixedPoolRender_pathPoolMixed(t *testing.T) {
	ups := []UpstreamConfig{
		{Host: "10.0.0.1", Port: 8001, Weight: 2, Protocol: "https", Enabled: true, OriginDomain: "path-origin.test"},
		{Host: "10.0.0.2", Port: 8002, Weight: 1, Protocol: "http", Enabled: true},
	}
	rule := SingleRuleConfig{
		CaddyID:                       "lb_mp_path",
		Domain:                        "mp-path.test",
		Protocol:                      "http",
		RequestBodyMaxSizeMB:          128,
		HealthCheckInterval:           10,
		HealthCheckTimeout:            2,
		HealthCheckUnhealthyThreshold: 3,
		HealthCheckHealthyThreshold:   2,
		Strategy:                      "weighted_round_robin",
	}
	chain := mustRenderChain(t, rule, ups)
	proxy := findChainProxyHandler(t, chain)
	if proxy == nil || proxy["mode"] != "wrr" {
		t.Fatalf("路径池混布（主池同入口）未渲染 wrr: %v", proxy)
	}
	upsOut := proxy["upstreams"].([]interface{})
	if upsOut[0].(map[string]interface{})["host"] != "path-origin.test" {
		t.Fatalf("路径池回源 Host 同口径失败: %v", upsOut[0])
	}

	rule.Strategy = "chain_fallback"
	chain = mustRenderChain(t, rule, ups)
	proxy = findChainProxyHandler(t, chain)
	if proxy == nil {
		t.Fatal("路径池混布 race 渲染失败")
	}
	if _, ok := proxy["mode"]; ok {
		t.Fatalf("路径池 race 不得发射 mode 键: %v", proxy)
	}
}

// ===== JJC-20261119-001 S2：health_check 发射钉测（裁决 4）=====

// hcEmissionRule 快捷构造：HC 标志/值域可变、混布双车道上游。
func hcEmissionRule(t *testing.T, id, strategy string, hcOn bool, interval, timeout, healthy, unhealthy int, path string) SingleRuleConfig {
	t.Helper()
	return SingleRuleConfig{
		CaddyID:                       id,
		Domain:                        id + ".test",
		Protocol:                      "http",
		RequestBodyMaxSizeMB:          128,
		EnableActiveHealthCheck:       hcOn,
		HealthCheckPath:               path,
		HealthCheckInterval:           interval,
		HealthCheckTimeout:            timeout,
		HealthCheckUnhealthyThreshold: unhealthy,
		HealthCheckHealthyThreshold:   healthy,
		Strategy:                      strategy,
	}
}

var hcEmissionUps = []UpstreamConfig{
	{Host: "10.0.0.1", Port: 8001, Weight: 1, Protocol: "https", Enabled: true},
	{Host: "10.0.0.2", Port: 8002, Weight: 1, Protocol: "http", Enabled: true},
}

// TestMixedPoolRender_healthCheckEmission 混布+HC 发射键面（A2）：race/wrr
// 同发射、值域一致——interval/timeout 秒→毫秒、path 透传、lag 直传；
// expect_status/body 无规则级字段不发射。
func TestMixedPoolRender_healthCheckEmission(t *testing.T) {
	for _, strategy := range []string{"weighted_round_robin", "chain_fallback"} {
		rule := hcEmissionRule(t, "lb_mp_hc", strategy, true, 10, 2, 2, 3, "/hc")
		chain := mustRenderChain(t, rule, hcEmissionUps)
		proxy := findChainProxyHandler(t, chain)
		if proxy == nil {
			t.Fatalf("strategy=%s: 混布+HC 未发射 chain_proxy", strategy)
		}
		hc, ok := proxy["health_check"].(map[string]interface{})
		if !ok {
			t.Fatalf("strategy=%s: chain_proxy 未发射 health_check 键: %v", strategy, proxy)
		}
		if hc["interval_ms"].(float64) != 10000 {
			t.Fatalf("strategy=%s: interval_ms=%v, want 10000（秒→毫秒）", strategy, hc["interval_ms"])
		}
		if hc["timeout_ms"].(float64) != 2000 {
			t.Fatalf("strategy=%s: timeout_ms=%v, want 2000", strategy, hc["timeout_ms"])
		}
		if hc["path"] != "/hc" {
			t.Fatalf("strategy=%s: path=%v, want /hc", strategy, hc["path"])
		}
		if hc["healthy_lag"].(float64) != 2 || hc["unhealthy_lag"].(float64) != 3 {
			t.Fatalf("strategy=%s: lag 阈值发射不一致: %v", strategy, hc)
		}
		if _, ok := hc["expect_status"]; ok {
			t.Fatalf("strategy=%s: expect_status 无规则级字段不得发射: %v", strategy, hc)
		}
		if _, ok := hc["body"]; ok {
			t.Fatalf("strategy=%s: body 无规则级字段不得发射: %v", strategy, hc)
		}
	}
}

// TestMixedPoolRender_healthCheckZeroValuesDirtyRow 存量脏行兜底：HC 标志=1
// 但 interval/path/阈值全零（直改 DB 形态）——零值不发射、不整规则渲染失败
// （模块侧按缺省 30s/5s/2,3/"/"兜底，自动获得真探测）。
func TestMixedPoolRender_healthCheckZeroValuesDirtyRow(t *testing.T) {
	rule := hcEmissionRule(t, "lb_mp_hc_dirty", "weighted_round_robin", true, 0, 0, 0, 0, "")
	chain := mustRenderChain(t, rule, hcEmissionUps)
	proxy := findChainProxyHandler(t, chain)
	if proxy == nil || proxy["mode"] != "wrr" {
		t.Fatalf("脏行渲染分派失败: %v", proxy)
	}
	if _, ok := proxy["health_check"]; ok {
		t.Fatalf("零值脏行不得发射空 health_check（模块缺省兜底）: %v", proxy)
	}
}

// TestMixedPoolRender_uniformReverseProxyHCUnchanged uniform+wrr+HC=true：
// reverse_proxy 原生 health_checks 照常发射、chain_proxy 零唤起——uniform
// 主路径不发射/不触碰（R3 落地，反向钉死）。
func TestMixedPoolRender_uniformReverseProxyHCUnchanged(t *testing.T) {
	uniformUps := []UpstreamConfig{
		{Host: "10.0.0.1", Port: 8001, Weight: 1, Protocol: "http", Enabled: true},
		{Host: "10.0.0.2", Port: 8002, Weight: 1, Protocol: "http", Enabled: true},
	}
	rule := hcEmissionRule(t, "lb_mp_uniform_hc", "weighted_round_robin", true, 10, 2, 2, 3, "/hc")
	chain := mustRenderChain(t, rule, uniformUps)
	if proxy := findChainProxyHandler(t, chain); proxy != nil {
		t.Fatalf("uniform+HC 不得唤起 chain 承载（uniform 路径零改动）: %v", chain)
	}
	raw, _ := json.Marshal(chain)
	if !strings.Contains(string(raw), `"health_checks"`) {
		t.Fatalf("uniform+HC 原生 health_checks 发射缺失:\n%s", raw)
	}
	if strings.Contains(string(raw), `"health_check"`) && !strings.Contains(string(raw), `"health_checks"`) {
		t.Fatalf("uniform 路径不得发射 chain 侧 health_check 单数键:\n%s", raw)
	}
}

// TestMixedPoolRender_uniformChainFallbackHCClosure uniform+chain_fallback+HC
// （A9 收口）：既有「HC 静默忽略」死配置分叉就此关闭——chain_proxy 发射
// health_check 真探测。
func TestMixedPoolRender_uniformChainFallbackHCClosure(t *testing.T) {
	uniformUps := []UpstreamConfig{
		{Host: "10.0.0.1", Port: 8001, Weight: 1, Protocol: "http", Enabled: true},
		{Host: "10.0.0.2", Port: 8002, Weight: 1, Protocol: "http", Enabled: true},
	}
	rule := hcEmissionRule(t, "lb_mp_uniform_chain_hc", "chain_fallback", true, 10, 2, 2, 3, "/hc")
	chain := mustRenderChain(t, rule, uniformUps)
	proxy := findChainProxyHandler(t, chain)
	if proxy == nil {
		t.Fatal("uniform+chain_fallback+HC 未发射 chain_proxy")
	}
	hc, ok := proxy["health_check"].(map[string]interface{})
	if !ok {
		t.Fatalf("uniform+chain_fallback+HC 未发射 health_check（收口失败）: %v", proxy)
	}
	if hc["interval_ms"].(float64) != 10000 || hc["path"] != "/hc" {
		t.Fatalf("收口发射值域不一致: %v", hc)
	}
}
