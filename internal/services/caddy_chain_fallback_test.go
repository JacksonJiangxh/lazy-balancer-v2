package services

import (
	"encoding/json"
	"strings"
	"testing"
)

// 链式回退（chain_fallback）渲染契约（2026-10-09）：
//   - 终端 handler 为 chain_proxy（caddychain 模块），上游按权重降序稳定排序；
//   - reverse_proxy 专属键（load_balancing/health_checks/transport/headers）不发射；
//   - 不发射 weights 键（「发射权重恒 > 0」不变量在 chain 语义下退化为权重排序，
//     见 caddy_weight_gate_test.go 的发射权重扫描口径）；
//   - 竞速参数 0 值兜底 3000/30000（与写侧 CreateRule 同口径）。
func TestBuildHTTPHandleChain_chainFallback_emitsChainProxy(t *testing.T) {
	rule := SingleRuleConfig{
		CaddyID:  "lb_chain_gate",
		Domain:   "chain-gate.test",
		Protocol: "http",
		Strategy: "chain_fallback",
	}
	ups := []UpstreamConfig{
		{Host: "10.0.0.3", Port: 9303, Weight: 20, Protocol: "http", Enabled: true},
		{Host: "10.0.0.1", Port: 9301, Weight: 60, Protocol: "http", Enabled: true},
		{Host: "10.0.0.2", Port: 9302, Weight: 0, Protocol: "http", Enabled: true}, // 0→1，排末位
	}
	chain := mustChain(t, rule, ups)
	raw, err := json.Marshal(chain)
	if err != nil {
		t.Fatalf("marshal chain: %v", err)
	}
	var generic interface{}
	if err := json.Unmarshal(raw, &generic); err != nil {
		t.Fatalf("unmarshal chain: %v", err)
	}

	// 找到 chain_proxy handler（应为链上唯一代理终端）
	var chainProxy map[string]interface{}
	var walk func(v interface{})
	walk = func(v interface{}) {
		switch node := v.(type) {
		case map[string]interface{}:
			if node["handler"] == "chain_proxy" {
				chainProxy = node
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
	if chainProxy == nil {
		t.Fatalf("chain_fallback 未发射 chain_proxy handler:\n%s", raw)
	}
	if _, ok := chainProxy["load_balancing"]; ok {
		t.Fatalf("chain_proxy 不应发射 load_balancing: %v", chainProxy)
	}

	upsOut, _ := chainProxy["upstreams"].([]interface{})
	if len(upsOut) != 3 {
		t.Fatalf("chain upstreams=%d, want 3", len(upsOut))
	}
	dials := make([]string, 0, 3)
	for _, u := range upsOut {
		m, _ := u.(map[string]interface{})
		dials = append(dials, m["dial"].(string))
	}
	// 权重降序：60 → 20 → 0(→1)
	want := []string{"10.0.0.1:9301", "10.0.0.3:9303", "10.0.0.2:9302"}
	for i := range want {
		if dials[i] != want[i] {
			t.Fatalf("chain order=%v, want %v（权重降序稳定排序）", dials, want)
		}
	}

	if chainProxy["race_interval_ms"].(float64) != 3000 {
		t.Fatalf("race_interval_ms=%v, want 3000（0 值渲染兜底）", chainProxy["race_interval_ms"])
	}
	if chainProxy["request_timeout_ms"].(float64) != 30000 {
		t.Fatalf("request_timeout_ms=%v, want 30000（0 值渲染兜底）", chainProxy["request_timeout_ms"])
	}
	if chainProxy["body_replay_limit_bytes"].(float64) != 5*1024*1024 {
		t.Fatalf("body_replay_limit_bytes=%v", chainProxy["body_replay_limit_bytes"])
	}
	stripped, _ := chainProxy["strip_request_headers"].([]interface{})
	if len(stripped) == 0 {
		t.Fatal("chain_proxy 应剥离 X-LB-* 进程内控制头")
	}
	foundRuleID := false
	for _, s := range stripped {
		if s == "X-LB-Rule-ID" {
			foundRuleID = true
		}
	}
	if !foundRuleID {
		t.Fatalf("strip_request_headers 缺 X-LB-Rule-ID: %v", stripped)
	}

	// 不变量：链式规则整链不发射 weights 键
	if strings.Contains(string(raw), `"weights"`) {
		t.Fatalf("chain_fallback 链不应发射 weights 键:\n%s", string(raw))
	}
	// reverse_proxy 专属键整链不发射
	for _, forbidden := range []string{`"health_checks"`, `"selection_policy"`} {
		if strings.Contains(string(raw), forbidden) {
			t.Fatalf("chain_fallback 链不应发射 %s:\n%s", forbidden, string(raw))
		}
	}
}

// 显式参数透传 + dial 超时映射。
func TestBuildChainProxyConfig_paramsAndDialTimeout(t *testing.T) {
	rule := SingleRuleConfig{
		CaddyID:               "lb_chain_params",
		Domain:                "chain-params.test",
		Protocol:              "http",
		Strategy:              "chain_fallback",
		ChainRaceIntervalMS:   800,
		ChainRequestTimeoutMS: 3000,
		ProxyDialTimeout:      2,
	}
	ups := []UpstreamConfig{
		{Host: "10.0.0.9", Port: 9409, Weight: 1, Protocol: "https", Enabled: true, HostHeader: "origin.test"},
	}
	cfg := buildChainProxyConfig(rule, ups)
	if cfg["race_interval_ms"].(int) != 800 || cfg["request_timeout_ms"].(int) != 3000 {
		t.Fatalf("竞速参数透传失败: %v/%v", cfg["race_interval_ms"], cfg["request_timeout_ms"])
	}
	if cfg["dial_timeout_ms"].(int) != 2000 {
		t.Fatalf("dial_timeout_ms=%v, want 2000（秒→毫秒）", cfg["dial_timeout_ms"])
	}
	upsOut := cfg["upstreams"].([]interface{})
	u0 := upsOut[0].(map[string]interface{})
	if u0["scheme"] != "https" {
		t.Fatalf("https 上游 scheme 缺失: %v", u0)
	}
	if u0["host"] != "origin.test" {
		t.Fatalf("逐上游回源 Host 解析失败: %v", u0)
	}
}

// 逐上游回源 Host 三级回退：上游 host_header > 规则级 host_header > 空（不发射）。
func TestBuildChainProxyConfig_hostHeaderFallback(t *testing.T) {
	rule := SingleRuleConfig{
		CaddyID:    "lb_chain_host",
		Protocol:   "http",
		Strategy:   "chain_fallback",
		HostHeader: "rule-level.test",
	}
	ups := []UpstreamConfig{
		{Host: "10.0.0.1", Port: 9501, Weight: 1, Protocol: "http", Enabled: true, HostHeader: "upstream-level.test"},
		{Host: "10.0.0.2", Port: 9502, Weight: 1, Protocol: "http", Enabled: true}, // 回退规则级
		{Host: "10.0.0.3", Port: 9503, Weight: 1, Protocol: "http", Enabled: true},
	}
	rule.HostHeader = ""
	ups[2].HostHeader = "  " // 空白视为空
	cfg := buildChainProxyConfig(rule, ups)
	upsOut := cfg["upstreams"].([]interface{})
	if upsOut[0].(map[string]interface{})["host"] != "upstream-level.test" {
		t.Fatalf("上游级 host_header 应最高优先: %v", upsOut[0])
	}
	if _, ok := upsOut[1].(map[string]interface{})["host"]; ok {
		t.Fatalf("规则级与上游级均空时不发射 host（用 dial 地址兜底）: %v", upsOut[1])
	}
}
