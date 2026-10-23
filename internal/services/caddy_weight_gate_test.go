package services

import (
	"encoding/json"
	"testing"
)

// 上游权重非正值的渲染不变量
// Caddy v2.11.4 WeightedRoundRobinSelection.Provision 仅累加 Weights，
// Select 首行 `currentWeight := int(r.index.Add(1)) % r.totalWeight`——全 0 权重
// 使 totalWeight=0 → 每请求 integer divide by zero panic（net/http 按连接
// recover，连接被重置）。写侧（rules.go 主上游 0→1）与渲染侧
// buildHTTPHandleChain 的 `weight <= 0 → 1` 收集归一共同保证不变量：
// **任何发射到引擎的权重恒 > 0**（含路径规则上游，二者共用本链构建器）。
func TestBuildHTTPHandleChain_nonPositiveWeightsNormalized(t *testing.T) {
	extractWeights := func(t *testing.T, chain []interface{}) []int {
		t.Helper()
		raw, err := json.Marshal(chain)
		if err != nil {
			t.Fatalf("marshal chain: %v", err)
		}
		var generic interface{}
		if err := json.Unmarshal(raw, &generic); err != nil {
			t.Fatalf("unmarshal chain: %v", err)
		}
		var found []int
		var walk func(v interface{})
		walk = func(v interface{}) {
			switch node := v.(type) {
			case map[string]interface{}:
				if w, ok := node["weights"].([]interface{}); ok {
					for _, item := range w {
						if f, ok := item.(float64); ok {
							found = append(found, int(f))
						}
					}
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
		if len(found) == 0 {
			t.Fatalf("weighted_round_robin 池未发射 weights（路径/主上游链形状变化）:\n%s", raw)
		}
		return found
	}

	cases := []struct {
		name  string
		input []int
		want  []int
	}{
		{name: "全 0（API/导入/集群应用可携带的畸形形状）", input: []int{0, 0}, want: []int{1, 1}},
		{name: "负值（防御性：写侧已拒，渲染仍兜底）", input: []int{-5, 2}, want: []int{1, 2}},
		{name: "混合 0 与正值（回归形状：正值不被改写）", input: []int{0, 3}, want: []int{1, 3}},
		{name: "单上游 0（len<2 早退路径）", input: []int{0}, want: []int{1}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			rule := SingleRuleConfig{HealthCheckInterval: 10, HealthCheckTimeout: 2, HealthCheckUnhealthyThreshold: 3, HealthCheckHealthyThreshold: 2, GlobalRequestBodyMaxSizeMB: 128, CaddyID: "lb_weight_gate",
				Domain:   "weight-gate.test",
				Protocol: "http",
				Strategy: "weighted_round_robin"}
			ups := make([]UpstreamConfig, 0, len(tc.input))
			for i, w := range tc.input {
				ups = append(ups, UpstreamConfig{
					Host: "127.0.0.1", Port: 9100 + i, Weight: w, Protocol: "http", Enabled: true,
				})
			}
			got := extractWeights(t, mustChain(t, rule, ups))
			if len(got) != len(tc.want) {
				t.Fatalf("weights 数量=%d want=%d (got=%v)", len(got), len(tc.want), got)
			}
			for i := range got {
				if got[i] != tc.want[i] {
					t.Fatalf("weights=%v want=%v", got, tc.want)
				}
			}
			// 不变量：发射值恒 > 0（引擎除零 panic 的唯一入口）
			for i, w := range got {
				if w <= 0 {
					t.Fatalf("weights[%d]=%d ≤ 0 → WRR totalWeight=0 → Select 除零 panic", i, w)
				}
			}
		})
	}
}

func mustChain(t *testing.T, rule SingleRuleConfig, ups []UpstreamConfig) []interface{} {
	t.Helper()
	chain, err := buildHTTPHandleChain(rule, ups)
	if err != nil {
		t.Fatalf("buildHTTPHandleChain: %v", err)
	}
	return chain
}

// normalizeWeights 的 gcd 约分口径：只按正权重求 gcd、非正项置 0 且不参与
// 求解；gcd<=1 时原样返回（含全零/单元素/互素三种「约分无意义」形态）。
func TestNormalizeWeights_gcdReduction(t *testing.T) {
	cases := []struct {
		name string
		in   []int
		want []int
	}{
		{name: "gcd 2", in: []int{4, 10}, want: []int{2, 5}},
		{name: "gcd 3", in: []int{6, 9}, want: []int{2, 3}},
		{name: "互素原样", in: []int{3, 5}, want: []int{3, 5}},
		{name: "单元素约到 1", in: []int{7}, want: []int{1}},
		{name: "非正项置 0 且不参与", in: []int{-5, 10}, want: []int{0, 1}},
		{name: "全零原样", in: []int{0, 0}, want: []int{0, 0}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := normalizeWeights(append([]int(nil), tc.in...))
			if len(got) != len(tc.want) {
				t.Fatalf("weights=%v, want %v", got, tc.want)
			}
			for i := range got {
				if got[i] != tc.want[i] {
					t.Fatalf("normalizeWeights(%v)=%v, want %v", tc.in, got, tc.want)
				}
			}
		})
	}
}

// TCP 权重不变量：与 HTTP 侧不同，layer4 侧不归一也不约分——非正权重直接
// 省略 weight 键（引擎按默认 1 处理），正值如实发射（6/9 不被 gcd 约分）。
// 披露：装配层 weight<=0→1 与「weight>1 才发射」门控在产物上等价（省略键
// 即取默认 1），无法用产物反证该冗余，故本用例钉的是产物不变量本身。
func TestGenerateCaddyConfig_tcpWeightsStayPositive(t *testing.T) {
	rule := SingleRuleConfig{
		CaddyID:                       "lb_tcp_weight",
		Protocol:                      "tcp",
		Strategy:                      "weighted_round_robin",
		HealthCheckInterval:           10,
		HealthCheckUnhealthyThreshold: 3,
		Upstreams: []UpstreamConfig{
			{Host: "127.0.0.1", Port: 9101, Weight: 0, Protocol: "tcp", Enabled: true},
			{Host: "127.0.0.1", Port: 9102, Weight: -5, Protocol: "tcp", Enabled: true},
			{Host: "127.0.0.1", Port: 9103, Weight: 6, Protocol: "tcp", Enabled: true},
			{Host: "127.0.0.1", Port: 9104, Weight: 9, Protocol: "tcp", Enabled: true},
		},
	}

	route, err := buildTCPProxyRoute(rule)
	if err != nil {
		t.Fatalf("buildTCPProxyRoute: %v", err)
	}
	handlers, ok := route["handle"].([]interface{})
	if !ok || len(handlers) != 1 {
		t.Fatalf("TCP 路由 handle 形状异常: %#v", route["handle"])
	}
	proxy, ok := handlers[0].(map[string]interface{})
	if !ok {
		t.Fatalf("TCP handler 类型=%T", handlers[0])
	}
	upstreams, ok := proxy["upstreams"].([]interface{})
	if !ok || len(upstreams) != 4 {
		t.Fatalf("TCP 上游形状异常: %#v", proxy["upstreams"])
	}

	// 前两条非正权重：省略 weight 键（引擎默认 1），不得发射 0/负值。
	for i, wantAbsent := range []bool{true, true, false, false} {
		entry, ok := upstreams[i].(map[string]interface{})
		if !ok {
			t.Fatalf("TCP 上游 #%d 类型=%T", i, upstreams[i])
		}
		weight, present := entry["weight"]
		if wantAbsent {
			if present {
				t.Fatalf("TCP 上游 #%d 非正权重必须省略 weight 键，实际 %v", i, weight)
			}
			continue
		}
		want := 6
		if i == 3 {
			want = 9
		}
		if !present || weight != want {
			t.Fatalf("TCP 上游 #%d weight=%v（present=%v），want %d（不 gcd 约分）", i, weight, present, want)
		}
	}
}
