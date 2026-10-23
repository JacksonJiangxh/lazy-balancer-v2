package services

import (
	"reflect"
	"testing"
)

// 六种负载策略的渲染契约：策略值原样进入 selection_policy.policy（Caddy
// 模块名同源），仅 weighted_round_robin 携带与启用上游序一致的权重，
// Cookie 粘滞固定声明 cookie 名。策略名写错会让 Caddy 加载时找不到模块，
// 权重错位会让流量比例与面板显示不符——两者都必须在渲染层钉死。
func TestGenerateCaddyConfig_rendersAllLoadBalancingStrategies(t *testing.T) {
	cases := []struct {
		strategy    string
		wantCookie  string
		wantWeights []int
	}{
		{strategy: "weighted_round_robin", wantWeights: []int{3, 1}},
		{strategy: "least_conn"},
		{strategy: "ip_hash"},
		{strategy: "random"},
		{strategy: "first"},
		{strategy: "cookie", wantCookie: "lb_sticky"},
	}
	for _, tc := range cases {
		t.Run(tc.strategy, func(t *testing.T) {
			// Given：同一规则两条启用上游，权重 3/1，策略为待测值。
			_, database := newClusterTestService(t)
			if _, err := database.Exec(`INSERT INTO lb_rules (caddy_id,name,protocol,domain,listen_port,strategy,health_check_path,health_check_interval,enabled)
				VALUES (?,?,'http','strategy.example.test',8080,?,'',10,1)`, "lb_strategy", "lb_strategy", tc.strategy); err != nil {
				t.Fatalf("seed rule: %v", err)
			}
			if _, err := database.Exec(`INSERT INTO upstreams (rule_id,host,port,enabled,protocol,weight) VALUES
				('lb_strategy','127.0.0.1',9000,1,'http',3),
				('lb_strategy','127.0.0.1',9001,1,'http',1)`); err != nil {
				t.Fatalf("seed upstreams: %v", err)
			}

			// When：走完整渲染入口，而非单规则构造。
			generated := generateCaddyConfigFromStore(database)

			// Then：策略名、权重序、Cookie 名逐字段对齐。
			if message, failed := generated[caddyConfigGenerationErrorKey].(string); failed {
				t.Fatalf("config generation failed: %s", message)
			}
			routes := httpRoutesFromServer(t, generated, "http_8080")
			if len(routes) != 1 {
				t.Fatalf("routes=%d, want 1", len(routes))
			}
			proxy := reverseProxyHandler(t, routes[0])
			loadBalancing := mustMap(t, proxy["load_balancing"], "load balancing")
			selection := mustMap(t, loadBalancing["selection_policy"], "selection policy")
			if selection["policy"] != tc.strategy {
				t.Fatalf("policy=%v, want %s", selection["policy"], tc.strategy)
			}
			if tc.wantCookie != "" {
				if selection["name"] != tc.wantCookie {
					t.Fatalf("cookie name=%v, want %s", selection["name"], tc.wantCookie)
				}
			}
			if tc.wantWeights != nil {
				weights, ok := selection["weights"].([]int)
				if !ok {
					t.Fatalf("weights has type %T", selection["weights"])
				}
				if !reflect.DeepEqual(weights, tc.wantWeights) {
					t.Fatalf("weights=%v, want %v", weights, tc.wantWeights)
				}
			} else if _, present := selection["weights"]; present {
				t.Fatalf("非加权策略不得发射 weights: %v", selection["weights"])
			}
		})
	}
}
