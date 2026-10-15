package services

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// 受信代理（v2.3.x CDN 真实 IP）渲染面：启用时每个 HTTP server（含 :80
// 默认站）注入 trusted_proxies/trusted_proxies_strict/client_ip_headers；
// 禁用时三键全缺席；layer4/admin 不注入。
func TestTrustedProxyRender_serversInjectedWhenEnabled(t *testing.T) {
	// Given
	_, database := newClusterTestService(t)
	seedHTTPRuleForGeneration(t, database, "lb_tp", "tp.example.test", 8080)
	if _, err := database.Exec(`UPDATE global_config SET trusted_proxy_enabled=1, trusted_proxy_ranges='["203.0.113.0/24","198.51.100.7/32"]', trusted_proxy_headers='["CF-Connecting-IP","X-Forwarded-For"]', trusted_proxy_strict=1 WHERE id=1`); err != nil {
		t.Fatal(err)
	}

	// When
	generated := generateCaddyConfigFromStore(database)
	if message, failed := generated[caddyConfigGenerationErrorKey].(string); failed {
		t.Fatalf("generation failed: %s", message)
	}

	// Then：每个 HTTP server 注入三键
	apps := generated["apps"].(map[string]interface{})
	httpApp := apps["http"].(map[string]interface{})
	servers := httpApp["servers"].(map[string]interface{})
	if len(servers) == 0 {
		t.Fatal("no servers rendered")
	}
	for name, serverVal := range servers {
		server := serverVal.(map[string]interface{})
		tp, ok := server["trusted_proxies"].(map[string]interface{})
		if !ok {
			t.Fatalf("server %s missing trusted_proxies: %#v", name, server)
		}
		if tp["source"] != "lb_file" {
			t.Fatalf("server %s trusted_proxies.source=%v, want lb_file（热路径投影源）", name, tp["source"])
		}
		path, _ := tp["path"].(string)
		wantPath := filepath.Join(IPListDataDir, "tp.txt")
		if path != wantPath {
			t.Fatalf("server %s trusted_proxies.path=%v, want %s", name, tp["path"], wantPath)
		}
		// 投影文件须已按合并网段落盘（内联 ∪ 引用名单的渲染副作用）
		raw, err := os.ReadFile(wantPath)
		if err != nil {
			t.Fatalf("读受信代理投影 %s: %v", wantPath, err)
		}
		content := string(raw)
		for _, want := range []string{"203.0.113.0/24", "198.51.100.7/32"} {
			if !strings.Contains(content, want) {
				t.Fatalf("投影内容=%q, want 含 %s", content, want)
			}
		}
		if strict, ok := server["trusted_proxies_strict"]; !ok || strict != 1 {
			t.Fatalf("server %s trusted_proxies_strict=%v, want 1", name, server["trusted_proxies_strict"])
		}
		headers, _ := server["client_ip_headers"].([]string)
		if len(headers) != 2 || headers[0] != "CF-Connecting-IP" {
			t.Fatalf("server %s client_ip_headers=%v", name, server["client_ip_headers"])
		}
	}
	// layer4/admin 不注入
	if l4, ok := apps["layer4"]; ok {
		for name, srv := range l4.(map[string]interface{})["servers"].(map[string]interface{}) {
			if _, has := srv.(map[string]interface{})["trusted_proxies"]; has {
				t.Fatalf("layer4 server %s must not carry trusted_proxies", name)
			}
		}
	}
	if _, has := generated["admin"].(map[string]interface{})["trusted_proxies"]; has {
		t.Fatal("admin must not carry trusted_proxies")
	}
}

func TestTrustedProxyRender_absentWhenDisabled(t *testing.T) {
	// Given：默认（未启用）
	_, database := newClusterTestService(t)
	seedHTTPRuleForGeneration(t, database, "lb_tp_off", "tpoff.example.test", 8080)

	// When
	generated := generateCaddyConfigFromStore(database)
	if message, failed := generated[caddyConfigGenerationErrorKey].(string); failed {
		t.Fatalf("generation failed: %s", message)
	}

	// Then：三键全缺席（行为零变化）
	servers := generated["apps"].(map[string]interface{})["http"].(map[string]interface{})["servers"].(map[string]interface{})
	for name, serverVal := range servers {
		server := serverVal.(map[string]interface{})
		for _, key := range []string{"trusted_proxies", "trusted_proxies_strict", "client_ip_headers"} {
			if _, has := server[key]; has {
				t.Fatalf("server %s must not carry %s when disabled", name, key)
			}
		}
	}
}

// 阶段 0 信任直通 subroute matcher 改用 client_ip（受信代理启用时=真实 IP；
// 未启用时与 remote_ip 同值，行为不变）。
func TestStage0MatcherIsClientIP(t *testing.T) {
	stubSecurityLibsAvailable(t) // 缺库降级：安全链渲染断言前先桩库可用
	// Given：stage0 直通策略绑定
	_, database := newClusterTestService(t)
	seedHTTPRuleForGeneration(t, database, "lb_trust", "trust.example.test", 8080)
	seedStage0Policy(t, database, "lb_trust", `["10.0.0.9"]`, false)

	// When
	generated := generateCaddyConfigFromStore(database)
	if message, failed := generated[caddyConfigGenerationErrorKey].(string); failed {
		t.Fatalf("generation failed: %s", message)
	}
	wire, err := json.Marshal(generated)
	if err != nil {
		t.Fatal(err)
	}

	// Then
	if !strings.Contains(string(wire), `"client_ip":{"ranges":["10.0.0.9/32"]}`) {
		t.Fatalf("stage0 passthrough matcher must use client_ip:\n%s", wire)
	}
	if strings.Contains(string(wire), `"remote_ip"`) {
		t.Fatalf("stage0 passthrough must not use remote_ip (socket IP):\n%s", wire)
	}
}

// 限流 zone key 改用 {http.vars.client_ip}（受信代理启用时=真实 IP，
// 未启用=socket IP，行为不变）——单 zone 与 burst 双 zone 分支同口径。
func TestRateLimitKeyIsClientIP(t *testing.T) {
	stubSecurityLibsAvailable(t) // 缺库降级：安全链渲染断言前先桩库可用
	// Given：burst=0 单 zone + burst>0 双 zone 各一规则
	_, database := newClusterTestService(t)
	seedHTTPRuleForGeneration(t, database, "lb_rl_single", "rl-single.example.test", 8080)
	seedBoundSecurityPolicyWithRateLimit(t, database, "lb_rl_single", "blocking", 100, 0)
	seedHTTPRuleForGeneration(t, database, "lb_rl_burst", "rl-burst.example.test", 8081)
	seedBoundSecurityPolicyWithRateLimit(t, database, "lb_rl_burst", "blocking", 100, 50)

	// When
	generated := generateCaddyConfigFromStore(database)
	if message, failed := generated[caddyConfigGenerationErrorKey].(string); failed {
		t.Fatalf("generation failed: %s", message)
	}
	wire, err := json.Marshal(generated)
	if err != nil {
		t.Fatal(err)
	}

	// Then：单 zone 1 处 + burst 双 zone 2 处 = 3 处 client_ip key；旧 socket key 归零
	if got := strings.Count(string(wire), `"key":"{http.vars.client_ip}"`); got != 3 {
		t.Fatalf("client_ip zone keys=%d, want 3:\n%s", got, wire)
	}
	if strings.Contains(string(wire), `{http.request.remote.host}`) {
		t.Fatalf("rate limit must not key on socket IP:\n%s", wire)
	}
}
