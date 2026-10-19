package services

// server」发布——证书未就绪时整条规则暂不进入运行配置（fail-closed），
// 证书物化后的强制重载再发布。测试覆盖目标/回归/畸形三形状：
//   1) 同端口仅未就绪 TLS 规则 → 不生成该端口 server；
//   2) 同端口已有就绪 TLS 规则 → 只发布就绪规则（未就绪主机无路由）；
//   3) 证书签发落库后 → 规则路由与 TLS 策略同时出现。

import (
	"encoding/json"
	"strings"
	"testing"
)

func l7HTTPServers(t *testing.T, generated map[string]interface{}) map[string]interface{} {
	t.Helper()
	if message, failed := generated[caddyConfigGenerationErrorKey].(string); failed {
		t.Fatalf("config generation failed: %s", message)
	}
	apps, _ := generated["apps"].(map[string]interface{})
	httpApp, _ := apps["http"].(map[string]interface{})
	servers, _ := httpApp["servers"].(map[string]interface{})
	if servers == nil {
		t.Fatalf("generated config has no http servers: %#v", generated)
	}
	return servers
}

func l7ServerRoutesJSON(t *testing.T, server map[string]interface{}) string {
	t.Helper()
	body, err := json.Marshal(server)
	if err != nil {
		t.Fatalf("marshal server: %v", err)
	}
	return string(body)
}

func TestP1_2_tlsRuleWithoutCertIsNotPublished(t *testing.T) {
	useTemporaryCertDir(t)
	_, database := newClusterTestService(t)

	// Given：启用 HTTPS + ACME、尚无任何证书任务的规则。
	seedGenerationRule(t, database, "lb_l7wait", false)
	if _, err := database.Exec(`UPDATE lb_rules SET enable_tls=1, tls_source='acme_dns', listen_port=18443 WHERE caddy_id='lb_l7wait'`); err != nil {
		t.Fatalf("enable ACME TLS: %v", err)
	}

	// When
	generated := generateCaddyConfigFromStore(database)
	servers := l7HTTPServers(t, generated)

	// Then：该端口不生成 server——不存在无 tls_connection_policies 的明文监听器。
	if _, ok := servers["http_18443"]; ok {
		t.Fatalf("unready ACME TLS rule must not publish a plaintext server: %#v", servers["http_18443"])
	}

	// When 2：证书签发落库（与 certissuer 物化后的强制重载同视图）。
	certPEM, keyPEM := matchingCertificatePair(t, "example.test")
	if _, err := database.Exec(`INSERT INTO cert_jobs (rule_id,domain,status,cert_pem,key_pem) VALUES ('lb_l7wait','example.test','issued',?,?)`, certPEM, keyPEM); err != nil {
		t.Fatalf("seed issued certificate: %v", err)
	}
	generated = generateCaddyConfigFromStore(database)
	servers = l7HTTPServers(t, generated)
	server, ok := servers["http_18443"].(map[string]interface{})
	if !ok {
		t.Fatalf("TLS rule must be published after certificate is ready: %#v", servers)
	}
	policies, _ := server["tls_connection_policies"].([]interface{})
	if len(policies) != 1 {
		t.Fatalf("published TLS server must carry tls_connection_policies (got %#v)", server["tls_connection_policies"])
	}
	routes := l7ServerRoutesJSON(t, server)
	if !strings.Contains(routes, `example.test`) || !strings.Contains(routes, `"reverse_proxy"`) {
		t.Fatalf("published server must route the rule host to upstream: %s", routes)
	}
}

func TestP1_2_readyTLSSiblingUnaffectedByPendingRule(t *testing.T) {
	useTemporaryCertDir(t)
	_, database := newClusterTestService(t)

	// Given：同端口一条手动 TLS 已就绪规则 + 一条 ACME 未就绪规则。
	certPEM, keyPEM := matchingCertificatePair(t, "ready.example.test")
	seedGenerationRule(t, database, "lb_l7ready", false)
	if _, err := database.Exec(`UPDATE lb_rules SET domain='ready.example.test', enable_tls=1, tls_source='manual', tls_cert=?, tls_key=?, listen_port=18444 WHERE caddy_id='lb_l7ready'`, certPEM, keyPEM); err != nil {
		t.Fatalf("seed ready TLS rule: %v", err)
	}
	seedGenerationRule(t, database, "lb_l7pending", false)
	if _, err := database.Exec(`UPDATE lb_rules SET domain='pending.example.test', enable_tls=1, tls_source='acme_dns', listen_port=18444 WHERE caddy_id='lb_l7pending'`); err != nil {
		t.Fatalf("seed pending ACME rule: %v", err)
	}

	// When
	servers := l7HTTPServers(t, generateCaddyConfigFromStore(database))
	server, ok := servers["http_18444"].(map[string]interface{})
	if !ok {
		t.Fatalf("ready TLS sibling must keep the port served: %#v", servers)
	}
	routes := l7ServerRoutesJSON(t, server)
	if !strings.Contains(routes, `ready.example.test`) {
		t.Fatalf("ready rule route missing: %s", routes)
	}
	if strings.Contains(routes, `pending.example.test`) {
		t.Fatalf("pending ACME rule must not be routed before certificate is ready: %s", routes)
	}
	policies, _ := server["tls_connection_policies"].([]interface{})
	if len(policies) != 1 {
		t.Fatalf("only ready rule should contribute a TLS policy, got %#v", server["tls_connection_policies"])
	}
}
