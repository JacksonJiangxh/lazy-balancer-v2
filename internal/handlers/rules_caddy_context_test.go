package handlers

import (
	"fmt"
	"reflect"
	"strings"
	"testing"
)

// 生产渲染（GenerateRuleServerContext / 全量生成）从不产出
// tls.automation（证书由应用层任务管理），旧实现扫描该段的分支恒不可达且
// 让配置查看响应携带恒空字段。此处钉住：即使运行配置被外部注入 automation
// 段，context 也不再声明/返回 automation_policies。
func TestBuildRuleCaddyContext_doesNotExposeDeadAutomationPolicies(t *testing.T) {
	fullConfig := map[string]interface{}{
		"apps": map[string]interface{}{
			"tls": map[string]interface{}{
				"automation": map[string]interface{}{
					"policies": []interface{}{
						map[string]interface{}{"subjects": []interface{}{"example.com"}},
					},
				},
			},
		},
	}

	result := buildRuleCaddyContext(fullConfig, "lb_testrule", "example.com")

	if _, exists := result["automation_policies"]; exists {
		t.Fatalf("automation_policies=%v, want field removed（生产渲染无该段）", result["automation_policies"])
	}
}

func tlsConnPolicyFixture(anyTag []string, sni ...string) map[string]interface{} {
	policy := map[string]interface{}{}
	if anyTag != nil {
		tags := make([]interface{}, 0, len(anyTag))
		for _, tag := range anyTag {
			tags = append(tags, tag)
		}
		policy["certificate_selection"] = map[string]interface{}{"any_tag": tags}
	}
	if sni != nil {
		sniList := make([]interface{}, 0, len(sni))
		for _, name := range sni {
			sniList = append(sniList, name)
		}
		policy["match"] = map[string]interface{}{"sni": sniList}
	}
	return policy
}

func tlsConnPoliciesConfigFixture(caddyID string, policies []interface{}) map[string]interface{} {
	return map[string]interface{}{
		"apps": map[string]interface{}{
			"http": map[string]interface{}{
				"servers": map[string]interface{}{
					"srv0": map[string]interface{}{
						"listen": []interface{}{":443"},
						"routes": []interface{}{
							map[string]interface{}{"@id": caddyID},
						},
						"tls_connection_policies": policies,
					},
				},
			},
		},
	}
}

func tlsConnPolicyFingerprints(t *testing.T, raw interface{}) []string {
	t.Helper()
	policies, ok := raw.([]interface{})
	if !ok {
		t.Fatalf("tls_connection_policies type = %T, want []interface{}", raw)
	}
	if policies == nil {
		t.Fatal("tls_connection_policies is nil, want initialized empty slice")
	}
	fingerprints := make([]string, 0, len(policies))
	for _, policyVal := range policies {
		policy, _ := policyVal.(map[string]interface{})
		parts := make([]string, 0)
		if selection, ok := policy["certificate_selection"].(map[string]interface{}); ok {
			if tags, ok := selection["any_tag"].([]interface{}); ok {
				for _, tag := range tags {
					parts = append(parts, fmt.Sprintf("tag=%v", tag))
				}
			}
		}
		if match, ok := policy["match"].(map[string]interface{}); ok {
			if sni, ok := match["sni"].([]interface{}); ok {
				for _, name := range sni {
					parts = append(parts, fmt.Sprintf("sni=%v", name))
				}
			}
		}
		fingerprints = append(fingerprints, strings.Join(parts, ","))
	}
	return fingerprints
}

func TestBuildRuleCaddyContext_TLSConnectionPoliciesScopedToRule(t *testing.T) {
	tests := []struct {
		name             string
		caddyID          string
		domain           string
		policies         []interface{}
		wantFingerprints []string
	}{
		{
			name:    "entry whose any_tag contains the rule caddy id is kept",
			caddyID: "lb_rule1",
			domain:  "other-rule-domain.com",
			policies: []interface{}{
				tlsConnPolicyFixture([]string{"lb_rule1"}, "go029.com"),
			},
			wantFingerprints: []string{"tag=lb_rule1,sni=go029.com"},
		},
		{
			name:    "entry tagged with a different rule id is dropped",
			caddyID: "lb_rule1",
			domain:  "go029.com",
			policies: []interface{}{
				tlsConnPolicyFixture([]string{"lb_otherrule"}),
			},
			wantFingerprints: []string{},
		},
		{
			name:    "entry without any_tag but sni intersecting rule domains is kept",
			caddyID: "lb_rule1",
			domain:  "go029.com",
			policies: []interface{}{
				tlsConnPolicyFixture(nil, "www.go029.com", "go029.com"),
			},
			wantFingerprints: []string{"sni=www.go029.com,sni=go029.com"},
		},
		{
			name:    "entry with neither any_tag nor sni match is dropped",
			caddyID: "lb_rule1",
			domain:  "go029.com",
			policies: []interface{}{
				tlsConnPolicyFixture([]string{"lb_otherrule"}, "unrelated.com"),
			},
			wantFingerprints: []string{},
		},
		{
			name:    "server context and top level carry the same filtered set",
			caddyID: "lb_rule1",
			domain:  "go029.com",
			policies: []interface{}{
				tlsConnPolicyFixture([]string{"lb_rule1"}, "go029.com"),
				tlsConnPolicyFixture([]string{"lb_otherrule"}, "ry029.com"),
			},
			wantFingerprints: []string{"tag=lb_rule1,sni=go029.com"},
		},
		{
			name:    "rule with no matching entries gets empty non-nil policies",
			caddyID: "lb_rule1",
			domain:  "go029.com",
			policies: []interface{}{
				tlsConnPolicyFixture([]string{"lb_otherrule"}, "ry029.com"),
				tlsConnPolicyFixture(nil, "quanyi.go029.com"),
			},
			wantFingerprints: []string{},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Given: an http server hosting the rule's route plus policies from sibling rules
			fullConfig := tlsConnPoliciesConfigFixture(tt.caddyID, tt.policies)

			// When
			result := buildRuleCaddyContext(fullConfig, tt.caddyID, tt.domain)

			// Then: both the top-level array and the server context carry the rule-scoped set
			gotTop := tlsConnPolicyFingerprints(t, result["tls_connection_policies"])
			if !reflect.DeepEqual(gotTop, tt.wantFingerprints) {
				t.Fatalf("tls_connection_policies = %v, want %v", gotTop, tt.wantFingerprints)
			}

			server, ok := result["server"].(map[string]interface{})
			if !ok || server == nil {
				t.Fatalf("server context = %v, want matching http server", result["server"])
			}
			gotServer := tlsConnPolicyFingerprints(t, server["tls_connection_policies"])
			if !reflect.DeepEqual(gotServer, tt.wantFingerprints) {
				t.Fatalf("server tls_connection_policies = %v, want %v", gotServer, tt.wantFingerprints)
			}
		})
	}
}

// 同一 @id 出现在多个 server（外部写入/历史漂移）时，配置查看框的
// server_context 必须确定性选定（排序后首个命中），不得随 map 序遍历漂移。
func TestBuildRuleCaddyContext_deterministicServerSelection(t *testing.T) {
	fullConfig := map[string]interface{}{
		"apps": map[string]interface{}{
			"http": map[string]interface{}{
				"servers": map[string]interface{}{
					"srv_b": map[string]interface{}{
						"listen": []interface{}{":9000"},
						"routes": []interface{}{map[string]interface{}{"@id": "lb_drift"}},
					},
					"srv_a": map[string]interface{}{
						"listen": []interface{}{":8000"},
						"routes": []interface{}{map[string]interface{}{"@id": "lb_drift"}},
					},
				},
			},
		},
	}
	for i := range 30 {
		result := buildRuleCaddyContext(fullConfig, "lb_drift", "drift.example.test")
		server, ok := result["server"].(map[string]interface{})
		if !ok {
			t.Fatalf("iteration %d: server context missing", i)
		}
		if name := server["server_name"]; name != "srv_a" {
			t.Fatalf("iteration %d: server_name=%v, want srv_a（排序后首个命中，确定性）", i, name)
		}
	}
}
