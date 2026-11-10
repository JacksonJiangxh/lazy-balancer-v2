package handlers

import (
	"strings"
	"testing"

	"lazy-balancer-v2/internal/models"
)

// 全数字点分串（999.1.1.1、1.2.3.4.5）net.ParseIP 解析失败，但标签字符表
// 校验会放行：落库后渲染进上游地址 / 健康检查 Host 头，解析与探测静默失败
// （保存时零提示）。dns_server 已有同款判据，此处要求上游 host 与健康检查
// host 同口径；含数字的普通域名不受影响。
func TestIsValidHost_rejectsNumericLookalikeAddresses(t *testing.T) {
	cases := []struct {
		name string
		host string
		want bool
	}{
		{"八位组越界", "999.1.1.1", false},
		{"末段越界", "1.2.3.256", false},
		{"五段全数字", "1.2.3.4.5", false},
		{"四段全数字越界", "256.256.256.256", false},
		{"合法IPv4", "10.0.0.1", true},
		{"合法IPv6", "2001:db8::1", true},
		{"回环", "127.0.0.1", true},
		{"含数字标签域名", "dns1.example.com", true},
		{"纯数字标签域名", "1.example.com", true},
		{"下划线服务名", "my_backend", true},
		{"单段纯数字主机名", "123", true},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if got := isValidHost(c.host); got != c.want {
				t.Fatalf("isValidHost(%q) = %v, want %v", c.host, got, c.want)
			}
		})
	}
}

// 上游 host 消费点：全数字点分串必须在保存门被点名拒绝，合法域名不得误伤。
func TestValidateRuleUpstreams_rejectsNumericLookalikeHost(t *testing.T) {
	cases := []struct {
		name    string
		host    string
		wantErr bool
	}{
		{"全数字越界", "999.1.1.1", true},
		{"五段全数字", "1.2.3.4.5", true},
		{"合法域名", "backend.example.com", false},
		{"合法IP", "10.0.0.1", false},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			upstreams := []models.Upstream{{Host: c.host, Port: 8080, Weight: 1, Enabled: true}}
			_, err := validateRuleUpstreams("http", false, upstreams, true)
			if c.wantErr {
				if err == nil || !strings.Contains(err.Error(), "主机") {
					t.Fatalf("validateRuleUpstreams(%q) error = %v, want 主机无效", c.host, err)
				}
				return
			}
			if err != nil {
				t.Fatalf("validateRuleUpstreams(%q) error = %v, want nil", c.host, err)
			}
		})
	}
}

// 健康检查 host 消费点：同一保存门内的形状校验须继承 isValidHost 的全数字拒绝。
func TestValidateRulePayloadBeforeSave_rejectsNumericLookalikeHealthCheckHost(t *testing.T) {
	for _, host := range []string{"999.1.1.1", "1.2.3.4.5"} {
		handler := &Handlers{}
		req := models.CreateRuleRequest{
			Protocol:            "http",
			ListenPort:          8080,
			HealthCheckInterval: 10,
			HealthCheckTimeout:  5,
			HealthCheckHost:     host,
			Upstreams:           []models.Upstream{{Host: "10.0.0.1", Port: 8080, Weight: 1, Enabled: true}},
		}
		err := handler.validateRulePayloadBeforeSave(req)
		if err == nil || !strings.Contains(err.Error(), "健康检查域名") {
			t.Fatalf("health_check_host=%q error = %v, want 健康检查域名无效", host, err)
		}
	}

	// 防误伤：合法域名与合法 IP 照常通过该门。
	handler := &Handlers{}
	req := models.CreateRuleRequest{
		Protocol:                      "http",
		ListenPort:                    8080,
		HealthCheckInterval:           10,
		HealthCheckTimeout:            5,
		HealthCheckUnhealthyThreshold: 3,
		HealthCheckHealthyThreshold:   2,
		HealthCheckHost:               "probe.example.com",
		Upstreams:                     []models.Upstream{{Host: "10.0.0.1", Port: 8080, Weight: 1, Enabled: true}},
	}
	if err := handler.validateRulePayloadBeforeSave(req); err != nil {
		t.Fatalf("合法健康检查域名被拒: %v", err)
	}
}

// 路径规则自定义上游 host 消费点（同包另一处 isValidHost 调用）。
func TestValidateRuleFeatures_rejectsNumericLookalikePathUpstreamHost(t *testing.T) {
	for _, address := range []string{"999.1.1.1", "1.2.3.4.5"} {
		input := ruleFeatureInput{
			Protocol:            "http",
			CustomRoutesEnabled: true,
			PathRules: []models.PathRule{{
				MatchType: "prefix", Path: "/api/",
				Upstreams: []models.PathRuleUpstream{{Address: address, Port: 9100, Weight: 1}},
			}},
		}
		err := validateRuleFeatures(input)
		if err == nil || !strings.Contains(err.Error(), "主机") {
			t.Fatalf("path upstream=%q error = %v, want 主机无效", address, err)
		}
	}

	input := ruleFeatureInput{
		Protocol:            "http",
		CustomRoutesEnabled: true,
		PathRules: []models.PathRule{{
			MatchType: "prefix", Path: "/api/",
			Upstreams: []models.PathRuleUpstream{{Address: "api1.example.com", Port: 9100, Weight: 1}},
		}},
	}
	if err := validateRuleFeatures(input); err != nil {
		t.Fatalf("合法路径上游域名被拒: %v", err)
	}
}
