package handlers

// U3-4(第 45 轮审计修复)：TCP 三字段（tcp_health_check_port/tcp_try_duration/
// tcp_try_interval）此前无负值校验，渲染侧静默钳制（caddy.go 3503-3522）——
// 保存前拒绝显式负值。代理超时族的 -1 哨兵（proxy_flush_interval=-1=立即刷新）
// 仅属 http 侧，TCP 三字段无哨兵语义，负值一律拒。

import (
	"testing"
)

func TestValidateRuleFeatures_rejectsNegativeTcpFields(t *testing.T) {
	base := func() ruleFeatureInput {
		return ruleFeatureInput{
			Protocol:           "tcp",
			Strategy:           "weighted_round_robin",
			ListenPort:         19099,
			TCPTryInterval:     250,
			TCPTryDuration:     3,
			TCPHealthCheckPort: 9123,
		}
	}

	// 目标形状：三字段各自 -1 → 拒绝
	negativeCases := []struct {
		name   string
		mutate func(*ruleFeatureInput)
	}{
		{"tcp_health_check_port", func(i *ruleFeatureInput) { i.TCPHealthCheckPort = -1 }},
		{"tcp_try_duration", func(i *ruleFeatureInput) { i.TCPTryDuration = -1 }},
		{"tcp_try_interval", func(i *ruleFeatureInput) { i.TCPTryInterval = -1 }},
	}
	for _, tc := range negativeCases {
		t.Run(tc.name, func(t *testing.T) {
			input := base()
			tc.mutate(&input)
			if err := validateRuleFeatures(input); err == nil {
				t.Fatalf("negative %s must be rejected, got nil error", tc.name)
			}
		})
	}

	// 回归形状：零值（跟随默认）与正值放行
	validShapes := []struct {
		name   string
		mutate func(*ruleFeatureInput)
	}{
		{"all zero", func(i *ruleFeatureInput) { i.TCPHealthCheckPort, i.TCPTryDuration, i.TCPTryInterval = 0, 0, 0 }},
		{"all positive", func(i *ruleFeatureInput) {}},
	}
	for _, tc := range validShapes {
		t.Run(tc.name, func(t *testing.T) {
			input := base()
			tc.mutate(&input)
			if err := validateRuleFeatures(input); err != nil {
				t.Fatalf("tcp shape %s must pass, got %v", tc.name, err)
			}
		})
	}

	// 哨兵不变：http 侧 proxy_flush_interval=-1 仍放行（立即刷新哨兵）
	httpSentinel := ruleFeatureInput{Protocol: "http", Strategy: "weighted_round_robin", ListenPort: 8080, ProxyFlushInterval: -1}
	if err := validateRuleFeatures(httpSentinel); err != nil {
		t.Fatalf("http flush_interval=-1 sentinel must still pass, got %v", err)
	}
}

// U4-P4-1（第 67 轮审计，P4）：TCP 规则 enable_dns_server/dns_server 落库恒
// 无效——渲染路径永不消费且无告警，对照 dynamic_dns 有保存侧 400+渲染告警
// 双保险，DNS 服务发现两字段保存侧拒绝清单漏列。与 TCP+dynamic_dns 同门：
// 字段属 HTTP 语义（L4 无 resolver 消费），协议切换零值化已覆盖迁移路径，
// 显式携带即拒。
func TestValidateRuleFeatures_rejectsTCPDnsServerFields(t *testing.T) {
	base := func() ruleFeatureInput {
		return ruleFeatureInput{
			Protocol:           "tcp",
			Strategy:           "weighted_round_robin",
			ListenPort:         19099,
			TCPTryInterval:     250,
			TCPTryDuration:     3,
			TCPHealthCheckPort: 9123,
		}
	}

	// 目标形状：两字段各自显式携带 → 拒绝
	rejectCases := []struct {
		name   string
		mutate func(*ruleFeatureInput)
	}{
		{"enable_dns_server", func(i *ruleFeatureInput) { i.EnableDnsServer = true }},
		{"dns_server", func(i *ruleFeatureInput) { i.DnsServer = "8.8.8.8:53" }},
	}
	for _, tc := range rejectCases {
		t.Run(tc.name, func(t *testing.T) {
			input := base()
			tc.mutate(&input)
			if err := validateRuleFeatures(input); err == nil {
				t.Fatalf("TCP 携带 %s 必须拒绝（渲染永不消费，落库即死配置）, got nil error", tc.name)
			}
		})
	}

	// 回归形状一：TCP 零值（未携带/协议切换零值化后）放行
	if err := validateRuleFeatures(base()); err != nil {
		t.Fatalf("TCP 零值 DNS 字段必须放行, got %v", err)
	}
	// 回归形状二：HTTP 规则同名字段是合法 DNS 服务发现语义，不受影响
	httpInput := ruleFeatureInput{
		Protocol: "http", Strategy: "weighted_round_robin", ListenPort: 8080,
		EnableDnsServer: true, DnsServer: "8.8.8.8:53",
	}
	if err := validateRuleFeatures(httpInput); err != nil {
		t.Fatalf("HTTP 携带 DNS 服务发现字段必须放行, got %v", err)
	}
}
