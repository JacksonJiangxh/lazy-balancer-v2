package services

import (
	"strings"
	"testing"

	"lazy-balancer-v2/internal/models"
)

// health_check_host（HTTP-only）——保存族已清，传输族漏检会造成
// 主从/导入面同形性分叉。
func TestNormalizeRuleForTransport_clearsTCPHealthCheckHost(t *testing.T) {
	rule := models.LbRule{
		Protocol: "tcp", HealthCheckHost: "probe.example",
		HealthCheckInterval: 10, HealthCheckTimeout: 2,
		HealthCheckUnhealthyThreshold: 3, HealthCheckHealthyThreshold: 2,
		TCPTryInterval: 250,
	}
	normalizeRuleForTransport(&rule)
	if rule.HealthCheckHost != "" {
		t.Fatalf("health_check_host=%q, want cleared for TCP transport", rule.HealthCheckHost)
	}
}

func TestFormatDriftRoutes_capsDisplay(t *testing.T) {
	missing := make([]string, 25)
	for i := range missing {
		missing[i] = "规则"
	}
	extra := []string{"多余规则（lb_x）"}
	out := FormatDriftRoutes(missing, extra)
	if !strings.Contains(out, "缺失规则路由: ") || !strings.Contains(out, "多余规则路由: 多余规则（lb_x）") {
		t.Fatalf("out=%q, want 两段", out)
	}
	if !strings.Contains(out, "共 25 条") {
		t.Fatalf("out=%q, want 截断计数说明", out)
	}
	if count := strings.Count(out, "规则、"); count > driftDisplayMaxEntries {
		t.Fatalf("out 展示条目=%d, want ≤%d", count, driftDisplayMaxEntries)
	}
}
