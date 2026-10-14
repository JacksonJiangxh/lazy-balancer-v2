package services

import (
	"encoding/json"
	"strings"
	"testing"
)

// LB-04 曾钉 health_check_timeout NULL/0 行渲染兜底 2s；库值唯一真相批 1+2
// （2026-10-14 用户裁定）废除写死兜底——health_check_timeout 为类型①值型列
// （NOT NULL DEFAULT 2+启动回填+写侧 400+导入归一门）：fresh DDL 的 NOT NULL
// 使 NULL 行结构上不可达（存量库可空列 NULL 由每启动回填报 2）；0 行=带外
// 脏数据，渲染显性报错（fail-visible）。
func TestGenerateCaddyConfig_activeHealthTimeout_zero_row_fails_generation(t *testing.T) {
	// Given：启用主动健康检查、timeout 显式置 0 的规则（带外写入形态）
	_, database := newClusterTestService(t)
	seedGenerationRule(t, database, "lb_hc_zero", false)
	if _, err := database.Exec(`UPDATE lb_rules SET enable_active_health_check=1, health_check_timeout=0 WHERE caddy_id='lb_hc_zero'`); err != nil {
		t.Fatalf("enable active health check (zero row): %v", err)
	}

	// When
	generated := generateCaddyConfigFromStore(database)

	// Then：不再回退写死 2s，生成显性失败且点名列
	message, failed := generated[caddyConfigGenerationErrorKey].(string)
	if !failed {
		t.Fatalf("health_check_timeout=0 must fail generation (fail-visible), got keys %v", generated)
	}
	if !strings.Contains(message, "health_check_timeout") {
		t.Fatalf("generation error %q must name health_check_timeout", message)
	}
}

// LB25-P2-1(第 25 轮审计)曾钉 TCP 主动健检 timeout=0 兜底 2s；库值唯一真相
// 批 1+2（2026-10-14 用户裁定）废除写死兜底——health_check_timeout 为类型①
// 值型列（NOT NULL DEFAULT 2+启动回填+写侧 400+导入归一门），0 值=库值治理
// 被带外写入破坏，渲染显性报错；有效值直读贯通（哨兵 13s 验证无替换）。
func TestBuildTCPServer_activeHealthTimeout_failVisibleAndPassThrough(t *testing.T) {
	t.Run("zero value fails generation", func(t *testing.T) {
		// Given: TCP 规则启用主动健检,timeout=0(带外写入形态)
		cfg := SingleRuleConfig{
			ListenPort:                    16379,
			Protocol:                      "tcp",
			EnableActiveHealthCheck:       true,
			HealthCheckInterval:           10,
			HealthCheckTimeout:            0,
			HealthCheckUnhealthyThreshold: 3,
			HealthCheckHealthyThreshold:   2,
			Upstreams:                     []UpstreamConfig{{Host: "127.0.0.1", Port: 6379, Weight: 1, Enabled: true}},
		}

		// When / Then: 渲染显性报错，不再回退写死 2s
		if _, err := buildTCPServer(cfg); err == nil {
			t.Fatal("health_check_timeout=0 must fail TCP render generation (fail-visible)")
		}
	})

	t.Run("stored value passes through", func(t *testing.T) {
		cfg := SingleRuleConfig{
			ListenPort:                    16379,
			Protocol:                      "tcp",
			EnableActiveHealthCheck:       true,
			HealthCheckInterval:           10,
			HealthCheckTimeout:            13,
			HealthCheckUnhealthyThreshold: 3,
			HealthCheckHealthyThreshold:   2,
			Upstreams:                     []UpstreamConfig{{Host: "127.0.0.1", Port: 6379, Weight: 1, Enabled: true}},
		}
		server, err := buildTCPServer(cfg)
		if err != nil {
			t.Fatalf("buildTCPServer: %v", err)
		}
		body, _ := json.Marshal(server)
		if !strings.Contains(string(body), `"timeout":"13s"`) {
			t.Fatalf("TCP active health timeout must pass through stored value 13s: %s", body)
		}
	})
}
