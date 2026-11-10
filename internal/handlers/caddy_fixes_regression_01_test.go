package handlers

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"testing"

	"lazy-balancer-v2/internal/db"
	"lazy-balancer-v2/internal/models"
	"lazy-balancer-v2/internal/services"
)

// 需要重启多次才能逐一暴露；聚合错误每条含规则名 + caddy_id。
func TestValidateEnabledStoredRuleConfigs_reports_all_bad_rules(t *testing.T) {
	// Given
	newBackupTestHandlers(t)
	if _, err := db.DB.Exec(`INSERT INTO lb_rules (caddy_id,name,protocol,domain,listen_port,enabled,enable_tls,tls_http_redirect) VALUES
		('lb_bad_a','坏规则甲','http','a.example.test',80,1,1,1),
		('lb_bad_b','坏规则乙','http','b.example.test',80,1,1,1)`); err != nil {
		t.Fatalf("seed bad rules: %v", err)
	}

	// When
	err := validateEnabledStoredRuleConfigs(context.Background())

	// Then: 两条坏规则在同一次校验中全部报出
	if err == nil {
		t.Fatal("validateEnabledStoredRuleConfigs 接受了两条 80 端口 TLS 跳转自环规则")
	}
	message := err.Error()
	for _, want := range []string{"坏规则甲", "lb_bad_a", "坏规则乙", "lb_bad_b"} {
		if !strings.Contains(message, want) {
			t.Fatalf("错误信息必须包含 %q，实际: %s", want, message)
		}
	}
}

// 而非失败（caddy.go 按启用上游数 continue），预校验返回 nil 与之对齐。
func TestValidateRuleConfigGeneration_zeroUpstreams_returnsNil(t *testing.T) {
	newBackupTestHandlers(t)
	rule := models.LbRule{CaddyID: "lb_zero", Protocol: "http", Domain: "zero.example.test", ListenPort: 80}

	if err := validateRuleConfigGeneration(rule); err != nil {
		t.Fatalf("零上游规则应返回 nil（全量渲染跳过），实际: %v", err)
	}
}

func TestValidateRuleConfigGeneration_dynamicDNS_returnsValidationError(t *testing.T) {
	newBackupTestHandlers(t)
	rule := models.LbRule{
		CaddyID: "lb_ddns", Protocol: "http", Domain: "ddns.example.test", ListenPort: 80,
		DynamicDNS: true, DnsFamily: "both",
		Upstreams: []models.Upstream{
			{Host: "up1.example.test", Port: 8080, Enabled: true},
			{Host: "up2.example.test", Port: 8080, Enabled: true},
		},
	}

	err := validateRuleConfigGeneration(rule)
	if err == nil {
		t.Fatal("dynamic-DNS 多上游应返回 configValidationError")
	}
	var validationErr *configValidationError
	if !errors.As(err, &validationErr) {
		t.Fatalf("应为 configValidationError，实际: %T %v", err, err)
	}
	if !strings.Contains(validationErr.Error(), "动态 DNS 模式仅支持一个启用的上游") {
		t.Fatalf("错误信息不符，实际: %s", validationErr.Error())
	}
}

func TestValidateRuleConfigGeneration_validRule_returnsNil(t *testing.T) {
	newBackupTestHandlers(t)
	// 库值唯一真相批 1+2：健康检查族为值型列，预检渲染直读零兜底——内存
	// fixture 构造即带库态有效值。
	rule := models.LbRule{
		CaddyID: "lb_ok", Protocol: "http", Domain: "ok.example.test", ListenPort: 80,
		HealthCheckInterval: 10, HealthCheckTimeout: 2, HealthCheckUnhealthyThreshold: 3, HealthCheckHealthyThreshold: 2,
		Upstreams: []models.Upstream{
			{Host: "up1.example.test", Port: 8080, Enabled: true},
		},
	}

	if err := validateRuleConfigGeneration(rule); err != nil {
		t.Fatalf("合法规则应返回 nil，实际: %v", err)
	}
}

// 已与 nil 统一回退主上游（caddy.go len(upstreams)==0），此前空数组触发
// buildHTTPHandleChain 硬失败，预校验与全量渲染语义不对称。
func TestValidateRuleConfigGeneration_pathRuleEmptyUpstreams_returnsNil(t *testing.T) {
	newBackupTestHandlers(t)
	rule := models.LbRule{
		CaddyID: "lb_path_empty", Protocol: "http", Domain: "path.example.test", ListenPort: 80,
		CustomRoutesEnabled: true,
		HealthCheckInterval: 10, HealthCheckTimeout: 2, HealthCheckUnhealthyThreshold: 3, HealthCheckHealthyThreshold: 2,
		Upstreams: []models.Upstream{
			{Host: "up1.example.test", Port: 8080, Enabled: true},
		},
		PathRules: []models.PathRule{
			{SortOrder: 1, MatchType: "prefix", Path: "/api", Upstreams: []models.PathRuleUpstream{}},
		},
	}

	if err := validateRuleConfigGeneration(rule); err != nil {
		t.Fatalf("路径规则空数组应回退主上游并放行，实际: %v", err)
	}
}

// 哨兵错误经包装后（生成失败 + 规则名上下文）仍被 errors.Is 命中；且单规则生成 map 的 error 值本身即为哨兵 error，
// 特判不依赖精确字符串、不随包装静默失效。
func TestValidateRuleConfigGeneration_zeroUpstreams_sentinelSurvivesWrapping(t *testing.T) {
	// Given 生成侧 map 携带哨兵 error（非字符串）
	config := services.GenerateSingleRuleCaddyConfig(services.SingleRuleConfig{
		CaddyID: "lb_z", Protocol: "tcp", ListenPort: 9000,
	})
	genErr, isErr := config["error"].(error)
	if !isErr {
		t.Fatalf("error 键应为 error 类型，实际 %T", config["error"])
	}

	// When 包装后特判判定
	wrapped := fmt.Errorf("规则 %s: %w", "lb_z", genErr)

	// Then
	if !errors.Is(wrapped, services.ErrNoEnabledUpstreams) {
		t.Fatalf("包装后的哨兵必须仍被 errors.Is 命中，实际: %v", wrapped)
	}
}

// CanonicalDomains 整串失败时（含 IP 等非法域名）必须回退小写拆分保留，而非返回 nil 丢弃域名——
// 与渲染侧 normalizedDomainSet（caddy.go）同口径，避免遮蔽检查静默通过。
func TestNormalizedRuleDomains_fallsBackOnCanonicalizationFailure(t *testing.T) {
	// CanonicalDomains 对 IP 报错 → 整串失败 → 回退小写拆分
	got := normalizedRuleDomains("Example.COM, 192.168.0.1")
	want := []string{"example.com", "192.168.0.1"}
	if len(got) != len(want) {
		t.Fatalf("回退结果长度 %d，want %d: %v", len(got), len(want), got)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("回退结果[%d]=%q，want %q", i, got[i], want[i])
		}
	}
}

func TestNormalizedRuleDomains_keepsCanonicalResult(t *testing.T) {
	got := normalizedRuleDomains("Example.COM, example.com")
	if len(got) != 1 || got[0] != "example.com" {
		t.Fatalf("规范化结果应为去重后的 [example.com]，实际: %v", got)
	}
}
