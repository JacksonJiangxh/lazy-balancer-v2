package handlers

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/gin-gonic/gin"

	"lazy-balancer-v2/internal/db"
)

// 存量 TCP 行的 HTTP 专属死字段在启用与启动聚合校验时按保存族归一；
// 同端口双启用 TCP 规则仍属于真实冲突，必须点名拒绝。

// 存量 TCP+cookie 规则启用时按保存族归一为默认策略，不再拒绝。
func TestEnableRule_normalizesTCPRuleWithHTTPOnlyStrategy(t *testing.T) {
	// Given
	handler, _, _ := newAuditRuleHandlers(t, 0)
	seedTCPStoredRule(t, "lb_tcp_cookie", "tcp-cookie", 19090, false, "cookie", false)
	router := gin.New()
	router.POST("/rules/:caddy_id/enable", handler.EnableRule)
	response := httptest.NewRecorder()

	// When
	router.ServeHTTP(response, httptest.NewRequest(http.MethodPost, "/rules/lb_tcp_cookie/enable", nil))

	// Then：启用成功，策略在同事务内归一为默认值。
	if response.Code != http.StatusOK {
		t.Fatalf("enable status=%d body=%s, want 200", response.Code, response.Body.String())
	}
	var enabled bool
	var strategy string
	if err := db.DB.QueryRow("SELECT enabled,strategy FROM lb_rules WHERE caddy_id='lb_tcp_cookie'").Scan(&enabled, &strategy); err != nil {
		t.Fatalf("read enabled rule: %v", err)
	}
	if !enabled || strategy != "weighted_round_robin" {
		t.Fatalf("enabled=%v strategy=%q, want true/weighted_round_robin", enabled, strategy)
	}
}

// 存量 TCP+dynamic_dns 规则启用时清除死配置，避免渲染跳过该规则。
func TestEnableRule_normalizesTCPRuleWithDynamicDNS(t *testing.T) {
	// Given
	handler, _, _ := newAuditRuleHandlers(t, 0)
	seedTCPStoredRule(t, "lb_tcp_ddns", "tcp-ddns", 19091, false, "weighted_round_robin", true)
	if _, err := db.DB.Exec("UPDATE lb_rules SET domain='dead.example.test' WHERE caddy_id='lb_tcp_ddns'"); err != nil {
		t.Fatalf("seed dead TCP domain: %v", err)
	}
	router := gin.New()
	router.POST("/rules/:caddy_id/enable", handler.EnableRule)
	response := httptest.NewRecorder()

	// When
	router.ServeHTTP(response, httptest.NewRequest(http.MethodPost, "/rules/lb_tcp_ddns/enable", nil))

	// Then
	if response.Code != http.StatusOK {
		t.Fatalf("enable status=%d body=%s, want 200", response.Code, response.Body.String())
	}
	var enabled, dynamicDNS bool
	var domain string
	if err := db.DB.QueryRow("SELECT enabled,dynamic_dns,COALESCE(domain,'') FROM lb_rules WHERE caddy_id='lb_tcp_ddns'").Scan(&enabled, &dynamicDNS, &domain); err != nil {
		t.Fatalf("read enabled rule: %v", err)
	}
	if !enabled || dynamicDNS || domain != "" {
		t.Fatalf("enabled=%v dynamic_dns=%v domain=%q, want true/false/empty", enabled, dynamicDNS, domain)
	}
}

// 存量两条同端口 TCP 均启用(兜 validatePortFromDB 之前的存量双
// 启用),聚合校验必须报错并点名全部冲突规则。
func TestValidateEnabledStoredRuleConfigs_namesDuplicateTCPPortRules(t *testing.T) {
	// Given
	initializeRuleFeatureTestDB(t)
	seedTCPStoredRule(t, "lb_tcp_dup_a", "tcp-dup-a", 19092, true, "weighted_round_robin", false)
	seedTCPStoredRule(t, "lb_tcp_dup_b", "tcp-dup-b", 19092, true, "least_conn", false)

	// When
	err := validateEnabledStoredRuleConfigs(context.Background())

	// Then:报错点名两条规则
	if err == nil {
		t.Fatal("duplicate enabled TCP port must be rejected by aggregate validation")
	}
	if !strings.Contains(err.Error(), "lb_tcp_dup_a") || !strings.Contains(err.Error(), "lb_tcp_dup_b") {
		t.Fatalf("aggregate error must name both conflicting rules, got: %v", err)
	}
}

// 聚合校验同样按归一后的 TCP 形态检查动态上游死配置。
func TestValidateEnabledStoredRuleConfigs_normalizesTCPDynamicDNS(t *testing.T) {
	// Given
	initializeRuleFeatureTestDB(t)
	seedTCPStoredRule(t, "lb_tcp_ddns_on", "tcp-ddns-on", 19093, true, "weighted_round_robin", true)

	// When
	err := validateEnabledStoredRuleConfigs(context.Background())

	// Then
	if err != nil {
		t.Fatalf("aggregate validation must normalize tcp+dynamic_dns rule, got: %v", err)
	}
}

func TestValidateEnabledStoredRuleConfigs_normalizesTCPHTTPOnlyStrategy(t *testing.T) {
	initializeRuleFeatureTestDB(t)
	seedTCPStoredRule(t, "lb_tcp_cookie_on", "tcp-cookie-on", 19094, true, "cookie", false)

	err := validateEnabledStoredRuleConfigs(context.Background())
	if err != nil {
		t.Fatalf("aggregate validation must normalize tcp+cookie rule, got: %v", err)
	}
}

func TestValidateEnabledStoredRuleConfigs_normalizesTCPNTLM(t *testing.T) {
	initializeRuleFeatureTestDB(t)
	seedTCPStoredRule(t, "lb_tcp_ntlm_on", "tcp-ntlm-on", 19095, true, "weighted_round_robin", false)
	if _, err := db.DB.Exec(`UPDATE lb_rules SET ntlm_compatible=1 WHERE caddy_id='lb_tcp_ntlm_on'`); err != nil {
		t.Fatal(err)
	}

	err := validateEnabledStoredRuleConfigs(context.Background())
	if err != nil {
		t.Fatalf("aggregate validation must normalize tcp+ntlm rule, got: %v", err)
	}
}

// 启用预校验的「规则不存在」必须带哨兵：首读后规则被并发删除属冲突
// （handler 409），不得折成 500「预校验规则配置失败」并携带内部错误文本。
func TestValidateStoredRuleConfig_missingRuleUsesConflictSentinel(t *testing.T) {
	initializeRuleFeatureTestDB(t)

	err := validateStoredRuleConfig(context.Background(), "lb_missing_concurrent_delete")
	if !errors.Is(err, errStoredRuleMissing) {
		t.Fatalf("err=%v, want errStoredRuleMissing（并发删除必须可被 409 分支识别）", err)
	}
}
