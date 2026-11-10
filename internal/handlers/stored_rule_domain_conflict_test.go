package handlers

import (
	"context"
	"strings"
	"testing"

	"lazy-balancer-v2/internal/db"
)

// 同端口同归一化域名的多条启用 HTTP 规则由启动/UpdateConfig 聚合校验点名
// （与 TCP 同端口同格=硬错）：保存/启用路径已有 enabledRuleDomainConflict 前置
// 拦截，本门兜直改 DB/历史脏库——渲染层同 server 内只有首条规则收到流量，
// 其余成为永不命中的死规则且面板仍显示「已启用」。
func TestValidateEnabledStoredRuleConfigs_namesDuplicateHTTPDomainRules(t *testing.T) {
	initializeRuleFeatureTestDB(t)
	seedStoredHTTPRule(t, "lb_http_dup_a", "http-dup-a", "Dup.Example.Test", 18080, true)
	seedStoredHTTPRule(t, "lb_http_dup_b", "http-dup-b", "dup.example.test", 18080, true)

	err := validateEnabledStoredRuleConfigs(context.Background())

	if err == nil {
		t.Fatal("同端口同域名双启用 HTTP 规则必须被聚合校验拒绝")
	}
	for _, want := range []string{"lb_http_dup_a", "lb_http_dup_b", "dup.example.test", "18080"} {
		if !strings.Contains(err.Error(), want) {
			t.Fatalf("聚合错误必须点名 %q，实际: %v", want, err)
		}
	}
}

// 对照形态：不同端口 / 不同域名 / 其中一条禁用 —— 均不构成运行时冲突。
func TestValidateEnabledStoredRuleConfigs_allowsNonConflictingHTTPRules(t *testing.T) {
	initializeRuleFeatureTestDB(t)
	seedStoredHTTPRule(t, "lb_http_ok_a", "http-ok-a", "one.example.test", 18081, true)
	seedStoredHTTPRule(t, "lb_http_ok_b", "http-ok-b", "two.example.test", 18081, true)
	seedStoredHTTPRule(t, "lb_http_ok_c", "http-ok-c", "one.example.test", 18082, true)
	// 域名相同、端口相同但禁用——不渲染、不占流量。
	seedStoredHTTPRule(t, "lb_http_ok_disabled", "http-ok-disabled", "one.example.test", 18081, false)

	if err := validateEnabledStoredRuleConfigs(context.Background()); err != nil {
		t.Fatalf("非冲突形态不应被拒绝: %v", err)
	}
}

func seedStoredHTTPRule(t *testing.T, caddyID, name, domain string, port int, enabled bool) {
	t.Helper()
	if _, err := db.DB.Exec(`INSERT INTO lb_rules (caddy_id,name,description,protocol,domain,listen_port,strategy,health_check_path,enabled,enable_compress,tls_source,enable_tls)
		VALUES (?,?,?,'http',?,?,'weighted_round_robin','',?,1,'manual',0)`, caddyID, name, "", domain, port, enabled); err != nil {
		t.Fatalf("seed http rule %s: %v", caddyID, err)
	}
	if _, err := db.DB.Exec(`INSERT INTO upstreams (rule_id,host,port,weight,enabled,protocol) VALUES (?, '127.0.0.1', 9000, 1, 1, 'http')`, caddyID); err != nil {
		t.Fatalf("seed http upstream %s: %v", caddyID, err)
	}
}
