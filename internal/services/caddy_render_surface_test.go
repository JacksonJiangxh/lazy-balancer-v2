package services

import (
	"encoding/json"
	"os"
	"strings"
	"testing"

	"lazy-balancer-v2/internal/models"
)

// 上游启用谓词单源：整个 services 包只允许一处 IIF 字面量（常量定义），
// 渲染上游装载 / 单规则服务上下文预览 / 看门狗发布谓词必须复用常量——
// 新增第二处字面量（单侧漂移面）即红。
func TestUpstreamEnabledPredicateHasOneLiteral(t *testing.T) {
	src, err := os.ReadFile("caddy.go")
	if err != nil {
		t.Fatalf("read caddy.go: %v", err)
	}
	if got := strings.Count(string(src), "u.enabled IN"); got != 1 {
		t.Fatalf("caddy.go 含 %d 处上游启用 IIF 字面量, want 1（只允许 upstreamEnabledSQLValue 定义）", got)
	}
	// 单规则服务上下文预览的两处 EXISTS 必须引用常量而非内联表达式。
	if got := strings.Count(string(src), "u.rule_id = lb_rules.caddy_id AND `+UpstreamEnabledSQLPredicate+`"); got != 2 {
		t.Fatalf("GenerateRuleServerContext 引用单源谓词 %d 处, want 2", got)
	}
	for _, path := range []string{"configwatchdog.go"} {
		data, err := os.ReadFile(path)
		if err != nil {
			t.Fatalf("read %s: %v", path, err)
		}
		if strings.Contains(string(data), "u.enabled IN") {
			t.Fatalf("%s 内联了上游启用表达式（应复用单源谓词）", path)
		}
	}
}

// 规则日志发射面随发布集收窄：未发布规则（零启用上游 / TLS 证书未就绪）
// 不建 logger_names，也不建 logging.logs 条目；已发布规则两者齐备。
func TestGenerateCaddyConfig_logSurfaceFollowsPublishSet(t *testing.T) {
	_, database := newClusterTestService(t)
	seedHTTPRuleForGeneration(t, database, "lb_log_pub", "pub.example.test", 8080)
	if _, err := database.Exec(`UPDATE lb_rules SET log_enabled=1 WHERE caddy_id='lb_log_pub'`); err != nil {
		t.Fatalf("enable log for published rule: %v", err)
	}

	// 未发布 A：启用上游数为零（渲染跳过）。
	seedHTTPRuleForGeneration(t, database, "lb_log_noup", "noup.example.test", 9090)
	if _, err := database.Exec(`UPDATE upstreams SET enabled=0 WHERE rule_id='lb_log_noup';
		UPDATE lb_rules SET log_enabled=1 WHERE caddy_id='lb_log_noup'`); err != nil {
		t.Fatalf("seed upstreamless rule: %v", err)
	}

	// 未发布 B：启用 TLS 但证书未就绪（整条规则 fail-closed 跳过）。
	seedHTTPRuleForGeneration(t, database, "lb_log_tlswait", "tlswait.example.test", 9091)
	if _, err := database.Exec(`UPDATE lb_rules SET log_enabled=1, enable_tls=1, tls_source='manual', tls_cert='', tls_key='' WHERE caddy_id='lb_log_tlswait'`); err != nil {
		t.Fatalf("seed tls-waiting rule: %v", err)
	}

	cfg := generateCaddyConfigFromStore(database)
	if message, failed := cfg[caddyConfigGenerationErrorKey].(string); failed {
		t.Fatalf("generate config: %s", message)
	}
	servers := mustMap(t, mustMap(t, mustMap(t, cfg["apps"], "apps")["http"], "http")["servers"], "servers")
	for _, port := range []string{"http_9090", "http_9091"} {
		if _, exists := servers[port]; exists {
			t.Fatalf("未发布规则仍占用 server %s（发布集收窄失效）", port)
		}
	}

	published := mustMap(t, servers["http_8080"], "http_8080")
	loggerNames := mustMap(t, mustMap(t, mustMap(t, published["logs"], "logs")["logger_names"], "logger_names"), "logger_names")
	if got := loggerNames["pub.example.test"]; got != "rule_lb_log_pub" {
		t.Fatalf("已发布规则 logger_names=%v, want pub.example.test→rule_lb_log_pub", loggerNames)
	}

	rootLogs := mustMap(t, mustMap(t, cfg["logging"], "logging")["logs"], "logging.logs")
	if _, exists := rootLogs["rule_lb_log_pub"]; !exists {
		t.Fatalf("已发布规则缺 logging.logs 条目: %v", rootLogs)
	}
	for _, unpublished := range []string{"rule_lb_log_noup", "rule_lb_log_tlswait"} {
		if _, exists := rootLogs[unpublished]; exists {
			t.Fatalf("未发布规则 %s 仍占用 logging.logs 条目（日志写盘面虚增）", unpublished)
		}
	}
}

// 默认站（:80 落地页）必须与规则 server 同构关闭引擎自动 HTTPS：否则 Caddy
// 会对 :80 追加 catch-all 308，与落地页路由竞争产生 superfluous WriteHeader。
func TestGenerateCaddyConfig_defaultSiteDisablesAutomaticHTTPS(t *testing.T) {
	_, database := newClusterTestService(t)
	seedHTTPRuleForGeneration(t, database, "lb_autohttps", "auto.example.test", 8080)
	cfg := generateCaddyConfigFromStore(database)
	if message, failed := cfg[caddyConfigGenerationErrorKey].(string); failed {
		t.Fatalf("generate config: %s", message)
	}
	servers := mustMap(t, mustMap(t, mustMap(t, cfg["apps"], "apps")["http"], "http")["servers"], "servers")
	for _, serverName := range []string{"http_80", "http_8080"} {
		server := mustMap(t, servers[serverName], serverName)
		automaticHTTPS := mustMap(t, server["automatic_https"], serverName+" automatic_https")
		if automaticHTTPS["disable"] != true {
			t.Fatalf("%s.automatic_https.disable=%v, want true", serverName, automaticHTTPS["disable"])
		}
	}
}

// 预检 directives 不读请求体（因此 request_body 限额只约束「会读体的」策略级
// 引擎顺序）：预检恒发 SecRequestBodyAccess Off，且全部 SecRule 都是 phase:1
// REMOTE_ADDR/健康检查形态，不引用任何请求体容器。
func TestIPPrecheckDirectivesDoNotReadRequestBody(t *testing.T) {
	policy := &models.SecurityPolicy{
		ID:             9,
		Mode:           "off",
		GeoIPMode:      "deny",
		GeoIPCountries: json.RawMessage(`["海外"]`),
	}
	directives := mustDirectives(buildIPPrecheckDirectives([]*models.SecurityPolicy{policy}, 403, "lb_precheck_body"))
	if directives == "" {
		t.Fatal("预检 directives 为空（无法断言不变量）")
	}
	if !strings.Contains(directives, "SecRequestBodyAccess Off") {
		t.Fatalf("预检 directives 未显式关闭请求体访问:\n%s", directives)
	}
	for _, banned := range []string{"SecRequestBodyAccess On", "REQUEST_BODY", "ARGS_POST", "XML:/*", "SecRuleRequestBody"} {
		if strings.Contains(directives, banned) {
			t.Fatalf("预检 directives 含读体标记 %q（request_body 顺序不变量收窄前提被破坏）:\n%s", banned, directives)
		}
	}
	for _, line := range strings.Split(directives, "\n") {
		if !strings.HasPrefix(line, "SecRule ") {
			continue
		}
		if !strings.Contains(line, "phase:1") {
			t.Fatalf("预检 SecRule 非 phase:1（可能读体）: %s", line)
		}
	}
}
