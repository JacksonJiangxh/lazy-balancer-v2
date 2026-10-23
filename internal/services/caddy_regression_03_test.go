package services

import (
	"database/sql"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
	"unicode/utf8"

	"lazy-balancer-v2/internal/models"
)

// 前被截断到 1KB 内且保持合法 UTF-8，防止经 last_sync_error / cert_jobs.message
// 等有界通道传播时膨胀。
func TestCaddyErrorBodyTruncation(t *testing.T) {
	// 1500 字节中文 + 3KB ASCII 的混合超长错误体：截断点落在多字节字符中间。
	longBody := strings.Repeat("中", 500) + strings.Repeat("x", 3000)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.Contains(r.URL.RawQuery, "validate=true") {
			w.WriteHeader(http.StatusBadRequest)
		} else {
			w.WriteHeader(http.StatusInternalServerError)
		}
		_, _ = w.Write([]byte(longBody))
	}))
	t.Cleanup(server.Close)
	service := NewCaddyService(server.URL)

	// /load 路径（applyConfigLocked）
	applyErr := service.ApplyConfig(map[string]interface{}{})
	if applyErr == nil {
		t.Fatal("ApplyConfig succeeded despite mock 500")
	}
	assertBoundedErrorBody(t, "ApplyConfig", applyErr.Error())

	// /load?validate=true 路径（ValidateConfig）
	validateErr := service.ValidateConfig(map[string]interface{}{})
	if validateErr == nil {
		t.Fatal("ValidateConfig succeeded despite mock 400")
	}
	assertBoundedErrorBody(t, "ValidateConfig", validateErr.Error())
}

// ValidateConfig 的状态码分类必须与 applyConfigWithOptions 同构：4xx=候选
// 配置被拒（ConfigRejectedError → handler 400），5xx=admin 系统故障（普通
// 错误 → handler 500）。把 5xx 归为「配置被拒」会让基础设施故障被表述成
// 用户配置错误，操作员会反复改一份本身正确的配置。
func TestValidateConfig_classifiesRejectionVsSystemFailure(t *testing.T) {
	for _, tc := range []struct {
		name       string
		status     int
		wantReject bool
	}{
		{name: "4xx rejection", status: http.StatusBadRequest, wantReject: true},
		{name: "5xx system failure", status: http.StatusServiceUnavailable, wantReject: false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				w.WriteHeader(tc.status)
				_, _ = w.Write([]byte(`{"error":"boom"}`))
			}))
			t.Cleanup(server.Close)
			service := NewCaddyService(server.URL)

			err := service.ValidateConfig(map[string]interface{}{})
			if err == nil {
				t.Fatalf("ValidateConfig succeeded despite %d", tc.status)
			}
			if got := IsConfigRejected(err); got != tc.wantReject {
				t.Fatalf("IsConfigRejected(%d)=%v, want %v (err=%v)", tc.status, got, tc.wantReject, err)
			}
		})
	}
}

func assertBoundedErrorBody(t *testing.T, call, message string) {
	t.Helper()
	if !utf8.ValidString(message) {
		t.Fatalf("%s error contains invalid UTF-8: %q", call, message)
	}
	if len(message) > caddyErrorBodyMaxBytes+128 {
		t.Fatalf("%s error length=%d exceeds bound (%d+prefix)", call, len(message), caddyErrorBodyMaxBytes)
	}
	// 可操作的错误体前缀必须保留（前 100 个中文字符）。
	if !strings.Contains(message, strings.Repeat("中", 100)) {
		t.Fatalf("%s error lost the actionable body prefix: %.120s...", call, message)
	}
}

func TestGetSecurityPoliciesForRule_logsOnlyRealPolicyReadFailures(t *testing.T) {
	// Given a healthy binding, an enabled but type-corrupted policy, and a
	// normally disabled binding.
	_, database := newClusterTestService(t)
	seedGenerationRule(t, database, "lb_policy_scan", false)
	if _, err := database.Exec(`INSERT INTO security_policies (id,name,mode,enabled,anomaly_threshold) VALUES
		(1,'healthy','off',1,5),
		(2,'corrupted','blocking',1,'not-an-integer'),
		(3,'disabled','blocking',0,5);
		INSERT INTO security_policy_bindings (rule_caddy_id,policy_id) VALUES
		('lb_policy_scan',1),('lb_policy_scan',2),('lb_policy_scan',3)`); err != nil {
		t.Fatal(err)
	}
	logs := captureApplicationLogs(t)

	// When the preview/fallback path loads all bindings.
	policies := GetSecurityPoliciesForRule("lb_policy_scan")

	// Then healthy policies still load, the real read error is visible, and the
	// ordinary disabled/not-found shape remains silent.
	if len(policies) != 1 || policies[0].ID != 1 {
		t.Fatalf("policies=%+v, want only healthy policy #1", policies)
	}
	if !strings.Contains(logs.String(), "安全策略 #2") || !strings.Contains(logs.String(), "not-an-integer") {
		t.Fatalf("corrupted policy read must be visible, logs=%q", logs.String())
	}
	if strings.Contains(logs.String(), "安全策略 #3") {
		t.Fatalf("disabled policy must remain a normal empty result, logs=%q", logs.String())
	}
}

// 严格同构——每规则返回全部启用策略（policy_id ASC）。最高 policy_id 绑定指向
// 禁用策略时，预载切片恰好只含次低的启用策略（旧单策略 MAX 语义下两者都为 nil，
// 新语义下禁用绑定仅占位、不产生元素）。
func TestLoadSecurityPolicyContext_multiBindingMatchesMultiPolicyQuery(t *testing.T) {
	// Given 两条绑定：低 policy_id 启用 + 高 policy_id 禁用
	useTemporaryCertDir(t)
	_, database := newClusterTestService(t)
	seedGenerationRule(t, database, "lb_multi_binding", false)
	seedBoundSecurityPolicy(t, database, "lb_multi_binding", "blocking", true)
	seedBoundSecurityPolicy(t, database, "lb_multi_binding", "blocking", false)

	// When 最高绑定为禁用策略：多策略查询仅返回次低的启用策略
	expected := GetSecurityPoliciesForRule("lb_multi_binding")
	if len(expected) != 1 {
		t.Fatalf("GetSecurityPoliciesForRule 应仅返回 1 条启用策略（禁用绑定被过滤），实际 %d 条", len(expected))
	}
	ctx, err := loadSecurityPolicyContext(database)
	if err != nil {
		t.Fatalf("loadSecurityPolicyContext: %v", err)
	}

	// Then 预载切片与多策略单查逐元素同构（id+mode 逐位置一致）
	assertPoliciesIsomorphic(t, expected, ctx.policyByRule["lb_multi_binding"])

	// When 删除禁用绑定（预载结果不应变化——禁用绑定本就零贡献）
	if _, err := database.Exec(`DELETE FROM security_policy_bindings WHERE policy_id = (SELECT MAX(policy_id) FROM security_policy_bindings WHERE rule_caddy_id='lb_multi_binding')`); err != nil {
		t.Fatalf("delete disabled binding: %v", err)
	}

	// Then 同构关系保持
	expectedAfter := GetSecurityPoliciesForRule("lb_multi_binding")
	ctx2, err := loadSecurityPolicyContext(database)
	if err != nil {
		t.Fatalf("loadSecurityPolicyContext(2): %v", err)
	}
	assertPoliciesIsomorphic(t, expectedAfter, ctx2.policyByRule["lb_multi_binding"])
}

// assertPoliciesIsomorphic 断言预载切片与 GetSecurityPoliciesForRule 逐元素一致
// （长度相等，每个位置的 id 与 mode 相同）。
func assertPoliciesIsomorphic(t *testing.T, want, got []*models.SecurityPolicy) {
	t.Helper()
	if len(got) != len(want) {
		t.Fatalf("预载策略数=%d，与 GetSecurityPoliciesForRule 的 %d 条不一致", len(got), len(want))
	}
	for i := range want {
		if got[i].ID != want[i].ID || got[i].Mode != want[i].Mode {
			t.Fatalf("位置 %d 预载 policy(id=%d mode=%s) 与单查 policy(id=%d mode=%s) 不一致", i, got[i].ID, got[i].Mode, want[i].ID, want[i].Mode)
		}
	}
}

// 不加载证书；同端口规则无启用上游或未开 TLS 时不进 TLS 策略。
func TestGenerateRuleServerContext_gatesByEnableTLSAndEnabledUpstreams(t *testing.T) {
	// Given
	useTemporaryCertDir(t)
	_, database := newClusterTestService(t)
	seedTLSCtxRule(t, database, "lb_ctx_main", 8443, 1, "main.example.test", 1)
	// 同端口：开 TLS + 有证书，但无任何启用上游 → 不进策略
	seedTLSCtxRule(t, database, "lb_ctx_no_upstream", 8443, 1, "noupstream.example.test", 0)
	// 同端口：有启用上游 + 有证书，但 enable_tls=0 → 不进策略
	seedTLSCtxRule(t, database, "lb_ctx_no_tls", 8443, 0, "notls.example.test", 1)
	// 主规则自身 enable_tls=0 的对照
	seedTLSCtxRule(t, database, "lb_ctx_main_off", 9443, 0, "mainoff.example.test", 1)

	// When
	cfg := GenerateRuleServerContext("lb_ctx_main", 8443, "http", "main.example.test")
	server := cfg["apps"].(map[string]interface{})["http"].(map[string]interface{})["servers"].(map[string]interface{})["http_8443"].(map[string]interface{})

	// Then 仅主规则进入 TLS 策略（no_tls/no_upstream 被门控）
	policies, _ := server["tls_connection_policies"].([]interface{})
	if len(policies) != 1 {
		t.Fatalf("tls_connection_policies 条数=%d, want 1: %#v", len(policies), server["tls_connection_policies"])
	}
	sel := policies[0].(map[string]interface{})["certificate_selection"].(map[string]interface{})
	if tags, _ := sel["any_tag"].([]string); len(tags) != 1 || tags[0] != "lb_ctx_main" {
		t.Fatalf("any_tag=%#v, want [lb_ctx_main]", sel["any_tag"])
	}
	// 主规则开 TLS + 手动证书 → 加载证书文件
	tlsApp, hasTLS := cfg["apps"].(map[string]interface{})["tls"].(map[string]interface{})
	if !hasTLS {
		t.Fatal("主规则开启 TLS 应生成 tls.load_files")
	}
	if _, ok := tlsApp["certificates"].(map[string]interface{}); !ok {
		t.Fatalf("tls app 缺 certificates: %#v", tlsApp)
	}

	// When 主规则 enable_tls=0 的对照
	cfgOff := GenerateRuleServerContext("lb_ctx_main_off", 9443, "http", "mainoff.example.test")
	// 为空切片而非 nil——JSON 序列化输出 [] 而非 null（消费方按数组形状解构）。
	if _, hasTLS := cfgOff["apps"].(map[string]interface{})["tls"].(map[string]interface{}); hasTLS {
		t.Fatal("enable_tls=0 的规则不应生成 tls.load_files")
	}
	serverOff := cfgOff["apps"].(map[string]interface{})["http"].(map[string]interface{})["servers"].(map[string]interface{})["http_9443"].(map[string]interface{})
	if serverOff["tls_connection_policies"] == nil {
		t.Fatal("无策略时 tls_connection_policies 应为空数组（非 nil/JSON null）")
	}
}

// seedTLSCtxRule 播种一条带手动证书与（可选）启用上游的 HTTP TLS 规则。
func seedTLSCtxRule(t *testing.T, database *sql.DB, ruleID string, port int, enableTLS int, domain string, enabledUpstream int) {
	t.Helper()
	if _, err := database.Exec(`INSERT INTO lb_rules (caddy_id,name,protocol,domain,listen_port,strategy,health_check_path,enabled,enable_tls,tls_source,tls_cert,tls_key)
		VALUES (?,?, 'http', ?, ?, 'weighted_round_robin', '', 1, ?, 'manual', 'cert', 'key')`, ruleID, ruleID, domain, port, enableTLS); err != nil {
		t.Fatalf("seed TLS ctx rule %s: %v", ruleID, err)
	}
	if enabledUpstream == 1 {
		if _, err := database.Exec(`INSERT INTO upstreams (rule_id,host,port,enabled,protocol) VALUES (?, '127.0.0.1', 9000, 1, 'http')`, ruleID); err != nil {
			t.Fatalf("seed TLS ctx upstream %s: %v", ruleID, err)
		}
	}
}

// countingQueryStore 包装 caddyConfigStore 统计 Query 次数（批量判定收敛度钉）。
type countingQueryStore struct {
	caddyConfigStore
	queries *int
}

func (c countingQueryStore) Query(query string, args ...any) (*sql.Rows, error) {
	*c.queries++
	return c.caddyConfigStore.Query(query, args...)
}

// 预览的 TLS 就绪判据必须与全量渲染同口径：已禁用规则或全部上游被禁用的
// 规则，即使带证书也不得在预览里展示 load_files（真实配置不会加载它）。
func TestGenerateRuleServerContext_disabledOrUpstreamlessRuleHasNoTLSFiles(t *testing.T) {
	useTemporaryCertDir(t)
	_, database := newClusterTestService(t)
	// 规则级 enabled=0（单条自带证书与启用上游）。
	if _, err := database.Exec(`INSERT INTO lb_rules (caddy_id,name,protocol,domain,listen_port,strategy,health_check_path,enabled,enable_tls,tls_source,tls_cert,tls_key)
		VALUES ('lb_ctx_disabled','disabled','http','disabled.example.test',7443,'weighted_round_robin','',0,1,'manual','cert','key')`); err != nil {
		t.Fatalf("seed disabled rule: %v", err)
	}
	if _, err := database.Exec(`INSERT INTO upstreams (rule_id,host,port,enabled,protocol) VALUES ('lb_ctx_disabled','127.0.0.1',9000,1,'http')`); err != nil {
		t.Fatalf("seed upstream: %v", err)
	}
	// 规则启用但全部上游禁用。
	if _, err := database.Exec(`INSERT INTO lb_rules (caddy_id,name,protocol,domain,listen_port,strategy,health_check_path,enabled,enable_tls,tls_source,tls_cert,tls_key)
		VALUES ('lb_ctx_noup','noup','http','noup.example.test',7444,'weighted_round_robin','',1,1,'manual','cert','key')`); err != nil {
		t.Fatalf("seed upstreamless rule: %v", err)
	}
	if _, err := database.Exec(`INSERT INTO upstreams (rule_id,host,port,enabled,protocol) VALUES ('lb_ctx_noup','127.0.0.1',9001,0,'http')`); err != nil {
		t.Fatalf("seed disabled upstream: %v", err)
	}

	for _, tc := range []struct {
		id, domain string
		port       int
	}{
		{"lb_ctx_disabled", "disabled.example.test", 7443},
		{"lb_ctx_noup", "noup.example.test", 7444},
	} {
		cfg := GenerateRuleServerContext(tc.id, tc.port, "http", tc.domain)
		if _, hasTLS := cfg["apps"].(map[string]interface{})["tls"].(map[string]interface{}); hasTLS {
			t.Fatalf("%s: 不可发布规则不得在预览里生成 tls.load_files", tc.id)
		}
	}
}

// ACME 可用性批量判定与单条路径同语义（SelectCertificate：域名匹配 + 有效期
// + 可解析），并覆盖「未知规则/过期证书/域名不匹配」三种否定形态。
func TestACMECertAvailabilityForRules_matchesSingleRuleSemantics(t *testing.T) {
	_, database := newClusterTestService(t)
	// SelectCertificate 要求证书与私钥成对可解析（X509KeyPair）——夹具必须是
	// 真实配对的 cert+key，否则「有效证书」前提不成立。
	validPEM, validKey := certificatePairForDomains(t, time.Now().Add(-time.Hour), time.Now().Add(90*24*time.Hour), "example.com")
	expiredPEM, expiredKey := certificatePairForDomains(t, time.Now().Add(-48*time.Hour), time.Now().Add(-time.Hour), "example.com")
	otherPEM, otherKey := certificatePairForDomains(t, time.Now().Add(-time.Hour), time.Now().Add(90*24*time.Hour), "other.example.com")
	for _, row := range []struct {
		id     int
		ruleID string
		domain string
		pem    string
		key    string
	}{
		{101, "lb_batch_ok", "example.com", validPEM, validKey},
		{102, "lb_batch_expired", "example.com", expiredPEM, expiredKey},
		{103, "lb_batch_mismatch", "other.example.com", otherPEM, otherKey},
	} {
		if _, err := database.Exec(`INSERT INTO cert_jobs (id,rule_id,domain,status,cert_pem,key_pem,updated_at) VALUES (?,?,?,'issued',?,?,datetime('now'))`, row.id, row.ruleID, row.domain, row.pem, row.key); err != nil {
			t.Fatalf("seed cert job %s: %v", row.ruleID, err)
		}
	}

	// 查询次数钉：批量判定对 N 条规则只发 1 条查询（预取候选），逐规则
	// 版本是 O(N) 往返 + O(N) 次 PEM 解析。
	queries := 0
	counted := countingQueryStore{caddyConfigStore: database, queries: &queries}
	got := acmeCertAvailabilityForRules(counted, map[string]string{
		"lb_batch_ok":       "example.com",
		"lb_batch_expired":  "example.com",
		"lb_batch_mismatch": "example.com",
		"lb_batch_missing":  "example.com",
	})
	if queries != 1 {
		t.Fatalf("批量判定发了 %d 条查询，want 1", queries)
	}
	if !got["lb_batch_ok"] {
		t.Fatalf("valid cert must be available: %+v", got)
	}
	for _, id := range []string{"lb_batch_expired", "lb_batch_mismatch", "lb_batch_missing"} {
		if got[id] {
			t.Fatalf("%s must not be available: %+v", id, got)
		}
	}
	if len(got) != 1 {
		t.Fatalf("批量判定只应包含可用规则，got=%+v", got)
	}
	// 与单条路径逐条对齐（单一谓词语义）。
	for ruleID, domain := range map[string]string{"lb_batch_ok": "example.com", "lb_batch_expired": "example.com", "lb_batch_mismatch": "example.com"} {
		if single := isACMECertIssuedFromStore(database, ruleID, domain); single != got[ruleID] {
			t.Fatalf("%s batch=%v single=%v（批量与单条判定必须一致）", ruleID, got[ruleID], single)
		}
	}
}
