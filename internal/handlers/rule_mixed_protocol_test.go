package handlers

// HTTP 规则混合 http/https 上游池在 Caddy 无逐上游
// 协议概念（shouldUseTLS 传输级+except_ports 例外表，v2.11.6 httptransport.go:
// 674-680）——任一 https 上游使池级 TLS 传输生效，http 上游明文打 TLS 端口
// 静默全灭 502。保存/导入侧显式拒绝混布（用户裁定修法①）。

import (
	"context"
	"fmt"
	"log"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/gin-gonic/gin"

	"lazy-balancer-v2/internal/db"
)

// 五态门禁矩阵（JJC-20261118-002 裁决 2，主池）：混布+允许策略=放行 /
// 混布+其他策略=400（文案点名允许策略）/ uniform+任何策略=现状 /
// 混布+主动健康检查=400（伴随门）/ 混布+空 strategy=放行。
func TestRulePayload_rejectsMixedHttpHttpsUpstreamPool(t *testing.T) {
	handler := newRuleFeatureTestHandlers(t)
	gin.SetMode(gin.TestMode)
	router := gin.New()
	router.POST("/rules", handler.CreateRule)

	cases := []struct {
		name      string
		strategy  string
		hc        bool
		upstreams string
		wantCode  int
		wantBody  string
	}{
		{"混布+weighted_round_robin 放行", `weighted_round_robin`, false, `[{"host":"10.0.0.1","port":8080,"protocol":"http","enabled":true},{"host":"10.0.0.2","port":8443,"protocol":"https","enabled":true}]`, http.StatusCreated, ""},
		{"混布+chain_fallback 放行", `chain_fallback`, false, `[{"host":"10.0.0.1","port":8080,"protocol":"http","enabled":true},{"host":"10.0.0.2","port":8443,"protocol":"https","enabled":true}]`, http.StatusCreated, ""},
		{"混布+空 strategy 放行", ``, false, `[{"host":"10.0.0.1","port":8080,"protocol":"http","enabled":true},{"host":"10.0.0.2","port":8443,"protocol":"https","enabled":true}]`, http.StatusCreated, ""},
		{"混布+least_conn 拒绝", `least_conn`, false, `[{"host":"10.0.0.1","port":8080,"protocol":"http","enabled":true},{"host":"10.0.0.2","port":8443,"protocol":"https","enabled":true}]`, http.StatusBadRequest, "weighted_round_robin"},
		{"混布+ip_hash 拒绝", `ip_hash`, false, `[{"host":"10.0.0.1","port":8080,"protocol":"http","enabled":true},{"host":"10.0.0.2","port":8443,"protocol":"https","enabled":true}]`, http.StatusBadRequest, "chain_fallback"},
		{"混布+主动健康检查 400（伴随门）", `weighted_round_robin`, true, `[{"host":"10.0.0.1","port":8080,"protocol":"http","enabled":true},{"host":"10.0.0.2","port":8443,"protocol":"https","enabled":true}]`, http.StatusBadRequest, "健康检查"},
		{"uniform+cookie 现状放行", `cookie`, false, `[{"host":"10.0.0.1","port":8080,"protocol":"http","enabled":true},{"host":"10.0.0.2","port":8081,"protocol":"http","enabled":true}]`, http.StatusCreated, ""},
		{"纯 http 池放行（回归）", `weighted_round_robin`, false, `[{"host":"10.0.0.1","port":8080,"protocol":"http","enabled":true},{"host":"10.0.0.2","port":8081,"protocol":"http","enabled":true}]`, http.StatusCreated, ""},
		{"纯 https 池放行（回归）", `weighted_round_robin`, false, `[{"host":"10.0.0.1","port":8443,"protocol":"https","enabled":true},{"host":"10.0.0.2","port":8444,"protocol":"https","enabled":true}]`, http.StatusCreated, ""},
		{"混合但 https 上游禁用放行（禁用不参与渲染）", `least_conn`, false, `[{"host":"10.0.0.1","port":8080,"protocol":"http","enabled":true},{"host":"10.0.0.2","port":8443,"protocol":"https","enabled":false}]`, http.StatusCreated, ""},
	}
	for i, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			body := fmt.Sprintf(`{"name":"mixpool-%d","protocol":"http","domain":"mix-%d.test","listen_port":%d,"strategy":%q,"enable_active_health_check":%v,"health_check_interval":10,"health_check_timeout":2,"health_check_unhealthy_threshold":3,"health_check_healthy_threshold":2,"upstreams":%s}`,
				i, i, 19300+i, tc.strategy, tc.hc, tc.upstreams)
			req := httptest.NewRequest(http.MethodPost, "/rules", strings.NewReader(body))
			req.Header.Set("Content-Type", "application/json")
			rec := httptest.NewRecorder()
			router.ServeHTTP(rec, req)
			if rec.Code != tc.wantCode {
				t.Fatalf("status=%d, want %d; body=%s", rec.Code, tc.wantCode, rec.Body.String())
			}
			if tc.wantBody != "" && !strings.Contains(rec.Body.String(), tc.wantBody) {
				t.Fatalf("body must mention %q, got %s", tc.wantBody, rec.Body.String())
			}
		})
	}
}

// 备份侧同门：手造备份带混布池+不允许策略须 400；允许策略放行（v2 导入双态）。
func TestValidateBackupRuleReferences_rejectsMixedHttpHttpsPool(t *testing.T) {
	reject := map[string][]map[string]any{
		"lb_rules": {{"caddy_id": "lb_mixbak", "protocol": "http", "strategy": "least_conn"}},
		"upstreams": {
			{"rule_id": "lb_mixbak", "host": "10.0.0.1", "port": 8080, "weight": 1, "protocol": "http", "enabled": true},
			{"rule_id": "lb_mixbak", "host": "10.0.0.2", "port": 8443, "weight": 1, "protocol": "https", "enabled": true},
		},
	}
	err := validateBackupRuleReferences(reject)
	if err == nil || !strings.Contains(err.Error(), "混布") && !strings.Contains(err.Error(), "混合") {
		t.Fatalf("mixed pool backup must be rejected, got %v", err)
	}

	allow := map[string][]map[string]any{
		"lb_rules": {{"caddy_id": "lb_mixbak_ok", "protocol": "http", "strategy": "weighted_round_robin"}},
		"upstreams": {
			{"rule_id": "lb_mixbak_ok", "host": "10.0.0.1", "port": 8080, "weight": 1, "protocol": "http", "enabled": true},
			{"rule_id": "lb_mixbak_ok", "host": "10.0.0.2", "port": 8443, "weight": 1, "protocol": "https", "enabled": true},
		},
	}
	if err := validateBackupRuleReferences(allow); err != nil {
		t.Fatalf("混布+允许策略的 v2 备份须放行，got %v", err)
	}
}

// 同族（路径规则自定义上游池，收敛面）：路径级自定义上游混布 + 不允许策略
// 拒绝；允许策略放行（与主池同谓词同口径）。
func TestRulePayload_rejectsMixedPathRuleUpstreamPool(t *testing.T) {
	handler := newRuleFeatureTestHandlers(t)
	gin.SetMode(gin.TestMode)
	router := gin.New()
	router.POST("/rules", handler.CreateRule)

	mkBody := func(strategy string) string {
		return `{"name":"mixpath","protocol":"http","domain":"mixpath.test","listen_port":19320,"strategy":"` + strategy + `","custom_routes_enabled":true,` +
			`"health_check_interval":10,"health_check_timeout":2,"health_check_unhealthy_threshold":3,"health_check_healthy_threshold":2,` +
			`"upstreams":[{"host":"10.0.0.1","port":9000,"weight":1,"enabled":true}],` +
			`"path_rules":[{"sort_order":0,"match_type":"prefix","path":"/api/","upstreams":[` +
			`{"address":"10.0.0.1","port":8080,"weight":1,"protocol":"http"},{"address":"10.0.0.2","port":8443,"weight":1,"protocol":"https"}]}]}`
	}
	req := httptest.NewRequest(http.MethodPost, "/rules", strings.NewReader(mkBody("least_conn")))
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	router.ServeHTTP(rec, req)
	if rec.Code != http.StatusBadRequest || !strings.Contains(rec.Body.String(), "混布") {
		t.Fatalf("path-rule mixed pool must 400, got %d %s", rec.Code, rec.Body.String())
	}

	req = httptest.NewRequest(http.MethodPost, "/rules", strings.NewReader(mkBody("weighted_round_robin")))
	req.Header.Set("Content-Type", "application/json")
	rec = httptest.NewRecorder()
	router.ServeHTTP(rec, req)
	if rec.Code != http.StatusCreated {
		t.Fatalf("path-rule mixed pool + allowed strategy must 201, got %d %s", rec.Code, rec.Body.String())
	}
}

// 混布门收敛三链——存量混布行（直改 DB 或更早版本落库）不得经启用/复制
// 静默投入运行，启动聚合校验须点名告警。保存门与 v2 导入链已拦新数据
//（上方两测试）；启用链/聚合校验/复制链此前零检查。

func seedMixedStoredRule(t *testing.T, id string, enabled bool) {
	seedMixedStoredRuleStrategy(t, id, enabled, "least_conn")
}

// seedMixedStoredRuleStrategy 混布存量行种子（strategy 面矩阵化：默认
// least_conn=不允许策略，保存门/启用门 400 语义保留；允许策略走新放行面）。
func seedMixedStoredRuleStrategy(t *testing.T, id string, enabled bool, strategy string) {
	seedMixedStoredRuleStrategyPort(t, id, enabled, strategy, 19400)
}

func seedMixedStoredRuleStrategyPort(t *testing.T, id string, enabled bool, strategy string, port int) {
	t.Helper()
	if _, err := db.DB.Exec(`INSERT INTO lb_rules (caddy_id,name,description,protocol,domain,listen_port,strategy,health_check_path,enabled,enable_compress,tls_source,enable_tls)
		VALUES (?,?,'','http',?, ?,?,'',?,1,'manual',0)`, id, id, fmt.Sprintf("mixed-%d.example.test", port), port, strategy, enabled); err != nil {
		t.Fatalf("seed mixed rule %s: %v", id, err)
	}
	if _, err := db.DB.Exec(`INSERT INTO upstreams (rule_id,host,port,weight,enabled,protocol) VALUES
		(?,'10.0.0.1',8080,1,1,'http'),(?,'10.0.0.2',8443,1,1,'https')`, id, id); err != nil {
		t.Fatalf("seed mixed upstreams %s: %v", id, err)
	}
}

// 链①：EnableRule 对存量混布行 400（与保存门同款文案），规则保持禁用。
func TestEnableRule_rejectsMixedHttpHttpsStoredPool(t *testing.T) {
	handler, _, _ := newAuditRuleHandlers(t, 0)
	seedMixedStoredRule(t, "lb_mix_enable", false)
	gin.SetMode(gin.TestMode)
	router := gin.New()
	router.POST("/rules/:caddy_id/enable", handler.EnableRule)
	rec := httptest.NewRecorder()

	router.ServeHTTP(rec, httptest.NewRequest(http.MethodPost, "/rules/lb_mix_enable/enable", nil))

	if rec.Code != http.StatusBadRequest || !strings.Contains(rec.Body.String(), "混布") {
		t.Fatalf("enable status=%d body=%s, want 400 点名混布", rec.Code, rec.Body.String())
	}
	var enabled bool
	if err := db.DB.QueryRow("SELECT enabled FROM lb_rules WHERE caddy_id='lb_mix_enable'").Scan(&enabled); err != nil {
		t.Fatalf("read enabled state: %v", err)
	}
	if enabled {
		t.Fatal("被拒规则不得进入启用态")
	}
}

// 链③：DuplicateRule 复制存量混布源行 400，无副本落库（保存门只拦新建/
// 更新载荷，复制是对存量行的旁路放大通道）。
func TestDuplicateRule_rejectsMixedHttpHttpsSourcePool(t *testing.T) {
	handler, _, _ := newAuditRuleHandlers(t, 0)
	seedMixedStoredRule(t, "lb_mix_dup", true)
	gin.SetMode(gin.TestMode)
	router := gin.New()
	router.POST("/rules/:caddy_id/duplicate", handler.DuplicateRule)
	rec := httptest.NewRecorder()

	router.ServeHTTP(rec, httptest.NewRequest(http.MethodPost, "/rules/lb_mix_dup/duplicate", nil))

	if rec.Code != http.StatusBadRequest || !strings.Contains(rec.Body.String(), "混布") {
		t.Fatalf("duplicate status=%d body=%s, want 400 点名混布", rec.Code, rec.Body.String())
	}
	var copies int
	if err := db.DB.QueryRow(`SELECT COUNT(*) FROM lb_rules WHERE name LIKE '%（副本）'`).Scan(&copies); err != nil {
		t.Fatalf("count copies: %v", err)
	}
	if copies != 0 {
		t.Fatalf("被拒复制不得落库, copies=%d", copies)
	}
}

// 链②：启动/UpdateConfig 聚合校验对启用混布行点名 warn（镜像 portTLSMix
// 形态——不阻断启动），而非静默通过。
func TestValidateEnabledStoredRuleConfigs_warnsMixedPoolWithoutBlocking(t *testing.T) {
	newAuditRuleHandlers(t, 0)
	seedMixedStoredRule(t, "lb_mix_agg", true)

	var logs strings.Builder
	oldWriter := log.Writer()
	log.SetOutput(&logs)
	t.Cleanup(func() { log.SetOutput(oldWriter) })

	if err := validateEnabledStoredRuleConfigs(context.Background()); err != nil {
		t.Fatalf("混布是告警不是阻断（存量行不拦启动）: %v", err)
	}
	out := logs.String()
	if !strings.Contains(out, "lb_mix_agg") || !strings.Contains(out, "混布") {
		t.Fatalf("聚合校验未点名混布规则（warn）: %q", out)
	}
}

// ===== JJC-20261118-002 裁决 2：定向放行面（启用/复制/聚合三链条件化）=====

// 链①放行面：EnableRule 对混布+允许策略存量行放行（wrr），规则进入启用态。
func TestEnableRule_allowsMixedPoolWithAllowedStrategy(t *testing.T) {
	handler, _, _ := newAuditRuleHandlers(t, 0)
	seedMixedStoredRuleStrategy(t, "lb_mix_allow_enable", false, "weighted_round_robin")
	gin.SetMode(gin.TestMode)
	router := gin.New()
	router.POST("/rules/:caddy_id/enable", handler.EnableRule)
	rec := httptest.NewRecorder()

	router.ServeHTTP(rec, httptest.NewRequest(http.MethodPost, "/rules/lb_mix_allow_enable/enable", nil))

	if rec.Code != http.StatusOK {
		t.Fatalf("enable status=%d body=%s, want 200（混布+允许策略放行）", rec.Code, rec.Body.String())
	}
	var enabled bool
	if err := db.DB.QueryRow("SELECT enabled FROM lb_rules WHERE caddy_id='lb_mix_allow_enable'").Scan(&enabled); err != nil {
		t.Fatalf("read enabled state: %v", err)
	}
	if !enabled {
		t.Fatal("放行规则应进入启用态")
	}
}

// 链③放行面：DuplicateRule 复制混布+允许策略源行成功落库。
func TestDuplicateRule_allowsMixedPoolWithAllowedStrategy(t *testing.T) {
	handler, _, _ := newAuditRuleHandlers(t, 0)
	seedMixedStoredRuleStrategy(t, "lb_mix_allow_dup", true, "chain_fallback")
	gin.SetMode(gin.TestMode)
	router := gin.New()
	router.POST("/rules/:caddy_id/duplicate", handler.DuplicateRule)
	rec := httptest.NewRecorder()

	router.ServeHTTP(rec, httptest.NewRequest(http.MethodPost, "/rules/lb_mix_allow_dup/duplicate", nil))

	if rec.Code != http.StatusOK && rec.Code != http.StatusCreated {
		t.Fatalf("duplicate status=%d body=%s, want success（混布+允许策略放行）", rec.Code, rec.Body.String())
	}
	var copies int
	if err := db.DB.QueryRow(`SELECT COUNT(*) FROM lb_rules WHERE name LIKE 'lb_mix_allow_dup%（副本）%'`).Scan(&copies); err != nil {
		t.Fatalf("count copies: %v", err)
	}
	if copies != 1 {
		t.Fatalf("放行复制应落库 1 条副本, copies=%d", copies)
	}
}

// 聚合 warn 三口径：①混布+不允许策略 → 协议承载 warn（保留，文案更新）；
// ②混布+允许策略+HC 标志 → 点名 HC 无效 warn；③混布+允许策略无 HC → 静默。
func TestValidateEnabledStoredRuleConfigs_warnCaliberThreeWays(t *testing.T) {
	// 口径③（静默）先行：不得有 warn。
	newAuditRuleHandlers(t, 0)
	seedMixedStoredRuleStrategy(t, "lb_mix_silent", true, "weighted_round_robin")

	var logs strings.Builder
	oldWriter := log.Writer()
	log.SetOutput(&logs)
	t.Cleanup(func() { log.SetOutput(oldWriter) })

	if err := validateEnabledStoredRuleConfigs(context.Background()); err != nil {
		t.Fatalf("允许策略混布行不得阻断: %v", err)
	}
	if strings.Contains(logs.String(), "lb_mix_silent") {
		t.Fatalf("口径③：混布+允许策略+无 HC 应静默，got %q", logs.String())
	}

	// 口径②（HC 无效点名）：清日志重新聚合。
	logs.Reset()
	if _, err := db.DB.Exec(`UPDATE lb_rules SET enable_active_health_check=1, health_check_interval=10, health_check_timeout=2, health_check_unhealthy_threshold=3, health_check_healthy_threshold=2 WHERE caddy_id='lb_mix_silent'`); err != nil {
		t.Fatalf("enable HC flag: %v", err)
	}
	if err := validateEnabledStoredRuleConfigs(context.Background()); err != nil {
		t.Fatalf("HC 标志 warn 不阻断: %v", err)
	}
	out := logs.String()
	if !strings.Contains(out, "lb_mix_silent") || !strings.Contains(out, "健康检查") {
		t.Fatalf("口径②：应点名 HC 在 chain 承载下无效: %q", out)
	}

	// 口径①（不允许策略协议承载 warn）。
	logs.Reset()
	seedMixedStoredRuleStrategyPort(t, "lb_mix_cal1", true, "least_conn", 19412)
	if err := validateEnabledStoredRuleConfigs(context.Background()); err != nil {
		t.Fatalf("不允许策略混布 warn 不阻断: %v", err)
	}
	out = logs.String()
	if !strings.Contains(out, "lb_mix_cal1") || !strings.Contains(out, "混布") {
		t.Fatalf("口径①：应保留协议承载点名 warn: %q", out)
	}
}

// NTLM × 混布互斥回归：ntlm=1 要求 strategy=cookie，与混布两允许策略结构互斥
// （混布+cookie 被混布门拒绝，双门串联闭环）。
func TestRulePayload_NTLMMixedPoolMutuallyExclusive(t *testing.T) {
	handler := newRuleFeatureTestHandlers(t)
	gin.SetMode(gin.TestMode)
	router := gin.New()
	router.POST("/rules", handler.CreateRule)

	// NTLM(cookie) + 混布池 → 混布门 400（cookie 不在允许集）。
	body := `{"name":"ntlm-mix","protocol":"http","domain":"ntlm-mix.test","listen_port":19410,"strategy":"cookie","upstreams":[{"host":"10.0.0.1","port":8080,"protocol":"http","enabled":true},{"host":"10.0.0.2","port":8443,"protocol":"https","enabled":true}]}`
	req := httptest.NewRequest(http.MethodPost, "/rules", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	router.ServeHTTP(rec, req)
	if rec.Code != http.StatusBadRequest || !strings.Contains(rec.Body.String(), "混布") {
		t.Fatalf("NTLM+混布 must 400 at mixed gate, got %d %s", rec.Code, rec.Body.String())
	}

	// NTLM + uniform 池 → 现状放行（NTLM 门零改动回归）。
	body = `{"name":"ntlm-uniform","protocol":"http","domain":"ntlm-uniform.test","listen_port":19411,"strategy":"cookie","ntlm_compatible":1,"tcp_try_duration":-1,"upstream_force_http1":1,"proxy_flush_interval":-1,"upstream_keepalive_timeout":300,"health_check_interval":10,"health_check_timeout":2,"health_check_unhealthy_threshold":3,"health_check_healthy_threshold":2,"upstreams":[{"host":"10.0.0.1","port":8080,"protocol":"http","enabled":true}]}`
	req = httptest.NewRequest(http.MethodPost, "/rules", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	rec = httptest.NewRecorder()
	router.ServeHTTP(rec, req)
	if rec.Code != http.StatusCreated {
		t.Fatalf("NTLM+uniform 现状放行回归失败, got %d %s", rec.Code, rec.Body.String())
	}
}

// 伴随门存量面：混布+允许策略+HC=1 的存量行经 EnableRule 400（响亮拒绝，
// 直改 DB 行不得绕过）。uniform 池不受影响（边界回归）。
func TestEnableRule_rejectsMixedPoolWithHealthCheck(t *testing.T) {
	handler, _, _ := newAuditRuleHandlers(t, 0)
	seedMixedStoredRuleStrategy(t, "lb_mix_hc", false, "weighted_round_robin")
	if _, err := db.DB.Exec(`UPDATE lb_rules SET enable_active_health_check=1, health_check_interval=10, health_check_timeout=2, health_check_unhealthy_threshold=3, health_check_healthy_threshold=2 WHERE caddy_id='lb_mix_hc'`); err != nil {
		t.Fatalf("enable HC flag: %v", err)
	}
	gin.SetMode(gin.TestMode)
	router := gin.New()
	router.POST("/rules/:caddy_id/enable", handler.EnableRule)
	rec := httptest.NewRecorder()

	router.ServeHTTP(rec, httptest.NewRequest(http.MethodPost, "/rules/lb_mix_hc/enable", nil))

	if rec.Code != http.StatusBadRequest || !strings.Contains(rec.Body.String(), "健康检查") {
		t.Fatalf("混布+HC 存量启用必须 400 点名健康检查, got %d %s", rec.Code, rec.Body.String())
	}
}
