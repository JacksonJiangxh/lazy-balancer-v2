package handlers

// 规则生命周期 handler 族修复的回归钉测。
// 覆盖：TCP 自愈族（TCP 自愈清单扩面）、删除复核（DisableRule 放锁窗口
// 删除复核）、规则文本长度上限（name/description 长度门）、并发修改复核（UpdateRule 放锁
// 窗口并发修改复核）、提交后失败审计（五端点提交后失败审计）。

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
	"unicode/utf8"

	"github.com/gin-gonic/gin"

	"lazy-balancer-v2/internal/db"
	"lazy-balancer-v2/internal/services"
)

// seedTCPRuleWithDeadHTTPOnlyConfig 播种带存量 HTTP 专属死值的 TCP 规则：
// proxy 超时族非零、custom_routes_enabled=1、dynamic_dns=1、strategy=cookie。
func seedTCPRuleWithDeadHTTPOnlyConfig(t *testing.T, caddyID, name string, listenPort int) {
	t.Helper()
	_, err := db.DB.Exec(`INSERT INTO lb_rules (caddy_id,name,description,protocol,domain,listen_port,strategy,
		health_check_path,health_check_interval,health_check_timeout,health_check_unhealthy_threshold,health_check_healthy_threshold,
		enable_active_health_check,tcp_health_check_port,tcp_proxy_protocol,tcp_try_duration,tcp_try_interval,
		request_body_max_size_mb,upstream_keepalive_timeout,server_tokens_hidden,
		enable_tls,tls_source,acme_config_id,ca_provider_id,tls_cert,tls_key,tls_http_redirect,
		enable_compress,compress_types,enabled,created_by,host_header,log_enabled,
		custom_routes_enabled,proxy_dial_timeout,proxy_response_header_timeout,proxy_read_timeout,
		proxy_write_timeout,proxy_stream_timeout,proxy_flush_interval,proxy_stream_close_delay,
		dynamic_dns)
		VALUES (?,?,'',?,'',?,'cookie','',10,5,3,2,0,9001,0,5000,300,0,0,0,
		0,'manual',0,0,'','',0,1,'gzip',0,0,'',0,
		1,30,60,120,120,300,-1,15,1)`, caddyID, name, "tcp", listenPort)
	if err != nil {
		t.Fatalf("seed tcp dead-config rule %s: %v", caddyID, err)
	}
	if _, err := db.DB.Exec(`INSERT INTO upstreams (rule_id,host,port,weight,enabled,protocol) VALUES (?,'127.0.0.1',9000,1,1,'tcp')`, caddyID); err != nil {
		t.Fatalf("seed upstream for %s: %v", caddyID, err)
	}
	if _, err := db.DB.Exec(`INSERT INTO path_rules (rule_id,sort_order,match_type,path) VALUES (?,1,'prefix','/legacy')`, caddyID); err != nil {
		t.Fatalf("seed path rule for %s: %v", caddyID, err)
	}
}

// seedTestDNSProviderConfig 播种 DNS 提供商配置并返回 id（acme_dns 规则引用门要求）。
func seedTestDNSProviderConfig(t *testing.T) int64 {
	t.Helper()
	result, err := db.DB.Exec(`INSERT INTO certificate_configs (name,dns_provider,dns_credentials,enabled) VALUES ('dns88','dnspod','{"token":"x"}',1)`)
	if err != nil {
		t.Fatalf("seed dns provider config: %v", err)
	}
	id, err := result.LastInsertId()
	if err != nil {
		t.Fatalf("read dns provider id: %v", err)
	}
	return id
}

// readTCPHTTPOnlyDeadColumns 读取 TCP 死配置族终态。
func readTCPHTTPOnlyDeadColumns(t *testing.T, caddyID string) (strategy string, proxy [7]int, customRoutes, dynamicDNS, pathRuleCount int) {
	t.Helper()
	if err := db.DB.QueryRow(`SELECT COALESCE(strategy,''), COALESCE(proxy_dial_timeout,0), COALESCE(proxy_response_header_timeout,0),
		COALESCE(proxy_read_timeout,0), COALESCE(proxy_write_timeout,0), COALESCE(proxy_stream_timeout,0),
		COALESCE(proxy_flush_interval,0), COALESCE(proxy_stream_close_delay,0),
		COALESCE(custom_routes_enabled,0), COALESCE(dynamic_dns,0)
		FROM lb_rules WHERE caddy_id = ?`, caddyID).Scan(
		&strategy, &proxy[0], &proxy[1], &proxy[2], &proxy[3], &proxy[4], &proxy[5], &proxy[6],
		&customRoutes, &dynamicDNS); err != nil {
		t.Fatalf("read tcp dead columns: %v", err)
	}
	if err := db.DB.QueryRow(`SELECT COUNT(*) FROM path_rules WHERE rule_id = ?`, caddyID).Scan(&pathRuleCount); err != nil {
		t.Fatalf("read path rules: %v", err)
	}
	return
}

func assertTCPDeadColumnsHealed(t *testing.T, caddyID string) {
	t.Helper()
	strategy, proxy, customRoutes, dynamicDNS, pathRuleCount := readTCPHTTPOnlyDeadColumns(t, caddyID)
	if strategy != "weighted_round_robin" {
		t.Fatalf("strategy=%q, want weighted_round_robin after TCP heal", strategy)
	}
	if proxy != [7]int{} {
		t.Fatalf("proxy timeouts=%v, want all zero after TCP heal", proxy)
	}
	if customRoutes != 0 || dynamicDNS != 0 {
		t.Fatalf("custom_routes_enabled=%d dynamic_dns=%d, want 0/0 after TCP heal", customRoutes, dynamicDNS)
	}
	if pathRuleCount != 0 {
		t.Fatalf("path_rules=%d, want 0 after TCP heal", pathRuleCount)
	}
}

// TCP 自愈族：同协议 TCP 编辑自愈（存量死值不再让无关编辑恒 400 死端）。
func TestUpdateRule_tcpSameProtocolEditSelfHealsHTTPOnlyConfig(t *testing.T) {
	// Given
	handler := newRuleFeatureTestHandlers(t)
	gin.SetMode(gin.TestMode)
	seedTCPRuleWithDeadHTTPOnlyConfig(t, "lb_tcp_heal", "tcp-heal", 17041)
	router := gin.New()
	router.PUT("/rules/:caddy_id", handler.UpdateRule)
	request := httptest.NewRequest(http.MethodPut, "/rules/lb_tcp_heal", strings.NewReader(`{"name":"healed"}`))
	request.Header.Set("Content-Type", "application/json")
	response := httptest.NewRecorder()

	// When：只改名字（未携带任何 HTTP 专属字段）
	router.ServeHTTP(response, request)

	// Then：200 且死配置族归零、残留路径规则删除
	if response.Code != http.StatusOK {
		t.Fatalf("update status=%d body=%s, want 200", response.Code, response.Body.String())
	}
	assertTCPDeadColumnsHealed(t, "lb_tcp_heal")
}

// TCP 自愈族：复制自愈（tcp+cookie / tcp+proxy 超时 / tcp+自定义路径的
// 存量行不再「复制即 400」；副本不放大死配置）。
func TestDuplicateRule_tcpSelfHealsHTTPOnlyConfig(t *testing.T) {
	// Given
	handler := newRuleFeatureTestHandlers(t)
	gin.SetMode(gin.TestMode)
	seedTCPRuleWithDeadHTTPOnlyConfig(t, "lb_tcp_dup_heal", "tcp-dupsrc", 17042)
	router := gin.New()
	router.POST("/rules/:caddy_id/duplicate", handler.DuplicateRule)
	request := httptest.NewRequest(http.MethodPost, "/rules/lb_tcp_dup_heal/duplicate", nil)
	response := httptest.NewRecorder()

	// When
	router.ServeHTTP(response, request)

	// Then：201，副本死配置族归零且未复制路径规则
	if response.Code != http.StatusCreated {
		t.Fatalf("duplicate status=%d body=%s, want 201", response.Code, response.Body.String())
	}
	var copyID string
	if err := db.DB.QueryRow(`SELECT caddy_id FROM lb_rules WHERE name='tcp-dupsrc（副本）'`).Scan(&copyID); err != nil {
		t.Fatalf("read duplicated rule: %v", err)
	}
	assertTCPDeadColumnsHealed(t, copyID)
}

// TCP 自愈族：Create 的显式携带仍由保存门 400 点名（请求值全部显式，无存量可愈）。
func TestCreateRule_tcpExplicitProxyTimeoutStillRejected(t *testing.T) {
	handler := newRuleFeatureTestHandlers(t)
	gin.SetMode(gin.TestMode)
	router := gin.New()
	router.POST("/rules", handler.CreateRule)
	body := `{"name":"tcp-explicit","protocol":"tcp","listen_port":17043,"proxy_dial_timeout":5,
		"health_check_interval":10,"health_check_timeout":2,"health_check_unhealthy_threshold":3,"health_check_healthy_threshold":2,
		"upstreams":[{"host":"127.0.0.1","port":9000,"enabled":true}]}`
	request := httptest.NewRequest(http.MethodPost, "/rules", strings.NewReader(body))
	request.Header.Set("Content-Type", "application/json")
	response := httptest.NewRecorder()

	router.ServeHTTP(response, request)

	if response.Code != http.StatusBadRequest || !strings.Contains(response.Body.String(), "代理超时") {
		t.Fatalf("create tcp with explicit proxy timeout status=%d body=%s, want 400 代理超时", response.Code, response.Body.String())
	}
}

// 删除复核：DisableRule 放锁窗口内规则被并发删除 → 冲突中止且不写「禁用」审计。
func TestDisableRule_abortsWhenRuleDeletedInLockWindow(t *testing.T) {
	// Given
	handler, _, _ := newAuditRuleHandlers(t, 0)
	seedAuditRule(t, "lb_dis_window", "diswindow", "diswindow.example.test", 18001, true, "acme_dns", true)
	seedAuditUpstream(t, "lb_dis_window")
	services.ResetCAQueueManagerForTest()
	services.InitCAQueueManager(nil, t.TempDir())
	services.GetCAQueueManager().Start()
	t.Cleanup(services.ResetCAQueueManagerForTest)
	disableRuleLockWindowHook = func(caddyID string) {
		if _, err := db.DB.Exec("DELETE FROM lb_rules WHERE caddy_id = ?", caddyID); err != nil {
			t.Errorf("delete rule in lock window: %v", err)
		}
	}
	t.Cleanup(func() { disableRuleLockWindowHook = nil })
	router := gin.New()
	router.POST("/rules/:caddy_id/disable", handler.DisableRule)

	// When
	response := httptest.NewRecorder()
	router.ServeHTTP(response, httptest.NewRequest(http.MethodPost, "/rules/lb_dis_window/disable", nil))

	// Then：409 中止；成功审计缺席
	if response.Code != http.StatusConflict || !strings.Contains(response.Body.String(), "已被删除") {
		t.Fatalf("disable status=%d body=%s, want 409 已被删除", response.Code, response.Body.String())
	}
	var auditCount int
	if err := db.AuditDB.QueryRow(`SELECT COUNT(*) FROM audit_log WHERE action='禁用' AND resource='负载规则' AND detail LIKE '%lb_dis_window%'`).Scan(&auditCount); err != nil {
		t.Fatalf("read disable audit: %v", err)
	}
	if auditCount != 0 {
		t.Fatalf("禁用 success audit=%d, want 0 when rule deleted in lock window", auditCount)
	}
}

// 并发修改复核：UpdateRule 放锁窗口内规则被并发修改 → 409 + 审计「并发修改」，
// DB 保留他人已提交内容。
func TestUpdateRule_abortsWhenRuleConcurrentlyModifiedInLockWindow(t *testing.T) {
	// Given：manual TLS（orphanACME=true）打开证书取消窗口
	handler, _, _ := newAuditRuleHandlers(t, 0)
	seedAuditRule(t, "lb_upd_conc", "updconc", "updconc.example.test", 18002, true, "manual", false)
	seedAuditUpstream(t, "lb_upd_conc")
	services.ResetCAQueueManagerForTest()
	services.InitCAQueueManager(nil, t.TempDir())
	services.GetCAQueueManager().Start()
	t.Cleanup(services.ResetCAQueueManagerForTest)
	updateRuleLockWindowHook = func(caddyID string, window int) {
		if window != 1 {
			return
		}
		if _, err := db.DB.Exec("UPDATE lb_rules SET name='concurrent' WHERE caddy_id = ?", caddyID); err != nil {
			t.Errorf("concurrent update in lock window: %v", err)
		}
	}
	t.Cleanup(func() { updateRuleLockWindowHook = nil })
	router := gin.New()
	router.PUT("/rules/:caddy_id", handler.UpdateRule)
	request := httptest.NewRequest(http.MethodPut, "/rules/lb_upd_conc", strings.NewReader(`{"name":"mine"}`))
	request.Header.Set("Content-Type", "application/json")
	response := httptest.NewRecorder()

	// When
	router.ServeHTTP(response, request)

	// Then：409 点名并发修改；DB 保留并发提交的 name；审计留痕
	if response.Code != http.StatusConflict || !strings.Contains(response.Body.String(), "并发修改") {
		t.Fatalf("update status=%d body=%s, want 409 并发修改", response.Code, response.Body.String())
	}
	var name string
	if err := db.DB.QueryRow(`SELECT name FROM lb_rules WHERE caddy_id='lb_upd_conc'`).Scan(&name); err != nil {
		t.Fatalf("read rule name: %v", err)
	}
	if name != "concurrent" {
		t.Fatalf("rule name=%q, want concurrent（他人已提交内容不得被回退）", name)
	}
	var auditCount int
	if err := db.AuditDB.QueryRow(`SELECT COUNT(*) FROM audit_log WHERE action='更新失败' AND resource='负载规则' AND detail LIKE '%并发修改%'`).Scan(&auditCount); err != nil {
		t.Fatalf("read concurrency audit: %v", err)
	}
	if auditCount == 0 {
		t.Fatal("并发修改中止必须落「更新失败」审计")
	}
}

// 并发修改复核：指纹复核的直接契约——未变不中止，变更即 409。
func TestAbortIfRuleConcurrentlyModified_detectsChange(t *testing.T) {
	initializeRuleFeatureTestDB(t)
	gin.SetMode(gin.TestMode)
	seedTCPRuleForZeroMerge(t, "lb_fp", 17051)
	baseline, err := ruleMutationFingerprint("lb_fp")
	if err != nil {
		t.Fatalf("fingerprint: %v", err)
	}
	recorder := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(recorder)
	c.Request = httptest.NewRequest(http.MethodGet, "/", nil)
	if abortIfRuleConcurrentlyModified(c, "lb_fp", baseline) {
		t.Fatal("unchanged rule must not abort")
	}
	if _, err := db.DB.Exec("UPDATE lb_rules SET name='changed' WHERE caddy_id='lb_fp'"); err != nil {
		t.Fatalf("mutate rule: %v", err)
	}
	if !abortIfRuleConcurrentlyModified(c, "lb_fp", baseline) {
		t.Fatal("changed rule must abort")
	}
	if recorder.Code != http.StatusConflict {
		t.Fatalf("status=%d, want 409", recorder.Code)
	}
}

// 规则文本长度上限：name/description 长度门（DDL 声明值 100/300 rune）。
func TestCreateRule_rejectsOverlongNameAndDescription(t *testing.T) {
	handler := newRuleFeatureTestHandlers(t)
	gin.SetMode(gin.TestMode)
	router := gin.New()
	router.POST("/rules", handler.CreateRule)

	cases := []struct {
		name    string
		body    string
		wantMsg string
	}{
		{
			name:    "name over 100 runes",
			body:    fmt.Sprintf(`{"name":%q,"protocol":"http","domain":"long.example.test","listen_port":17061,"upstreams":[{"host":"127.0.0.1","port":9000,"enabled":true}]}`, strings.Repeat("名", 101)),
			wantMsg: "规则名称过长",
		},
		{
			name:    "description over 300 runes",
			body:    fmt.Sprintf(`{"name":"desc-long","description":%q,"protocol":"http","domain":"long2.example.test","listen_port":17062,"upstreams":[{"host":"127.0.0.1","port":9000,"enabled":true}]}`, strings.Repeat("述", 301)),
			wantMsg: "规则描述过长",
		},
	}
	for _, tc := range cases {
		request := httptest.NewRequest(http.MethodPost, "/rules", strings.NewReader(tc.body))
		request.Header.Set("Content-Type", "application/json")
		response := httptest.NewRecorder()
		router.ServeHTTP(response, request)
		if response.Code != http.StatusBadRequest || !strings.Contains(response.Body.String(), tc.wantMsg) {
			t.Fatalf("%s: status=%d body=%s, want 400 %s", tc.name, response.Code, response.Body.String(), tc.wantMsg)
		}
	}
}

func TestUpdateRule_rejectsOverlongName(t *testing.T) {
	handler, _, _ := newAuditRuleHandlers(t, 0)
	seedAuditRule(t, "lb_longname", "longname", "longname.example.test", 18003, true, "manual", false)
	seedAuditUpstream(t, "lb_longname")
	router := gin.New()
	router.PUT("/rules/:caddy_id", handler.UpdateRule)
	request := httptest.NewRequest(http.MethodPut, "/rules/lb_longname",
		strings.NewReader(fmt.Sprintf(`{"name":%q}`, strings.Repeat("名", 101))))
	request.Header.Set("Content-Type", "application/json")
	response := httptest.NewRecorder()

	router.ServeHTTP(response, request)

	if response.Code != http.StatusBadRequest || !strings.Contains(response.Body.String(), "规则名称过长") {
		t.Fatalf("update overlong name status=%d body=%s, want 400 规则名称过长", response.Code, response.Body.String())
	}
}

// 规则文本长度上限：副本名累积后缀截断到上限内（源名 100 rune → 基名截断保后缀）。
func TestDuplicateRule_truncatesCopyNameWithinLimit(t *testing.T) {
	handler := newRuleFeatureTestHandlers(t)
	gin.SetMode(gin.TestMode)
	sourceName := strings.Repeat("名", maxRuleNameRunes)
	seedTCPRuleForZeroMerge(t, "lb_dup_long", 17071)
	if _, err := db.DB.Exec("UPDATE lb_rules SET name=? WHERE caddy_id='lb_dup_long'", sourceName); err != nil {
		t.Fatalf("rename source: %v", err)
	}
	router := gin.New()
	router.POST("/rules/:caddy_id/duplicate", handler.DuplicateRule)
	response := httptest.NewRecorder()
	router.ServeHTTP(response, httptest.NewRequest(http.MethodPost, "/rules/lb_dup_long/duplicate", nil))

	if response.Code != http.StatusCreated {
		t.Fatalf("duplicate status=%d body=%s, want 201", response.Code, response.Body.String())
	}
	var copyName string
	if err := db.DB.QueryRow(`SELECT name FROM lb_rules WHERE caddy_id != 'lb_dup_long' ORDER BY rowid DESC LIMIT 1`).Scan(&copyName); err != nil {
		t.Fatalf("read copy name: %v", err)
	}
	if n := utf8.RuneCountInString(copyName); n > maxRuleNameRunes {
		t.Fatalf("copy name runes=%d, want <= %d", n, maxRuleNameRunes)
	}
	if !strings.HasSuffix(copyName, "（副本）") {
		t.Fatalf("copy name=%q must keep 副本 suffix", copyName)
	}
}

// 规则文本长度上限：复制路径同样拒绝超长描述（点名源规则）。
func TestDuplicateRule_rejectsOverlongDescription(t *testing.T) {
	handler := newRuleFeatureTestHandlers(t)
	gin.SetMode(gin.TestMode)
	seedTCPRuleForZeroMerge(t, "lb_dup_desc", 17072)
	if _, err := db.DB.Exec("UPDATE lb_rules SET description=? WHERE caddy_id='lb_dup_desc'", strings.Repeat("述", maxRuleDescriptionRunes+1)); err != nil {
		t.Fatalf("seed long description: %v", err)
	}
	router := gin.New()
	router.POST("/rules/:caddy_id/duplicate", handler.DuplicateRule)
	response := httptest.NewRecorder()
	router.ServeHTTP(response, httptest.NewRequest(http.MethodPost, "/rules/lb_dup_desc/duplicate", nil))

	if response.Code != http.StatusBadRequest || !strings.Contains(response.Body.String(), "规则描述过长") {
		t.Fatalf("duplicate overlong description status=%d body=%s, want 400 规则描述过长", response.Code, response.Body.String())
	}
}

// 提交后失败审计 行为钉：CreateRule 提交后入队失败（CA 队列未初始化）→ 500 + 「创建失败」审计。
func TestCreateRule_auditsEnqueueFailureWhenQueueInactive(t *testing.T) {
	handler, _, _ := newAuditRuleHandlers(t, 0)
	acmeConfigID := seedTestDNSProviderConfig(t)
	services.ResetCAQueueManagerForTest()
	t.Cleanup(services.ResetCAQueueManagerForTest)
	router := gin.New()
	router.POST("/rules", handler.CreateRule)
	body := fmt.Sprintf(`{"name":"acme-create","protocol":"http","domain":"acme-create.example.test","listen_port":18004,
		"enable_tls":true,"tls_source":"acme_dns","acme_config_id":%d,
		"health_check_interval":10,"health_check_timeout":2,"health_check_unhealthy_threshold":3,"health_check_healthy_threshold":2,
		"upstreams":[{"host":"127.0.0.1","port":9000,"enabled":true}]}`, acmeConfigID)
	request := httptest.NewRequest(http.MethodPost, "/rules", strings.NewReader(body))
	request.Header.Set("Content-Type", "application/json")
	response := httptest.NewRecorder()

	router.ServeHTTP(response, request)

	if response.Code != http.StatusInternalServerError || !strings.Contains(response.Body.String(), "CA 队列未初始化") {
		t.Fatalf("create status=%d body=%s, want 500 CA 队列未初始化", response.Code, response.Body.String())
	}
	var auditCount int
	if err := db.AuditDB.QueryRow(`SELECT COUNT(*) FROM audit_log WHERE action='创建失败' AND resource='负载规则' AND detail LIKE '%队列%'`).Scan(&auditCount); err != nil {
		t.Fatalf("read create failure audit: %v", err)
	}
	if auditCount == 0 {
		t.Fatal("创建入队失败必须落「创建失败」审计")
	}
}

// 提交后失败审计 行为钉：UpdateRule 提交后入队失败 → 500 + 「更新失败」审计。
func TestUpdateRule_auditsEnqueueFailureWhenQueueInactive(t *testing.T) {
	handler, _, _ := newAuditRuleHandlers(t, 0)
	acmeConfigID := seedTestDNSProviderConfig(t)
	seedAuditRule(t, "lb_acme_upd", "acmeupd", "acmeupd.example.test", 18005, true, "manual", true)
	seedAuditUpstream(t, "lb_acme_upd")
	services.ResetCAQueueManagerForTest()
	t.Cleanup(services.ResetCAQueueManagerForTest)
	router := gin.New()
	router.PUT("/rules/:caddy_id", handler.UpdateRule)
	request := httptest.NewRequest(http.MethodPut, "/rules/lb_acme_upd",
		strings.NewReader(fmt.Sprintf(`{"tls_source":"acme_dns","acme_config_id":%d}`, acmeConfigID)))
	request.Header.Set("Content-Type", "application/json")
	response := httptest.NewRecorder()

	router.ServeHTTP(response, request)

	if response.Code != http.StatusInternalServerError || !strings.Contains(response.Body.String(), "CA 队列未初始化") {
		t.Fatalf("update status=%d body=%s, want 500 CA 队列未初始化", response.Code, response.Body.String())
	}
	var auditCount int
	if err := db.AuditDB.QueryRow(`SELECT COUNT(*) FROM audit_log WHERE action='更新失败' AND resource='负载规则' AND detail LIKE '%队列%'`).Scan(&auditCount); err != nil {
		t.Fatalf("read update failure audit: %v", err)
	}
	if auditCount == 0 {
		t.Fatal("更新入队失败必须落「更新失败」审计")
	}
}

// 提交后失败审计 结构钉：五端点提交后失败分支的审计留痕数量下限（提交失败/入队
// 失败路径无法在 handler 层注入 DB commit 故障，按源码分支计数）
func TestRuleFailurePathAudits_pinAllPostCommitBranches(t *testing.T) {
	src, err := os.ReadFile("rules.go")
	if err != nil {
		t.Fatalf("read rules.go: %v", err)
	}
	body := string(src)
	cases := []struct {
		fn     string
		action string
		min    int
	}{
		{"func (h *Handlers) CreateRule(", "创建失败", 3},  // commit + qm nil + enqueue err
		{"func (h *Handlers) UpdateRule(", "更新失败", 3},  // commit + qm nil + enqueue err（并发修改另有 1 处）
		{"func (h *Handlers) DeleteRule(", "删除失败", 2},  // cancel timeout + commit
		{"func (h *Handlers) DisableRule(", "禁用失败", 1}, // commit
	}
	for _, tc := range cases {
		window := handlerFuncBody(body, tc.fn)
		if got := strings.Count(window, `recordAudit(c, "`+tc.action+`"`); got < tc.min {
			t.Fatalf("%s 失败审计 %s 次数=%d, want >= %d", tc.fn, tc.action, got, tc.min)
		}
	}
}

// handlerFuncBody 截取 handler 函数体（到下一个顶格 func）。
func handlerFuncBody(body, anchor string) string {
	start := strings.Index(body, anchor)
	if start < 0 {
		return ""
	}
	rest := body[start+len(anchor):]
	if end := strings.Index(rest, "\nfunc "); end >= 0 {
		rest = rest[:end]
	}
	return rest
}

// 列表投影派生断言：列表投影派生必须命中——列表列不含 tls_cert/tls_key 字样，且
// 实际列表查询不返回证书正文（派生失效时 strings.Replace 静默返回原文）。
func TestListRules_omitsTLSMaterialAndDerivationHits(t *testing.T) {
	if strings.Contains(lbRuleListColumns, "tls_cert") || strings.Contains(lbRuleListColumns, "tls_key") {
		t.Fatalf("lbRuleListColumns 仍含证书列字样——派生未命中: %q", lbRuleListColumns)
	}
	if !strings.Contains(lbRuleColumns, "COALESCE(tls_cert,''), COALESCE(tls_key,'')") {
		t.Fatal("lbRuleColumns 证书列字样缺失（派生锚点被改名）")
	}

	handler := newRuleFeatureTestHandlers(t)
	gin.SetMode(gin.TestMode)
	seedTCPRuleForZeroMerge(t, "lb_list_tls", 17081)
	// 直改 DB 写入证书正文（保存链会归一，故绕过链路模拟遗留行）。
	if _, err := db.DB.Exec(`UPDATE lb_rules SET tls_cert='CERT-BODY-MARKER', tls_key='KEY-BODY-MARKER' WHERE caddy_id='lb_list_tls'`); err != nil {
		t.Fatalf("seed tls material: %v", err)
	}
	router := gin.New()
	router.GET("/rules", handler.ListRules)
	response := httptest.NewRecorder()
	router.ServeHTTP(response, httptest.NewRequest(http.MethodGet, "/rules", nil))
	if response.Code != http.StatusOK {
		t.Fatalf("list status=%d body=%s, want 200", response.Code, response.Body.String())
	}
	if strings.Contains(response.Body.String(), "CERT-BODY-MARKER") || strings.Contains(response.Body.String(), "KEY-BODY-MARKER") {
		t.Fatalf("列表响应泄露证书/私钥正文: %s", response.Body.String())
	}
	if !strings.Contains(response.Body.String(), "lb_list_tls") {
		t.Fatal("列表响应缺少规则行（列序对齐被破坏）")
	}
}

// 治理默认值单源：治理默认值列绑定 db.Default* 常量（源码不得回流写死字面量）。
func TestLbRuleColumns_governedDefaultsBindConstants(t *testing.T) {
	src, err := os.ReadFile("rule_features.go")
	if err != nil {
		t.Fatalf("read rule_features.go: %v", err)
	}
	for _, literal := range []string{
		"COALESCE(health_check_interval,10)",
		"COALESCE(health_check_timeout,2)",
		"COALESCE(health_check_unhealthy_threshold,3)",
		"COALESCE(health_check_healthy_threshold,2)",
		"COALESCE(tcp_try_interval,250)",
	} {
		if strings.Contains(string(src), literal) {
			t.Fatalf("rule_features.go 仍含写死治理默认值 %q（应绑定 db.Default* 常量）", literal)
		}
	}
	bindings := []struct {
		fragment string
		value    int
	}{
		{"COALESCE(health_check_interval,%d)", db.DefaultHealthCheckInterval},
		{"COALESCE(health_check_timeout,%d)", db.DefaultHealthCheckTimeout},
		{"COALESCE(health_check_unhealthy_threshold,%d)", db.DefaultHealthCheckUnhealthyThreshold},
		{"COALESCE(health_check_healthy_threshold,%d)", db.DefaultHealthCheckHealthyThreshold},
		{"COALESCE(tcp_try_interval,%d)", db.DefaultTCPTryInterval},
	}
	for _, binding := range bindings {
		want := fmt.Sprintf(binding.fragment, binding.value)
		if !strings.Contains(lbRuleColumns, want) {
			t.Fatalf("lbRuleColumns 缺少常量绑定后的列 %q", want)
		}
	}
}
