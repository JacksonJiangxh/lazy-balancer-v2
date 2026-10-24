package handlers

// 主动健康检查未启用时，health_check_path 渲染零消费——它不得参与形状校验
// （否则存量死组合的任何无关编辑恒 400，且新建/更新的校验与清零顺序会给出
// 不同结果）；清零判据是「合并后的生效态」而非「是否显式提交开关」：显式提交
// 开关时连存量派生字段一起清零（与 Create 终态一致），只提交派生字段时只清被
// 提交项，三者全缺席的无关编辑保持存量；显式启用时保留用户值。Create / Update
// / Duplicate 三入口同判据（API 与 MCP update_rule 同路径）。

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/gin-gonic/gin"

	"lazy-balancer-v2/internal/db"
	"lazy-balancer-v2/internal/mcpserver"
)

func TestCreateRule_healthPathValidatedOnlyWhenActive(t *testing.T) {
	handler := newRuleFeatureTestHandlers(t)
	gin.SetMode(gin.TestMode)
	router := gin.New()
	router.POST("/rules", handler.CreateRule)

	deadBody := `{"name":"dead-path","protocol":"http","domain":"deadpath.test","listen_port":18710,` +
		`"enable_active_health_check":false,"health_check_path":"health",` +
		`"health_check_interval":10,"health_check_timeout":2,"health_check_unhealthy_threshold":3,"health_check_healthy_threshold":2,` +
		`"upstreams":[{"host":"127.0.0.1","port":9000,"enabled":true}]}`
	deadResp := httptest.NewRecorder()
	createReq := httptest.NewRequest(http.MethodPost, "/rules", strings.NewReader(deadBody))
	createReq.Header.Set("Content-Type", "application/json")
	router.ServeHTTP(deadResp, createReq)
	if deadResp.Code != http.StatusCreated {
		t.Fatalf("未启用主动检查的非法路径 status=%d body=%s, want 201（死字段不校验）", deadResp.Code, deadResp.Body.String())
	}
	var deadPath string
	if err := db.DB.QueryRow(`SELECT COALESCE(health_check_path,'') FROM lb_rules WHERE domain LIKE '%deadpath.test%' ORDER BY rowid DESC LIMIT 1`).Scan(&deadPath); err != nil {
		t.Fatalf("read created rule: %v", err)
	}
	if deadPath != "" {
		t.Fatalf("新建归一刻零后 health_check_path=%q, want 空", deadPath)
	}

	activeBody := `{"name":"active-path","protocol":"http","domain":"activepath.test","listen_port":18711,` +
		`"enable_active_health_check":true,"health_check_path":"health",` +
		`"health_check_interval":10,"health_check_timeout":2,"health_check_unhealthy_threshold":3,"health_check_healthy_threshold":2,` +
		`"upstreams":[{"host":"127.0.0.1","port":9000,"enabled":true}]}`
	activeResp := httptest.NewRecorder()
	activeReq := httptest.NewRequest(http.MethodPost, "/rules", strings.NewReader(activeBody))
	activeReq.Header.Set("Content-Type", "application/json")
	router.ServeHTTP(activeResp, activeReq)
	if activeResp.Code != http.StatusBadRequest || !strings.Contains(activeResp.Body.String(), "健康检查路径必须以 / 开头") {
		t.Fatalf("启用主动检查的非法路径 status=%d body=%s, want 400", activeResp.Code, activeResp.Body.String())
	}
}

func TestValidateV2BackupRules_deadHealthPathIsNotRejected(t *testing.T) {
	tables := ruleTablesShared()
	tables["lb_rules"][0]["enable_active_health_check"] = 0
	tables["lb_rules"][0]["health_check_path"] = "health"
	// 未启用主动检查 = 渲染零消费：存量死组合不得让整包导入被 400。
	if err := validateV2BackupRules(tables); err != nil {
		t.Fatalf("未启用主动检查的 health_check_path 不应参与校验: %v", err)
	}
}

func TestRuleUpdate_healthPathEnabledPreservedDisabledCleared(t *testing.T) {
	handler := newRuleFeatureTestHandlers(t)
	gin.SetMode(gin.TestMode)
	router := gin.New()
	router.PUT("/rules/:caddy_id", handler.UpdateRule)

	const caddyID = "lb_hcheck"
	if _, err := db.DB.Exec(`INSERT INTO lb_rules (caddy_id,name,description,protocol,domain,listen_port,strategy,enabled,enable_active_health_check,health_check_path)
		VALUES (?, 'hcheck', '', 'http', 'hcheck.test', 18712, 'weighted_round_robin', 1, 0, '')`, caddyID); err != nil {
		t.Fatalf("seed rule: %v", err)
	}
	if _, err := db.DB.Exec(`INSERT INTO upstreams (rule_id,host,port,weight,enabled,protocol) VALUES (?, '127.0.0.1', 9000, 1, 1, 'http')`, caddyID); err != nil {
		t.Fatalf("seed upstream: %v", err)
	}

	// 显式启用 + 用户填写的路径：必须落库（此前极性反了会清空）。
	enableResp := putRule(t, router, caddyID, `{"enable_active_health_check":true,"health_check_path":"/healthz"}`)
	if enableResp.Code != http.StatusOK {
		t.Fatalf("启用主动检查 status=%d body=%s, want 200", enableResp.Code, enableResp.Body.String())
	}
	var enabled int
	var path string
	if err := db.DB.QueryRow(`SELECT enable_active_health_check, COALESCE(health_check_path,'') FROM lb_rules WHERE caddy_id = ?`, caddyID).Scan(&enabled, &path); err != nil {
		t.Fatalf("read rule: %v", err)
	}
	if enabled != 1 || path != "/healthz" {
		t.Fatalf("启用后 enabled=%d path=%q, want 1 /healthz（用户填写不得被清零）", enabled, path)
	}

	// 显式关闭：派生字段同请求清零（此前极性反了会保留死配置）。
	disableResp := putRule(t, router, caddyID, `{"enable_active_health_check":false}`)
	if disableResp.Code != http.StatusOK {
		t.Fatalf("关闭主动检查 status=%d body=%s, want 200", disableResp.Code, disableResp.Body.String())
	}
	if err := db.DB.QueryRow(`SELECT enable_active_health_check, COALESCE(health_check_path,'') FROM lb_rules WHERE caddy_id = ?`, caddyID).Scan(&enabled, &path); err != nil {
		t.Fatalf("read rule: %v", err)
	}
	if enabled != 0 || path != "" {
		t.Fatalf("关闭后 enabled=%d path=%q, want 0 空", enabled, path)
	}

	// 存量死组合 + 缺席字段的无关编辑：沿用存量（不被形状门 400，也不静默改写）。
	if _, err := db.DB.Exec(`UPDATE lb_rules SET enable_active_health_check=0, health_check_path='health' WHERE caddy_id = ?`, caddyID); err != nil {
		t.Fatalf("seed dead combo: %v", err)
	}
	renameResp := putRule(t, router, caddyID, `{"name":"renamed-hcheck"}`)
	if renameResp.Code != http.StatusOK {
		t.Fatalf("存量死组合的无关编辑 status=%d body=%s, want 200", renameResp.Code, renameResp.Body.String())
	}
}

// seedInactiveHealthCheckRule 播种一条主动健康检查未启用的 HTTP 规则 + 一个上游。
func seedInactiveHealthCheckRule(t *testing.T, caddyID, domain string, listenPort int) {
	t.Helper()
	if _, err := db.DB.Exec(`INSERT INTO lb_rules (caddy_id,name,description,protocol,domain,listen_port,strategy,enabled,enable_active_health_check,health_check_path,health_check_host,tcp_health_check_port)
		VALUES (?, ?, '', 'http', ?, ?, 'weighted_round_robin', 1, 0, '', '', 0)`, caddyID, caddyID, domain, listenPort); err != nil {
		t.Fatalf("seed rule %s: %v", caddyID, err)
	}
	if _, err := db.DB.Exec(`INSERT INTO upstreams (rule_id,host,port,weight,enabled,protocol) VALUES (?, '127.0.0.1', 9000, 1, 1, 'http')`, caddyID); err != nil {
		t.Fatalf("seed upstream %s: %v", caddyID, err)
	}
}

// readHealthCheckColumns 读回三列（COALESCE 归一空值）。
func readHealthCheckColumns(t *testing.T, caddyID string) (string, string, int) {
	t.Helper()
	var path, host string
	var port int
	if err := db.DB.QueryRow(`SELECT COALESCE(health_check_path,''), COALESCE(health_check_host,''), COALESCE(tcp_health_check_port,0) FROM lb_rules WHERE caddy_id = ?`, caddyID).Scan(&path, &host, &port); err != nil {
		t.Fatalf("read health check columns (%s): %v", caddyID, err)
	}
	return path, host, port
}

// 清零判据是「合并后的生效态」而非「本次请求是否显式提交开关」：
// 存量 switch=0 时只交派生字段（不带开关）也必须清零——与 Create 同口径，
// 同一载荷新建/编辑得到同一终态（此前只在显式关闭开关时清零，API 只交
// health_check_path 会把死配置原样落库）。
func TestUpdateRule_submittedHealthCheckFieldsClearedWhenEffectiveInactive(t *testing.T) {
	handler := newRuleFeatureTestHandlers(t)
	gin.SetMode(gin.TestMode)
	router := gin.New()
	router.PUT("/rules/:caddy_id", handler.UpdateRule)

	const caddyID = "lb_hcheck_api"
	seedInactiveHealthCheckRule(t, caddyID, "hcheck-api.test", 18713)

	// When：只交 HTTP 派生字段，不带 enable_active_health_check（存量生效态=false）
	resp := putRule(t, router, caddyID, `{"health_check_path":"health","health_check_host":"probe.example.test"}`)

	// Then：两列清零（与 Create 同口径）
	if resp.Code != http.StatusOK {
		t.Fatalf("只交派生字段 status=%d body=%s, want 200", resp.Code, resp.Body.String())
	}
	path, host, _ := readHealthCheckColumns(t, caddyID)
	if path != "" || host != "" {
		t.Fatalf("生效态关闭时派生字段必须清零: path=%q host=%q", path, host)
	}
	// 审计必须披露被清字段（用户可从操作审计回答「为什么我填的路径没落库」）
	var detail string
	if err := db.AuditDB.QueryRow(`SELECT detail FROM audit_log WHERE action='更新' AND resource='负载规则' ORDER BY id DESC LIMIT 1`).Scan(&detail); err != nil {
		t.Fatalf("read update audit: %v", err)
	}
	if !strings.Contains(detail, "已清空未启用主动健康检查的死配置") {
		t.Fatalf("更新审计未披露清零: %q", detail)
	}

	// TCP 形态：tcp_health_check_port 只在主动健康检查启用时被 TCP 渲染消费，
	// 生效态关闭时同样按提交即清零（HTTP 行的该列由协议归一恒零，不作判据）。
	const tcpID = "lb_hcheck_api_tcp"
	seedTCPRuleForZeroMerge(t, tcpID, 18716)
	tcpResp := putRule(t, router, tcpID, `{"tcp_health_check_port":8443}`)
	if tcpResp.Code != http.StatusOK {
		t.Fatalf("TCP 只交健康检查端口 status=%d body=%s, want 200", tcpResp.Code, tcpResp.Body.String())
	}
	if _, _, port := readHealthCheckColumns(t, tcpID); port != 0 {
		t.Fatalf("生效态关闭时 tcp_health_check_port=%d, want 0（与 Create 同口径）", port)
	}
}

// 非显式提交不误清存量：存量生效态关闭但本次请求未提交派生字段（缺省=沿用）
// 时，存量列必须原样保留——部分更新契约不得借清零把缺席字段当「显式清空」。
func TestUpdateRule_absentHealthCheckFieldsPreserveStoredValues(t *testing.T) {
	handler := newRuleFeatureTestHandlers(t)
	gin.SetMode(gin.TestMode)
	router := gin.New()
	router.PUT("/rules/:caddy_id", handler.UpdateRule)

	const caddyID = "lb_hcheck_absent"
	seedInactiveHealthCheckRule(t, caddyID, "hcheck-absent.test", 18714)
	if _, err := db.DB.Exec(`UPDATE lb_rules SET health_check_path='health', health_check_host='probe.example.test' WHERE caddy_id = ?`, caddyID); err != nil {
		t.Fatalf("seed dead combo: %v", err)
	}

	// When：只改名（HTTP 派生字段全部缺席）
	putRule(t, router, caddyID, `{"name":"renamed-absent"}`)

	// Then：存量值原样保留
	path, host, _ := readHealthCheckColumns(t, caddyID)
	if path != "health" || host != "probe.example.test" {
		t.Fatalf("缺席字段不得被静默清零: path=%q host=%q", path, host)
	}

	// TCP 形态同口径：未提交 tcp_health_check_port 时沿用存量 9001。
	const tcpID = "lb_hcheck_absent_tcp"
	seedTCPRuleForZeroMerge(t, tcpID, 18717)
	putRule(t, router, tcpID, `{"name":"renamed-absent-tcp"}`)
	if _, _, port := readHealthCheckColumns(t, tcpID); port != 9001 {
		t.Fatalf("缺席 tcp_health_check_port 不得被静默清零: port=%d, want 9001", port)
	}
}

// callRuleMCPTool 走 MCP streamable 端点调用工具（与生产 MCP 客户端同形态）。
func callRuleMCPTool(t *testing.T, handler http.Handler, name, arguments string) string {
	t.Helper()
	body := `{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"` + name + `","arguments":` + arguments + `}}`
	request := httptest.NewRequest(http.MethodPost, "/api/v1/mcp", strings.NewReader(body))
	request.Header.Set("Content-Type", "application/json")
	request.Header.Set("Accept", "application/json, text/event-stream")
	request.Header.Set("X-API-Key", "lb_sk_mcp-health-check")
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, request)
	return response.Body.String()
}

// MCP 形态（update_rule 工具）与 REST 同路径同终态：工具层不注入
// enable_active_health_check，只交派生字段时由 API 侧按合并后生效态归一清零。
func TestUpdateRule_viaMCPToolClearsDeadHealthCheck(t *testing.T) {
	handler := newRuleFeatureTestHandlers(t)
	gin.SetMode(gin.TestMode)
	router := gin.New()
	router.PUT("/api/v1/rules/:caddy_id", handler.UpdateRule)
	api := httptest.NewServer(router)
	t.Cleanup(api.Close)

	const caddyID = "lb_hcheck_mcp"
	seedInactiveHealthCheckRule(t, caddyID, "hcheck-mcp.test", 18715)

	// When：MCP update_rule 只交 health_check_path（不带开关）
	response := callRuleMCPTool(t, mcpserver.NewForTest(api.URL+"/api/v1", api.Client()), "update_rule",
		`{"caddy_id":"`+caddyID+`","health_check_path":"health"}`)

	// Then：工具调用成功且死配置清零
	if !strings.Contains(response, "规则已更新") {
		t.Fatalf("MCP update_rule 响应=%s, want 规则已更新", response)
	}
	path, _, _ := readHealthCheckColumns(t, caddyID)
	if path != "" {
		t.Fatalf("MCP 形态 health_check_path=%q, want 空（与 REST 同口径清零）", path)
	}
}

// 复制入口同族收敛：源行「生效态关闭 + 派生死配置」不得随副本放大
// （复制即新建，与 Create/Update 同一归一终态）。
func TestDuplicateRule_clearsDeadHealthCheck(t *testing.T) {
	handler := newRuleFeatureTestHandlers(t)
	gin.SetMode(gin.TestMode)
	router := gin.New()
	router.POST("/rules/:caddy_id/duplicate", handler.DuplicateRule)

	const srcID = "lb_hcheck_dup"
	seedInactiveHealthCheckRule(t, srcID, "hcheck-dup.test", 18718)
	if _, err := db.DB.Exec(`UPDATE lb_rules SET health_check_path='health', health_check_host='probe.example.test' WHERE caddy_id = ?`, srcID); err != nil {
		t.Fatalf("seed dead combo: %v", err)
	}

	// When：复制源规则
	response := httptest.NewRecorder()
	router.ServeHTTP(response, httptest.NewRequest(http.MethodPost, "/rules/"+srcID+"/duplicate", nil))

	// Then：副本的三专属列已清零（源行保留原样，等后续显式编辑/开关清零）
	if response.Code != http.StatusCreated {
		t.Fatalf("duplicate status=%d body=%s, want 201", response.Code, response.Body.String())
	}
	var copyID string
	if err := db.DB.QueryRow(`SELECT caddy_id FROM lb_rules WHERE caddy_id <> ? AND name = ? ORDER BY rowid DESC LIMIT 1`, srcID, srcID+"（副本）").Scan(&copyID); err != nil {
		t.Fatalf("read duplicated rule: %v", err)
	}
	path, host, _ := readHealthCheckColumns(t, copyID)
	if path != "" || host != "" {
		t.Fatalf("副本不应携带死配置: path=%q host=%q", path, host)
	}
}
