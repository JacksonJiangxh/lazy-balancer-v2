package handlers

// 主动健康检查未启用时，health_check_path 渲染零消费——它不得参与形状校验
// （否则存量死组合的任何无关编辑恒 400，且新建/更新的校验与清零顺序会给出
// 不同结果）；显式关闭 active 时必须清零派生字段，显式启用时必须保留用户值。

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/gin-gonic/gin"

	"lazy-balancer-v2/internal/db"
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
