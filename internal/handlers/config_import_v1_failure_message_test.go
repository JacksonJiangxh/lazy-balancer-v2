package handlers

// v1 导入失败面与 v2 同口径：审计 action 已带「导入失败/部分失败」，detail 与
// 响应 message 都走 importFailureAuditDetail 单源（不重复动作前缀），并且必须
// 带阶段说明（事务回滚后=「数据库未变更」）。回滚路径不得报 imported:N——
// 事务内的插入计数在回滚后全部作废。

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/gin-gonic/gin"

	"lazy-balancer-v2/internal/db"
	"lazy-balancer-v2/internal/services"
)

// v1ImportFailureBackup 是单规则 v1 备份（合法形状，足以进入事务与 commit）。
func v1ImportFailureBackup(name string) string {
	return fmt.Sprintf(`{
		"proxy_config":{"config":[
			{"pk":1,"fields":{"proxy_name":%q,"protocol":true,"listen":8566,"server_name":"%s.example.test","status":true,"ssl":false,"http_check":false,"fail_timeout":30,"upstream_list":[1]}}
		]},
		"upstream_config":{"config":[
			{"pk":1,"fields":{"status":true,"address":"127.0.0.1","port":9566,"weight":100}}
		]}
	}`, name, name)
}

func TestImportV1Config_failureMessageCarriesActionOnce(t *testing.T) {
	h := newBackupTestHandlers(t)
	// Caddy admin 指向未监听端口：commit 的运行配置快照阶段必失败（事务回滚）。
	h.cfg.CaddyAdminURL = deadCaddyURL
	h.caddyService = services.NewCaddyService(deadCaddyURL)

	// 既有规则：回滚后必须原样保留（证明没有部分落地）。
	if _, err := db.DB.Exec(`
		INSERT INTO lb_rules (caddy_id,name,domain,protocol,listen_port,enabled) VALUES
		('lb_v1_keep','keep-before-import','keep.example.test','http',8560,1)`); err != nil {
		t.Fatalf("seed existing rule: %v", err)
	}

	gin.SetMode(gin.TestMode)
	router := gin.New()
	router.POST("/config/import/v1", h.ImportV1Config)
	recorder := httptest.NewRecorder()
	request := httptest.NewRequest(http.MethodPost, "/config/import/v1", strings.NewReader(v1ImportFailureBackup("v1-failure")))
	request.Header.Set("Content-Type", "application/json")
	router.ServeHTTP(recorder, request)

	if recorder.Code != http.StatusInternalServerError {
		t.Fatalf("status=%d body=%s, want 500", recorder.Code, recorder.Body.String())
	}
	var response struct {
		Message string         `json:"message"`
		Data    map[string]any `json:"data"`
	}
	if err := json.Unmarshal(recorder.Body.Bytes(), &response); err != nil {
		t.Fatalf("decode response: %v body=%s", err, recorder.Body.String())
	}
	// 动作词只出现一次（旧实现 detail 自带「导入失败：」→ 双前缀）。
	if count := strings.Count(response.Message, "导入失败"); count != 1 {
		t.Fatalf("message=%q，动作词出现 %d 次, want 1（禁止双前缀）", response.Message, count)
	}
	if !strings.Contains(response.Message, "数据库未变更") {
		t.Fatalf("message=%q, want 阶段描述「数据库未变更」", response.Message)
	}
	// 事务已回滚：不得报 imported:N（旧实现把循环内计数原样返回）。
	if value, ok := response.Data["imported"]; ok {
		t.Fatalf("回滚后的响应仍携带 imported=%v，会误导为部分规则已落地", value)
	}

	var action, detail string
	if err := db.AuditDB.QueryRow(`SELECT action, detail FROM audit_log WHERE resource='配置备份' ORDER BY id DESC LIMIT 1`).Scan(&action, &detail); err != nil {
		t.Fatalf("read failure audit: %v", err)
	}
	if action != "导入失败" {
		t.Fatalf("audit action=%q, want 导入失败", action)
	}
	if strings.Contains(detail, "导入失败") {
		t.Fatalf("audit detail=%q 重复动作前缀", detail)
	}
	if !strings.Contains(detail, "数据库未变更") {
		t.Fatalf("audit detail=%q, want 阶段描述", detail)
	}

	// 回滚实证：既有规则仍在，导入规则未落库。
	var existing, imported int
	if err := db.DB.QueryRow(`SELECT
		(SELECT COUNT(*) FROM lb_rules WHERE caddy_id='lb_v1_keep'),
		(SELECT COUNT(*) FROM lb_rules WHERE name='v1-failure')`).Scan(&existing, &imported); err != nil {
		t.Fatalf("count rules: %v", err)
	}
	if existing != 1 || imported != 0 {
		t.Fatalf("回滚后规则 existing=%d imported=%d, want 1/0", existing, imported)
	}
}
