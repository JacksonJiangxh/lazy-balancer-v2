package handlers

// PUT /rules/:id 的可选乐观并发前置条件：客户端回传打开表单时的
// updated_at，服务端在事务内（immediate 写锁）比对；不一致 409 且库零改动，
// 省略字段保持向后兼容。

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/gin-gonic/gin"

	"lazy-balancer-v2/internal/db"
)

func seedVersionedRule(t *testing.T, caddyID, updatedAt string) {
	t.Helper()
	if _, err := db.DB.Exec(`INSERT INTO lb_rules (caddy_id,name,description,protocol,domain,listen_port,strategy,enabled,updated_at)
		VALUES (?, 'orig-name', '', 'http', 'ver.test', 18700, 'weighted_round_robin', 1, ?)`, caddyID, updatedAt); err != nil {
		t.Fatalf("seed rule: %v", err)
	}
	if _, err := db.DB.Exec(`INSERT INTO upstreams (rule_id,host,port,weight,enabled,protocol) VALUES (?, '127.0.0.1', 9000, 1, 1, 'http')`, caddyID); err != nil {
		t.Fatalf("seed upstream: %v", err)
	}
}

func ruleName(t *testing.T, caddyID string) string {
	t.Helper()
	var name string
	if err := db.DB.QueryRow(`SELECT name FROM lb_rules WHERE caddy_id = ?`, caddyID).Scan(&name); err != nil {
		t.Fatalf("read rule name: %v", err)
	}
	return name
}

func putRuleRaw(t *testing.T, router *gin.Engine, caddyID, body string) *httptest.ResponseRecorder {
	t.Helper()
	request := httptest.NewRequest(http.MethodPut, "/rules/"+caddyID, strings.NewReader(body))
	request.Header.Set("Content-Type", "application/json")
	response := httptest.NewRecorder()
	router.ServeHTTP(response, request)
	return response
}

func TestUpdateRule_expectedUpdatedAtPrecondition(t *testing.T) {
	handler := newRuleFeatureTestHandlers(t)
	gin.SetMode(gin.TestMode)
	router := gin.New()
	router.PUT("/rules/:caddy_id", handler.UpdateRule)

	const caddyID = "lb_verpre"
	seedVersionedRule(t, caddyID, "2026-01-01 00:00:00")

	// 1) 版本匹配（RFC3339 形态）→ 200
	if resp := putRuleRaw(t, router, caddyID, `{"name":"renamed-ok","expected_updated_at":"2026-01-01T00:00:00Z"}`); resp.Code != http.StatusOK {
		t.Fatalf("匹配版本 status=%d body=%s, want 200", resp.Code, resp.Body.String())
	}
	if got := ruleName(t, caddyID); got != "renamed-ok" {
		t.Fatalf("name=%q, want renamed-ok", got)
	}

	// 2) 他人已提交（库内版本前进）→ 陈旧版本 409 且库不变
	if _, err := db.DB.Exec(`UPDATE lb_rules SET updated_at='2026-02-02 03:04:05' WHERE caddy_id = ?`, caddyID); err != nil {
		t.Fatalf("bump version: %v", err)
	}
	stale := putRuleRaw(t, router, caddyID, `{"name":"stale-write","expected_updated_at":"2026-01-01 00:00:00"}`)
	if stale.Code != http.StatusConflict {
		t.Fatalf("陈旧版本 status=%d body=%s, want 409", stale.Code, stale.Body.String())
	}
	if !strings.Contains(stale.Body.String(), "规则已被他人修改") {
		t.Fatalf("409 body=%s, want 冲突文案", stale.Body.String())
	}
	if got := ruleName(t, caddyID); got != "renamed-ok" {
		t.Fatalf("冲突请求不得落库, name=%q", got)
	}

	// 3) 平面 UTC 形态匹配（库值原样回传）→ 200
	if resp := putRuleRaw(t, router, caddyID, `{"name":"flat-ok","expected_updated_at":"2026-02-02 03:04:05"}`); resp.Code != http.StatusOK {
		t.Fatalf("平面 UTC 版本 status=%d body=%s, want 200", resp.Code, resp.Body.String())
	}

	// 4) 省略字段 → 不校验（API/MCP 向后兼容）
	if resp := putRuleRaw(t, router, caddyID, `{"name":"omitted-ok"}`); resp.Code != http.StatusOK {
		t.Fatalf("省略版本 status=%d body=%s, want 200", resp.Code, resp.Body.String())
	}

	// 5) 非法格式 → 400（不得静默忽略）
	if resp := putRuleRaw(t, router, caddyID, `{"name":"bad","expected_updated_at":"yesterday"}`); resp.Code != http.StatusBadRequest {
		t.Fatalf("非法版本 status=%d body=%s, want 400", resp.Code, resp.Body.String())
	}

	// 6) 库内 NULL → fail-closed 409（无法证明未被他人修改）
	if _, err := db.DB.Exec(`UPDATE lb_rules SET updated_at=NULL WHERE caddy_id = ?`, caddyID); err != nil {
		t.Fatalf("null version: %v", err)
	}
	if resp := putRuleRaw(t, router, caddyID, `{"name":"null-version","expected_updated_at":"2026-02-02 03:04:05"}`); resp.Code != http.StatusConflict {
		t.Fatalf("库内 NULL 版本 status=%d body=%s, want 409", resp.Code, resp.Body.String())
	}
}
