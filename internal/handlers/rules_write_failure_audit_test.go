package handlers

// 规则写端点的失败留痕与源码残留守卫：
//  1) Explicit 审计策略下中间件不补 5xx 失败留痕——数据库层失败（事务开启/
//     主表写入/确认影响行数）必须与 Caddy 层失败同口径落一条「失败」审计，
//     否则运维无法回答「谁在何时尝试写库失败」。
//  2) 规则/Caddy 端点源码不得重新出现审计过程残留（日志前缀「问题: 」、注释
//     里的「发现N」引用）——它们污染生产日志可读性并让审计过程泄进产品代码。

import (
	"net/http"
	"net/http/httptest"
	"os"
	"regexp"
	"strings"
	"testing"

	"github.com/gin-gonic/gin"

	"lazy-balancer-v2/internal/db"
)

func TestUpdateRule_auditsDatabaseWriteFailure(t *testing.T) {
	handler, _, _ := newAuditRuleHandlers(t, 0)
	seedAuditRule(t, "lb_dbfail", "dbfail", "dbfail.example.test", 18041, true, "manual", false)
	seedAuditUpstream(t, "lb_dbfail")
	if _, err := db.DB.Exec(`CREATE TRIGGER fail_rule_update BEFORE UPDATE ON lb_rules
		BEGIN SELECT RAISE(ABORT, 'write blocked by trigger'); END`); err != nil {
		t.Fatalf("install failing trigger: %v", err)
	}
	gin.SetMode(gin.TestMode)
	router := gin.New()
	router.Use(func(c *gin.Context) { c.Set("user_id", 42) })
	router.PUT("/rules/:caddy_id", handler.UpdateRule)

	before := auditCountFor(t, "更新失败", "负载规则")
	request := httptest.NewRequest(http.MethodPut, "/rules/lb_dbfail", strings.NewReader(`{"name":"renamed"}`))
	request.Header.Set("Content-Type", "application/json")
	response := httptest.NewRecorder()
	router.ServeHTTP(response, request)

	if response.Code != http.StatusInternalServerError {
		t.Fatalf("status=%d body=%s, want 500（事务内写入失败）", response.Code, response.Body.String())
	}
	if got := auditCountFor(t, "更新失败", "负载规则") - before; got != 1 {
		t.Fatalf("db-layer failure audit rows=%d, want 1", got)
	}
	var detail string
	if err := db.AuditDB.QueryRow(`SELECT COALESCE(detail,'') FROM audit_log
		WHERE action='更新失败' AND resource='负载规则' ORDER BY id DESC LIMIT 1`).Scan(&detail); err != nil {
		t.Fatalf("read audit detail: %v", err)
	}
	if !strings.Contains(detail, "写入数据库失败（更新规则）") || !strings.Contains(detail, "write blocked by trigger") {
		t.Fatalf("audit detail=%q, want 相位与底层错误（可追溯）", detail)
	}
}

func TestRuleEndpointSources_freeOfAuditResidue(t *testing.T) {
	residue := map[string]*regexp.Regexp{
		"产物日志前缀":   regexp.MustCompile(`"问题: `),
		"注释审计编号引用": regexp.MustCompile(`发现[ \t]*[0-9]`),
		"截断注释残骸":   regexp.MustCompile(`历史[ \t]*问题[ \t]*[:：]`),
	}
	for _, file := range []string{"rules.go", "caddy.go"} {
		src, err := os.ReadFile(file)
		if err != nil {
			t.Fatalf("read %s: %v", file, err)
		}
		text := string(src)
		for label, pattern := range residue {
			if match := pattern.FindString(text); match != "" {
				t.Fatalf("%s 含%s（%q）——审计过程残留不得进入产品源码", file, label, match)
			}
		}
	}
}
