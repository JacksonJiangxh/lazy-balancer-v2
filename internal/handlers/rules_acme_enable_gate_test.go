package handlers

import (
	"database/sql"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/gin-gonic/gin"

	"lazy-balancer-v2/internal/db"
)

// 启用路径必须与创建/更新/预校验同口径做 ACME 域名形状校验：v2 导入对禁用行
// 不做该校验（只校验启用行），非法域名集随导入落库后，经 /enable 启用若不在
// 这里拦下，入队阶段才以泛化 500 暴露（非用户可修正的 400）。
func TestEnableRule_invalidACMEDomainsIs400(t *testing.T) {
	handler := newRuleFeatureTestHandlers(t)
	seedAuditRule(t, "lb_acme_bad_domains", "bad-domains", "a.example.test,www.a.example.test,extra.example.test", 8443, false, "acme_dns", true)
	if _, err := db.DB.Exec(`INSERT INTO certificate_configs (id,name,dns_provider,dns_credentials,enabled) VALUES (1,'dns','dnspod','{"id":"1","token":"t"}',1)`); err != nil {
		t.Fatalf("seed certificate config: %v", err)
	}
	if _, err := db.DB.Exec(`UPDATE lb_rules SET acme_config_id=1 WHERE caddy_id='lb_acme_bad_domains'`); err != nil {
		t.Fatalf("bind acme config: %v", err)
	}
	router := gin.New()
	router.POST("/rules/:caddy_id/enable", handler.EnableRule)

	response := httptest.NewRecorder()
	router.ServeHTTP(response, httptest.NewRequest(http.MethodPost, "/rules/lb_acme_bad_domains/enable", nil))

	if response.Code != http.StatusBadRequest {
		t.Fatalf("enable status=%d body=%s, want 400（非法 ACME 域名是用户可修正的输入错误）", response.Code, response.Body.String())
	}
	if !strings.Contains(response.Body.String(), "ACME证书仅支持单域名或根域+www二级域名") {
		t.Fatalf("body=%s, want ACME 域名形状文案", response.Body.String())
	}
	var enabled bool
	if err := db.DB.QueryRow("SELECT enabled FROM lb_rules WHERE caddy_id='lb_acme_bad_domains'").Scan(&enabled); err != nil {
		t.Fatalf("read enabled state: %v", err)
	}
	if enabled {
		t.Fatal("校验失败的规则不得被启用")
	}
}

// seedACMEWithoutEnabledCAProvider 建一条「跟随默认 CA（0）+ 无任何启用提供商」
// 的 ACME 规则夹具（ACME 配置引用本身合法，唯一缺失面是没有启用的 CA 提供商），
// 该状态只能由导入还原/带外改库产生——正是写前 CA 门的可达面。
func seedACMEWithoutEnabledCAProvider(t *testing.T, caddyID, domain string, listenPort int, enabled bool) {
	t.Helper()
	seedAuditRule(t, caddyID, caddyID, domain, listenPort, enabled, "acme_dns", true)
	seedAuditUpstream(t, caddyID)
	res, err := db.DB.Exec(`INSERT INTO certificate_configs (name,dns_provider,dns_credentials,enabled)
		VALUES ('dns','dnspod','{"token":"x"}',1)`)
	if err != nil {
		t.Fatalf("seed certificate config: %v", err)
	}
	configID, err := res.LastInsertId()
	if err != nil {
		t.Fatalf("read certificate config ID: %v", err)
	}
	if _, err := db.DB.Exec("UPDATE lb_rules SET acme_config_id=?, ca_provider_id=0 WHERE caddy_id=?", configID, caddyID); err != nil {
		t.Fatalf("bind rule ACME/CA state: %v", err)
	}
	if _, err := db.DB.Exec("UPDATE ca_providers SET enabled=0"); err != nil {
		t.Fatalf("disable CA providers: %v", err)
	}
}

// 无可用 CA 提供商是用户可修复的配置状态：更新路径必须在事务/应用之前判 400
// 并给出指引，而不是先提交事务 + /load 再以 500 整体回滚——后者把前置条件
// 呈现为服务端故障，且一次真实的 Caddy 应用被白做。
func TestUpdateRule_noEnabledCAProviderIs400BeforeCommit(t *testing.T) {
	handler, _, _ := newAuditRuleHandlers(t, 0)
	seedACMEWithoutEnabledCAProvider(t, "lb_no_ca_upd", "no-ca-upd.example.test", 18431, true)
	router := gin.New()
	router.PUT("/rules/:caddy_id", handler.UpdateRule)
	request := httptest.NewRequest(http.MethodPut, "/rules/lb_no_ca_upd", strings.NewReader(`{"name":"renamed"}`))
	request.Header.Set("Content-Type", "application/json")
	response := httptest.NewRecorder()

	before := auditCountFor(t, "更新失败", "负载规则")
	router.ServeHTTP(response, request)

	if response.Code != http.StatusBadRequest {
		t.Fatalf("status=%d body=%s, want 400（无可用 CA 提供商是用户可修复状态，不得报 500）", response.Code, response.Body.String())
	}
	if !strings.Contains(response.Body.String(), "没有可用的 CA 提供商") {
		t.Fatalf("body=%s, want 与创建路径同款可操作指引", response.Body.String())
	}
	var name string
	if err := db.DB.QueryRow("SELECT name FROM lb_rules WHERE caddy_id='lb_no_ca_upd'").Scan(&name); err != nil {
		t.Fatalf("read rule name: %v", err)
	}
	if name != "lb_no_ca_upd" {
		t.Fatalf("name=%q, 写前拒绝不得提交更新", name)
	}
	if got := auditCountFor(t, "更新失败", "负载规则") - before; got != 0 {
		t.Fatalf("写前 400 落下 %d 条失败审计——4xx 载荷/配置状态错误不入审计", got)
	}
}

// 启用路径同口径：无可用 CA 提供商时 400，不得先提交启用 + /load 再 500 回滚。
func TestEnableRule_noEnabledCAProviderIs400BeforeCommit(t *testing.T) {
	handler, loadCalls, lastLoad := newAuditRuleHandlers(t, 0)
	seedACMEWithoutEnabledCAProvider(t, "lb_no_ca_enable", "no-ca-enable.example.test", 18432, false)
	router := gin.New()
	router.POST("/rules/:caddy_id/enable", handler.EnableRule)
	response := httptest.NewRecorder()

	router.ServeHTTP(response, httptest.NewRequest(http.MethodPost, "/rules/lb_no_ca_enable/enable", nil))

	if response.Code != http.StatusBadRequest {
		t.Fatalf("status=%d body=%s, want 400（无可用 CA 提供商是用户可修复状态，不得报 500）", response.Code, response.Body.String())
	}
	if !strings.Contains(response.Body.String(), "没有可用的 CA 提供商") {
		t.Fatalf("body=%s, want 与创建路径同款可操作指引", response.Body.String())
	}
	var enabled bool
	if err := db.DB.QueryRow("SELECT enabled FROM lb_rules WHERE caddy_id='lb_no_ca_enable'").Scan(&enabled); err != nil {
		t.Fatalf("read enabled state: %v", err)
	}
	if enabled {
		t.Fatal("写前拒绝的启用不得落库")
	}
	if loadCalls.Load() != 0 || *lastLoad != "" {
		t.Fatalf("/load 次数=%d（末次载荷 %q），写前拒绝不得触碰 Caddy", loadCalls.Load(), *lastLoad)
	}
}

// CA 解析失败的分类是三条写路径共用的单源：只有「无可用提供商」（ErrNoRows）
// 映射为可修复的 400，DB 故障才 500 且必须留痕（Explicit 路由中间件不兜底）。
func TestRespondCAProviderResolveFailure_classification(t *testing.T) {
	initializeRuleFeatureTestDB(t)
	cases := []struct {
		name       string
		err        error
		wantStatus int
		wantAudits int
	}{
		{name: "无可用提供商", err: fmt.Errorf("load CA provider 0: %w", sql.ErrNoRows), wantStatus: http.StatusBadRequest, wantAudits: 0},
		{name: "数据库故障", err: errors.New("database is locked"), wantStatus: http.StatusInternalServerError, wantAudits: 1},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			gin.SetMode(gin.TestMode)
			recorder := httptest.NewRecorder()
			ctx, _ := gin.CreateTestContext(recorder)
			ctx.Request = httptest.NewRequest(http.MethodPut, "/rules/lb_ca_classify", nil)
			ctx.Params = gin.Params{{Key: "caddy_id", Value: "lb_ca_classify"}}
			before := auditCountFor(t, "更新失败", "负载规则")

			respondCAProviderResolveFailure(ctx, "更新", tc.err)

			if recorder.Code != tc.wantStatus {
				t.Fatalf("status=%d body=%s, want %d", recorder.Code, recorder.Body.String(), tc.wantStatus)
			}
			if got := auditCountFor(t, "更新失败", "负载规则") - before; got != tc.wantAudits {
				t.Fatalf("失败审计条数=%d, want %d", got, tc.wantAudits)
			}
		})
	}
}
