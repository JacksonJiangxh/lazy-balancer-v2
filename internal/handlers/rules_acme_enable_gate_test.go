package handlers

import (
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
