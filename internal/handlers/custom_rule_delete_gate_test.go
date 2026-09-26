package handlers

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"lazy-balancer-v2/internal/db"
	"lazy-balancer-v2/internal/services"

	"github.com/gin-gonic/gin"
)

// 第 59 轮 R59-P3（U1-2）：非规范数字 id（如 "5.0"/" 5"）不得借 SQLite 数值亲和
// 绕过「被启用策略引用不可删除」门——DeleteIPList:617 已修同型，本处为家族收敛。
// RED：Atoi 失败时引用检查被跳过但 DELETE 照执行；GREEN：非规范 id 直接 400。
func newCustomRuleDeleteRouter(t *testing.T) *gin.Engine {
	t.Helper()
	fakeCaddy := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	t.Cleanup(fakeCaddy.Close)
	gin.SetMode(gin.TestMode)
	h := &Handlers{caddyService: services.NewCaddyService(fakeCaddy.URL)}
	router := gin.New()
	router.DELETE("/security/custom-rules/:id", h.DeleteSecurityCustomRule)
	return router
}

func TestDeleteSecurityCustomRule_nonCanonicalIDRejected(t *testing.T) {
	setupSecurityPolicyTestDB(t)
	router := newCustomRuleDeleteRouter(t)

	// Given：规则 id=5 被 id=900 启用策略引用（custom_rules 数组形态）
	if _, err := db.DB.Exec(`INSERT INTO security_custom_rules (id, name, conditions, action, enabled) VALUES (5, '被引用规则', '[]', 'block', 1)`); err != nil {
		t.Fatal(err)
	}
	if _, err := db.DB.Exec(`INSERT INTO security_policies (id, name, mode, enabled, custom_rules) VALUES (900, '引用策略', 'blocking', 1, '[5]')`); err != nil {
		t.Fatal(err)
	}

	// When：以非规范 id "5.0" 删除（Atoi 失败形态；SQLite 亲和仍会命中 id=5 行）
	req, _ := http.NewRequest(http.MethodDelete, "/security/custom-rules/5.0", nil)
	rec := httptest.NewRecorder()
	router.ServeHTTP(rec, req)

	// Then：400 拒绝（而非跳过引用检查删除）
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("非规范 id 应 400: status=%d body=%s", rec.Code, rec.Body.String())
	}
	var remains int
	if err := db.DB.QueryRow(`SELECT COUNT(*) FROM security_custom_rules WHERE id=5`).Scan(&remains); err != nil {
		t.Fatal(err)
	}
	if remains != 1 {
		t.Fatalf("规则不得被非规范 id 删除: remains=%d", remains)
	}
	// 边界：规范数字 id 保持既有语义（引用检查 409）
	req2, _ := http.NewRequest(http.MethodDelete, "/security/custom-rules/5", nil)
	rec2 := httptest.NewRecorder()
	router.ServeHTTP(rec2, req2)
	if rec2.Code != http.StatusConflict {
		t.Fatalf("被引用规则规范删除应 409: status=%d body=%s", rec2.Code, rec2.Body.String())
	}
}
