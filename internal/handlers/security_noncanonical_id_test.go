package handlers

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/gin-gonic/gin"

	"lazy-balancer-v2/internal/db"
	"lazy-balancer-v2/internal/services"
)

// 非规范数字 ID 家族门（R-12）：策略/自定义规则更新、策略解绑与删除路径
// 同口径 400，不得让 SQLite INTEGER 亲和（'5.0'→5）命中并改写真实行。
func TestSecurityWritePaths_rejectNoncanonicalIDs(t *testing.T) {
	setupSecurityPolicyTestDB(t)
	gin.SetMode(gin.TestMode)
	fakeCaddy := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	t.Cleanup(fakeCaddy.Close)
	h := &Handlers{caddyService: services.NewCaddyService(fakeCaddy.URL)}
	router := gin.New()
	router.PUT("/security/policies/:id", h.UpdateSecurityPolicy)
	router.DELETE("/security/policies/:id/bind/:caddy_id", h.UnbindRuleFromPolicy)
	router.PUT("/security/custom-rules/:id", h.UpdateSecurityCustomRule)

	if _, err := db.DB.Exec(`INSERT INTO security_policies (id,name,mode,enabled) VALUES (5,'policy','off',1)`); err != nil {
		t.Fatal(err)
	}
	if _, err := db.DB.Exec(`INSERT INTO security_custom_rules (id,name,conditions,action,enabled) VALUES (5,'rule','[]','block',1)`); err != nil {
		t.Fatal(err)
	}
	if _, err := db.DB.Exec(`INSERT INTO security_policy_bindings (rule_caddy_id,policy_id) VALUES ('lb_x',5)`); err != nil {
		t.Fatal(err)
	}

	cases := []struct {
		name   string
		method string
		path   string
		body   any
	}{
		{"policy update", http.MethodPut, "/security/policies/5.0", map[string]any{"name": "changed"}},
		{"custom rule update", http.MethodPut, "/security/custom-rules/5.0", map[string]any{"name": "changed"}},
		{"policy unbind", http.MethodDelete, "/security/policies/5.0/bind/lb_x", nil},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			var body *bytes.Reader
			if tc.body != nil {
				raw, _ := json.Marshal(tc.body)
				body = bytes.NewReader(raw)
			} else {
				body = bytes.NewReader(nil)
			}
			req := httptest.NewRequest(tc.method, tc.path, body)
			req.Header.Set("Content-Type", "application/json")
			rec := httptest.NewRecorder()
			router.ServeHTTP(rec, req)
			if rec.Code != http.StatusBadRequest {
				t.Fatalf("%s %s status=%d body=%s, want 400", tc.method, tc.path, rec.Code, rec.Body.String())
			}
		})
	}

	var policyName, ruleName string
	if err := db.DB.QueryRow(`SELECT name FROM security_policies WHERE id=5`).Scan(&policyName); err != nil {
		t.Fatal(err)
	}
	if err := db.DB.QueryRow(`SELECT name FROM security_custom_rules WHERE id=5`).Scan(&ruleName); err != nil {
		t.Fatal(err)
	}
	var bindings int
	if err := db.DB.QueryRow(`SELECT COUNT(*) FROM security_policy_bindings WHERE rule_caddy_id='lb_x' AND policy_id=5`).Scan(&bindings); err != nil {
		t.Fatal(err)
	}
	if policyName != "policy" || ruleName != "rule" || bindings != 1 {
		t.Fatalf("noncanonical ids mutated rows: policy=%q rule=%q bindings=%d", policyName, ruleName, bindings)
	}
}
