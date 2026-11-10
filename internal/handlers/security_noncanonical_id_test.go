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

// 非规范数字 ID 家族门：策略/自定义规则更新、策略解绑与删除路径
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
	router.POST("/security/policies/:id/split", h.SplitSecurityPolicy)

	if _, err := db.DB.Exec(`INSERT INTO security_policies (id,name,mode,enabled) VALUES (5,'policy','off',1)`); err != nil {
		t.Fatal(err)
	}
	// 拆分端点此前缺规范 ID 门——用 mixed 策略做哨兵
	// 无门时 "6.0" 会被 SQLite 亲和命中并真正进入拆分（生成子策略），有门则
	// 在查库前 400。
	if _, err := db.DB.Exec(`INSERT INTO security_policies (id,name,mode,policy_type,enabled) VALUES (6,'mixed-sentinel','blocking','mixed',1)`); err != nil {
		t.Fatal(err)
	}
	if _, err := db.DB.Exec(`INSERT INTO security_custom_rules (id,name,conditions,action,enabled) VALUES (5,'rule','[]','block',1)`); err != nil {
		t.Fatal(err)
	}
	if _, err := db.DB.Exec(`INSERT INTO security_policy_bindings (rule_caddy_id,policy_id) VALUES ('lb_x',5)`); err != nil {
		t.Fatal(err)
	}

	var baselinePolicies int
	if err := db.DB.QueryRow(`SELECT COUNT(*) FROM security_policies`).Scan(&baselinePolicies); err != nil {
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
		{"policy split", http.MethodPost, "/security/policies/6.0/split", nil},
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
	// 拆分端点：非规范 ID 不得生成子策略（无门时 "6.0" 会命中 mixed 行并拆分）
	var policies int
	if err := db.DB.QueryRow(`SELECT COUNT(*) FROM security_policies`).Scan(&policies); err != nil {
		t.Fatal(err)
	}
	if policies != baselinePolicies {
		t.Fatalf("security_policies count=%d, want %d（split 不得因非规范 ID 生成子策略）", policies, baselinePolicies)
	}
}

// 策略详情读路径同属非规范数字 ID 家族门。SQLite 数值亲和会让
// '5.0' 命中 id=5 并返回详情，与全部写路径（parsePositiveNumericID → 400）
// 口径分叉。
func TestGetSecurityPolicy_rejectsNoncanonicalID(t *testing.T) {
	setupSecurityPolicyTestDB(t)
	gin.SetMode(gin.TestMode)
	h := &Handlers{}
	router := gin.New()
	router.GET("/security/policies/:id", h.GetSecurityPolicy)

	if _, err := db.DB.Exec(`INSERT INTO security_policies (id,name,mode,enabled) VALUES (5,'policy','off',1)`); err != nil {
		t.Fatal(err)
	}

	// 规范 ID 仍正常返回
	rec := httptest.NewRecorder()
	router.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/security/policies/5", nil))
	if rec.Code != http.StatusOK {
		t.Fatalf("canonical id status=%d body=%s, want 200", rec.Code, rec.Body.String())
	}

	for _, bad := range []string{"5.0", "0x5", "%205", "5e0"} {
		rec := httptest.NewRecorder()
		router.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/security/policies/"+bad, nil))
		if rec.Code != http.StatusBadRequest {
			t.Fatalf("id=%q status=%d body=%s, want 400（读路径须与写路径同门）", bad, rec.Code, rec.Body.String())
		}
	}
}
