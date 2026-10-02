package handlers

import (
	"context"
	"database/sql"
	"database/sql/driver"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/gin-gonic/gin"

	"lazy-balancer-v2/internal/db"
	"lazy-balancer-v2/internal/services"
)

func newCustomRuleCreateRouter(t *testing.T) *gin.Engine {
	t.Helper()
	fakeCaddy := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	t.Cleanup(fakeCaddy.Close)
	gin.SetMode(gin.TestMode)
	h := &Handlers{caddyService: services.NewCaddyService(fakeCaddy.URL)}
	router := gin.New()
	router.POST("/security/custom-rules", h.CreateSecurityCustomRule)
	return router
}

func seedCustomRules(t *testing.T, n int) {
	t.Helper()
	for i := 0; i < n; i++ {
		if _, err := db.DB.Exec(`INSERT INTO security_custom_rules (name, conditions, action, score, enabled) VALUES (?, '[]', 'block', 5, 1)`,
			fmt.Sprintf("批量规则 %03d", i)); err != nil {
			t.Fatalf("seed rule %d: %v", i, err)
		}
	}
}

func validCustomRulePayload(name string) map[string]any {
	return map[string]any{
		"name":       name,
		"conditions": []map[string]string{{"target": "uri", "operator": "contains", "pattern": "/x"}},
		"action":     "block",
		"score":      5,
		"enabled":    true,
	}
}

// U3-1（第 65 轮）/U3-F1（第 66 轮常量化）：全局 200 条上限的目标形状钉测试
// ——上限行为第 65 轮已存在（基线钉，R-1 豁免 RED，见修复报告），第 66 轮
// 常量化 securityCustomRuleMaxGlobalCount 不改变阈值与文案语义。
func TestCreateSecurityCustomRule_rejectsAtGlobalCountLimit(t *testing.T) {
	setupSecurityPolicyTestDB(t)
	router := newCustomRuleCreateRouter(t)
	seedCustomRules(t, 200)

	rec := postJSON(t, router, "/security/custom-rules", validCustomRulePayload("越限规则"))
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("status=%d body=%s, want 400", rec.Code, rec.Body.String())
	}
	if !strings.Contains(rec.Body.String(), "上限（200 条）") {
		t.Fatalf("body=%s, want message naming the 200-rule limit", rec.Body.String())
	}
	var count int
	if err := db.DB.QueryRow("SELECT COUNT(*) FROM security_custom_rules").Scan(&count); err != nil {
		t.Fatal(err)
	}
	if count != 200 {
		t.Fatalf("rows=%d, want 200 (rejected rule must not commit)", count)
	}
}

// 边界回归形状：199 条存量时创建放行（第 201 条才触限）。
func TestCreateSecurityCustomRule_allowsAtLimitMinusOne(t *testing.T) {
	setupSecurityPolicyTestDB(t)
	router := newCustomRuleCreateRouter(t)
	seedCustomRules(t, 199)

	rec := postJSON(t, router, "/security/custom-rules", validCustomRulePayload("边界规则"))
	if rec.Code != http.StatusOK {
		t.Fatalf("status=%d body=%s, want 200 at 199 existing rows", rec.Code, rec.Body.String())
	}
	var count int
	if err := db.DB.QueryRow("SELECT COUNT(*) FROM security_custom_rules").Scan(&count); err != nil {
		t.Fatal(err)
	}
	if count != 200 {
		t.Fatalf("rows=%d, want 200 (rule committed)", count)
	}
}

// customRuleCountFailConnector 注入「规则计数查询失败」的主库故障（U3-F2
// fail-closed 形状）——Begin/INSERT 照常成功，仅命中 security_custom_rules
// 计数的查询失败。
type customRuleCountFailConnector struct{}

func (customRuleCountFailConnector) Connect(context.Context) (driver.Conn, error) {
	return customRuleCountFailConn{}, nil
}

func (customRuleCountFailConnector) Driver() driver.Driver { return customRuleCountFailDriver{} }

type customRuleCountFailDriver struct{}

func (customRuleCountFailDriver) Open(string) (driver.Conn, error) {
	return customRuleCountFailConn{}, nil
}

type customRuleCountFailConn struct{}

func (customRuleCountFailConn) Prepare(string) (driver.Stmt, error) {
	return nil, errors.New("unexpected prepare")
}

func (customRuleCountFailConn) Close() error              { return nil }
func (customRuleCountFailConn) Begin() (driver.Tx, error) { return customRuleCountFailTx{}, nil }

func (customRuleCountFailConn) QueryContext(_ context.Context, query string, _ []driver.NamedValue) (driver.Rows, error) {
	if strings.Contains(query, "COUNT(*) FROM security_custom_rules") {
		return nil, errors.New("注入的规则计数故障")
	}
	return &fakeQueryRows{}, nil
}

func (customRuleCountFailConn) ExecContext(_ context.Context, _ string, _ []driver.NamedValue) (driver.Result, error) {
	return customRuleFakeResult{}, nil
}

type customRuleCountFailTx struct{}

func (customRuleCountFailTx) Commit() error   { return nil }
func (customRuleCountFailTx) Rollback() error { return nil }

type customRuleFakeResult struct{}

func (customRuleFakeResult) LastInsertId() (int64, error) { return 1, nil }
func (customRuleFakeResult) RowsAffected() (int64, error) { return 1, nil }

// U3-F2（第 66 轮）：计数查询失败必须拒绝创建（fail-closed）——此前
// `err == nil && ruleCount >= 200` 使 DB 故障静默跳过上限检查继续创建
// （fail-open）；计数移入 BeginTx 事务内后同型故障返回 500，不再有绕过
// 上限的通道。
func TestCreateSecurityCustomRule_countQueryFailureFailsClosed(t *testing.T) {
	setupSecurityPolicyTestDB(t)
	router := newCustomRuleCreateRouter(t)
	fake := sql.OpenDB(customRuleCountFailConnector{})
	t.Cleanup(func() { _ = fake.Close() })
	orig := db.DB
	db.DB = fake
	t.Cleanup(func() { db.DB = orig })

	rec := postJSON(t, router, "/security/custom-rules", validCustomRulePayload("故障期规则"))
	if rec.Code != http.StatusInternalServerError {
		t.Fatalf("status=%d body=%s, want 500 (count query failure must fail closed, not bypass the limit)", rec.Code, rec.Body.String())
	}
}
