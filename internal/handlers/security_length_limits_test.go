package handlers

// 安全域文本字段长度封顶——策略名 ≤100 rune、描述 ≤500 rune、
// 自定义规则名 ≤100 rune、自定义规则描述 ≤500 rune、
// 拦截页名 ≤100 rune、拦截页描述 ≤500 rune、
// 拦截页 content ≤64KB;DB 列无长度约束,超长串随审计详情/列表响应/发射文本放大。
// 另：策略内联 IP 名单条数 ≤ipListMaxEntries（与 IP 名单条目同阈值）、
// 自定义规则条件数/pattern 长度与 custom_rules 引用数在 services 侧单源封顶。

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/gin-gonic/gin"

	"lazy-balancer-v2/internal/services"
)

func newSecurityLengthRouter(t *testing.T) *gin.Engine {
	t.Helper()
	fakeCaddy := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	t.Cleanup(fakeCaddy.Close)
	gin.SetMode(gin.TestMode)
	h := &Handlers{caddyService: services.NewCaddyService(fakeCaddy.URL)}
	router := gin.New()
	router.POST("/security/policies", h.CreateSecurityPolicy)
	router.PUT("/security/policies/:id", h.UpdateSecurityPolicy)
	router.POST("/security/custom-rules", h.CreateSecurityCustomRule)
	router.POST("/security/block-pages", h.CreateSecurityBlockPage)
	router.PUT("/security/block-pages/:id", h.UpdateSecurityBlockPage)
	return router
}

func TestSecurityInputs_lengthLimits(t *testing.T) {
	setupSecurityPolicyTestDB(t)
	router := newSecurityLengthRouter(t)

	t.Run("policy name over 100 runes rejected", func(t *testing.T) {
		rec := postJSON(t, router, "/security/policies", map[string]any{"name": strings.Repeat("名", 101)})
		if rec.Code != http.StatusBadRequest || !strings.Contains(rec.Body.String(), "100") {
			t.Fatalf("101-rune name must 400, got %d %s", rec.Code, rec.Body.String())
		}
		rec = postJSON(t, router, "/security/policies", map[string]any{"name": strings.Repeat("名", 100)})
		if rec.Code != http.StatusOK {
			t.Fatalf("100-rune name must pass, got %d %s", rec.Code, rec.Body.String())
		}
	})

	t.Run("policy description over 500 runes rejected", func(t *testing.T) {
		rec := postJSON(t, router, "/security/policies", map[string]any{"name": "d", "description": strings.Repeat("描", 501)})
		if rec.Code != http.StatusBadRequest || !strings.Contains(rec.Body.String(), "500") {
			t.Fatalf("501-rune description must 400, got %d %s", rec.Code, rec.Body.String())
		}
	})

	t.Run("policy update name over 100 runes rejected", func(t *testing.T) {
		rec := putJSON(t, router, "/security/policies/1", map[string]any{"name": strings.Repeat("名", 101)})
		if rec.Code != http.StatusBadRequest {
			t.Fatalf("update 101-rune name must 400, got %d %s", rec.Code, rec.Body.String())
		}
	})

	t.Run("custom rule name over 100 runes rejected", func(t *testing.T) {
		rec := postJSON(t, router, "/security/custom-rules", map[string]any{
			"name": strings.Repeat("规", 101), "action": "block", "score": 5, "conditions": []map[string]any{{"target": "uri", "operator": "contains", "pattern": "/x"}},
		})
		if rec.Code != http.StatusBadRequest || !strings.Contains(rec.Body.String(), "100") {
			t.Fatalf("101-rune rule name must 400, got %d %s", rec.Code, rec.Body.String())
		}
	})

	// 自定义规则 description 补封顶（家族漏收敛
	// ——策略描述同口径 500 rune；DB 列无约束，超长串随列表响应/审计详情放大）。
	t.Run("custom rule description over 500 runes rejected", func(t *testing.T) {
		rec := postJSON(t, router, "/security/custom-rules", map[string]any{
			"name": "d", "description": strings.Repeat("描", 501), "action": "block", "score": 5,
			"conditions": []map[string]any{{"target": "uri", "operator": "contains", "pattern": "/x"}},
		})
		if rec.Code != http.StatusBadRequest || !strings.Contains(rec.Body.String(), "500") {
			t.Fatalf("501-rune rule description must 400, got %d %s", rec.Code, rec.Body.String())
		}
		// 边界回归：恰好 500 rune 放行
		rec = postJSON(t, router, "/security/custom-rules", map[string]any{
			"name": "d2", "description": strings.Repeat("描", 500), "action": "block", "score": 5,
			"conditions": []map[string]any{{"target": "uri", "operator": "contains", "pattern": "/x"}},
		})
		if rec.Code != http.StatusOK {
			t.Fatalf("500-rune rule description must pass, got %d %s", rec.Code, rec.Body.String())
		}
	})

	t.Run("block page content over 64KB rejected", func(t *testing.T) {
		rec := postJSON(t, router, "/security/block-pages", map[string]any{
			"name": "p", "content": strings.Repeat("a", 64*1024+1),
		})
		if rec.Code != http.StatusBadRequest || !strings.Contains(rec.Body.String(), "64KB") {
			t.Fatalf("64KB+1 content must 400, got %d %s", rec.Code, rec.Body.String())
		}
		rec = postJSON(t, router, "/security/block-pages", map[string]any{
			"name": "p", "content": strings.Repeat("a", 64*1024),
		})
		if rec.Code != http.StatusOK {
			t.Fatalf("exactly 64KB content must pass, got %d %s", rec.Code, rec.Body.String())
		}
	})
	// 拦截页 name/description 补封顶（家族漏收敛
	// 点——策略/自定义规则同口径 100/500 rune；创建与更新同门）。
	t.Run("block page name over 100 runes rejected", func(t *testing.T) {
		rec := postJSON(t, router, "/security/block-pages", map[string]any{
			"name": strings.Repeat("页", 101), "content": "<html></html>",
		})
		if rec.Code != http.StatusBadRequest || !strings.Contains(rec.Body.String(), "100") {
			t.Fatalf("101-rune block page name must 400, got %d %s", rec.Code, rec.Body.String())
		}
		rec = putJSON(t, router, "/security/block-pages/1", map[string]any{
			"name": strings.Repeat("页", 101), "content": "<html></html>",
		})
		if rec.Code != http.StatusBadRequest || !strings.Contains(rec.Body.String(), "100") {
			t.Fatalf("update 101-rune block page name must 400, got %d %s", rec.Code, rec.Body.String())
		}
	})

	t.Run("block page description over 500 runes rejected", func(t *testing.T) {
		rec := postJSON(t, router, "/security/block-pages", map[string]any{
			"name": "p", "description": strings.Repeat("描", 501), "content": "<html></html>",
		})
		if rec.Code != http.StatusBadRequest || !strings.Contains(rec.Body.String(), "500") {
			t.Fatalf("501-rune block page description must 400, got %d %s", rec.Code, rec.Body.String())
		}
		// 边界回归：恰好 500 rune 放行
		rec = postJSON(t, router, "/security/block-pages", map[string]any{
			"name": "p2", "description": strings.Repeat("描", 500), "content": "<html></html>",
		})
		if rec.Code != http.StatusOK {
			t.Fatalf("500-rune block page description must pass, got %d %s", rec.Code, rec.Body.String())
		}
	})
}

// 策略内联 IP 名单条数封顶（与 IP 名单条目上限同阈值 2000）：内联名单原样
// 随策略列表/详情回传并在每次渲染时逐条展开，全局请求体上限拦不住十万级
// 条目；创建与更新两侧同门，边界值 N 放行 / N+1 拒绝。
func TestSecurityPolicy_inlineIPListCountLimit(t *testing.T) {
	setupSecurityPolicyTestDB(t)
	router := newSecurityLengthRouter(t)

	entries := make([]string, ipListMaxEntries)
	for i := range entries {
		entries[i] = fmt.Sprintf("10.0.%d.%d", i/256, i%256)
	}
	atLimit, err := json.Marshal(entries)
	if err != nil {
		t.Fatal(err)
	}
	rec := postJSON(t, router, "/security/policies", map[string]any{
		"name": "ip-limit-at", "mode": "off", "ip_whitelist": string(atLimit),
	})
	if rec.Code != http.StatusOK {
		t.Fatalf("条目数=上限(%d)必须放行, got %d %s", ipListMaxEntries, rec.Code, rec.Body.String())
	}

	overLimit, err := json.Marshal(append(entries, "10.9.9.9"))
	if err != nil {
		t.Fatal(err)
	}
	limitText := fmt.Sprintf("%d", ipListMaxEntries)
	rec = postJSON(t, router, "/security/policies", map[string]any{
		"name": "ip-limit-over", "mode": "off", "ip_whitelist": string(overLimit),
	})
	if rec.Code != http.StatusBadRequest || !strings.Contains(rec.Body.String(), "不能超过") || !strings.Contains(rec.Body.String(), limitText) {
		t.Fatalf("创建条目数=上限+1 必须 400 并给出数值, got %d %s", rec.Code, rec.Body.String())
	}
	// 更新侧同门。
	rec = putJSON(t, router, "/security/policies/1", map[string]any{"ip_whitelist": string(overLimit)})
	if rec.Code != http.StatusBadRequest || !strings.Contains(rec.Body.String(), "不能超过") {
		t.Fatalf("更新条目数=上限+1 必须 400, got %d %s", rec.Code, rec.Body.String())
	}
}

// 自定义规则的条件数与 pattern 长度超限经 API 返回 400（阈值单源在
// services：customRuleMaxConditions/customRuleMaxPatternBytes——本用例只钉
// 「写端点确实拒绝并给出可读文案」，具体阈值由 services 侧边界测试钉住）。
func TestSecurityCustomRule_fieldLevelLimits(t *testing.T) {
	setupSecurityPolicyTestDB(t)
	router := newSecurityLengthRouter(t)

	conditions := make([]map[string]any, 65)
	for i := range conditions {
		conditions[i] = map[string]any{"target": "uri", "operator": "contains", "pattern": "/x"}
	}
	rec := postJSON(t, router, "/security/custom-rules", map[string]any{
		"name": "cond-limit", "action": "block", "score": 5, "conditions": conditions,
	})
	if rec.Code != http.StatusBadRequest || !strings.Contains(rec.Body.String(), "最多支持") {
		t.Fatalf("条件数超限必须 400, got %d %s", rec.Code, rec.Body.String())
	}

	rec = postJSON(t, router, "/security/custom-rules", map[string]any{
		"name": "pattern-limit", "action": "block", "score": 5,
		"conditions": []map[string]any{{"target": "uri", "operator": "contains", "pattern": strings.Repeat("a", 4*1024+1)}},
	})
	if rec.Code != http.StatusBadRequest || !strings.Contains(rec.Body.String(), "不能超过") {
		t.Fatalf("pattern 超限必须 400, got %d %s", rec.Code, rec.Body.String())
	}

	// 边界回归：上限内（64 条件 / 4KB pattern）放行。
	conditions = conditions[:64]
	rec = postJSON(t, router, "/security/custom-rules", map[string]any{
		"name": "cond-limit-ok", "action": "block", "score": 5, "conditions": conditions,
	})
	if rec.Code != http.StatusOK {
		t.Fatalf("条件数=上限必须放行, got %d %s", rec.Code, rec.Body.String())
	}
	rec = postJSON(t, router, "/security/custom-rules", map[string]any{
		"name": "pattern-limit-ok", "action": "block", "score": 5,
		"conditions": []map[string]any{{"target": "uri", "operator": "contains", "pattern": strings.Repeat("a", 4*1024)}},
	})
	if rec.Code != http.StatusOK {
		t.Fatalf("pattern=上限必须放行, got %d %s", rec.Code, rec.Body.String())
	}
}
