package handlers

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"lazy-balancer-v2/internal/db"

	"github.com/gin-gonic/gin"
)

// 链式回退（chain_fallback，2026-10-09）写侧契约：
//   - HTTP 规则放行；0 值参数落库前兜底 3000/30000（与渲染侧同口径）；
//   - TCP 规则拒绝（协议感知白名单，同 cookie 先例）；
//   - 参数越界 400；
//   - Update 指针合并：省略（nil）=保留原值（LB-02 口径）。

func chainFallbackCreateBody(strategy string, race, timeout any) map[string]any {
	body := map[string]any{
		"name": "chain-rule", "protocol": "http", "domain": "chain.example.test",
		"listen_port": 443, "strategy": strategy,
		"enable_tls": false, "tls_source": "manual", "enabled": false,
		"upstreams": []map[string]any{
			{"host": "10.0.0.1", "port": 8081, "weight": 70, "enabled": true},
			{"host": "10.0.0.2", "port": 8082, "weight": 30, "enabled": true},
		},
	}
	if race != nil {
		body["chain_race_interval_ms"] = race
	}
	if timeout != nil {
		body["chain_request_timeout_ms"] = timeout
	}
	return body
}

func postRule(t *testing.T, handler *Handlers, body map[string]any) *httptest.ResponseRecorder {
	t.Helper()
	gin.SetMode(gin.TestMode)
	router := gin.New()
	router.POST("/api/v1/rules", handler.CreateRule)
	raw, _ := json.Marshal(body)
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/api/v1/rules", bytes.NewReader(raw))
	req.Header.Set("Content-Type", "application/json")
	router.ServeHTTP(rec, req)
	return rec
}

func TestCreateRule_chainFallback_defaultsApplied(t *testing.T) {
	handler := newRuleFeatureTestHandlers(t)
	rec := postRule(t, handler, chainFallbackCreateBody("chain_fallback", nil, nil))
	if rec.Code != http.StatusCreated {
		t.Fatalf("chain_fallback 创建 status=%d body=%s, want 201", rec.Code, rec.Body.String())
	}
	var raceInterval, requestTimeout int
	if err := db.DB.QueryRow(`SELECT COALESCE(chain_race_interval_ms,0), COALESCE(chain_request_timeout_ms,0) FROM lb_rules WHERE name='chain-rule'`).Scan(&raceInterval, &requestTimeout); err != nil {
		t.Fatalf("read back: %v", err)
	}
	if raceInterval != 3000 || requestTimeout != 30000 {
		t.Fatalf("0 值兜底失败: race=%d timeout=%d, want 3000/30000", raceInterval, requestTimeout)
	}
}

func TestCreateRule_chainFallback_rejectedForTCP(t *testing.T) {
	handler := newRuleFeatureTestHandlers(t)
	body := chainFallbackCreateBody("chain_fallback", nil, nil)
	body["protocol"] = "tcp"
	body["domain"] = ""
	rec := postRule(t, handler, body)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("tcp+chain_fallback status=%d body=%s, want 400", rec.Code, rec.Body.String())
	}
}

func TestCreateRule_chainFallback_rejectsOutOfRangeParams(t *testing.T) {
	handler := newRuleFeatureTestHandlers(t)
	rec := postRule(t, handler, chainFallbackCreateBody("chain_fallback", 60001, nil))
	if rec.Code != http.StatusBadRequest || !bytes.Contains(rec.Body.Bytes(), []byte("竞速间隔")) {
		t.Fatalf("race 越界 status=%d body=%s, want 400", rec.Code, rec.Body.String())
	}
	handler2 := newRuleFeatureTestHandlers(t)
	rec2 := postRule(t, handler2, chainFallbackCreateBody("chain_fallback", nil, 600001))
	if rec2.Code != http.StatusBadRequest || !bytes.Contains(rec2.Body.Bytes(), []byte("兜底超时")) {
		t.Fatalf("timeout 越界 status=%d body=%s, want 400", rec2.Code, rec2.Body.String())
	}
}

func TestCreateRule_chainFallback_explicitParamsPersisted(t *testing.T) {
	handler := newRuleFeatureTestHandlers(t)
	rec := postRule(t, handler, chainFallbackCreateBody("chain_fallback", 800, 3000))
	if rec.Code != http.StatusCreated {
		t.Fatalf("status=%d body=%s, want 201", rec.Code, rec.Body.String())
	}
	var raceInterval, requestTimeout int
	if err := db.DB.QueryRow(`SELECT COALESCE(chain_race_interval_ms,0), COALESCE(chain_request_timeout_ms,0) FROM lb_rules WHERE name='chain-rule'`).Scan(&raceInterval, &requestTimeout); err != nil {
		t.Fatalf("read back: %v", err)
	}
	if raceInterval != 800 || requestTimeout != 3000 {
		t.Fatalf("显式参数落库失败: race=%d timeout=%d, want 800/3000", raceInterval, requestTimeout)
	}
}

func chainRuleCaddyID(t *testing.T, name string) string {
	t.Helper()
	var caddyID string
	if err := db.DB.QueryRow(`SELECT caddy_id FROM lb_rules WHERE name = ?`, name).Scan(&caddyID); err != nil {
		t.Fatalf("read caddy_id for %s: %v", name, err)
	}
	return caddyID
}

// Update 省略（nil）链式参数 = 保留原值；显式携带 = 覆盖。
func TestUpdateRule_chainFallback_nilMergeKeepsExisting(t *testing.T) {
	handler := newRuleFeatureTestHandlers(t)
	if rec := postRule(t, handler, chainFallbackCreateBody("chain_fallback", 800, 3000)); rec.Code != http.StatusCreated {
		t.Fatalf("seed create status=%d body=%s", rec.Code, rec.Body.String())
	}
	caddyID := chainRuleCaddyID(t, "chain-rule")

	gin.SetMode(gin.TestMode)
	router := gin.New()
	router.PUT("/api/v1/rules/:caddy_id", handler.UpdateRule)

	// 省略两参数：仅改名
	raw, _ := json.Marshal(map[string]any{"name": "chain-rule-renamed"})
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPut, "/api/v1/rules/"+caddyID, bytes.NewReader(raw))
	req.Header.Set("Content-Type", "application/json")
	router.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("省略参数更新 status=%d body=%s, want 200", rec.Code, rec.Body.String())
	}
	var raceInterval, requestTimeout int
	if err := db.DB.QueryRow(`SELECT COALESCE(chain_race_interval_ms,0), COALESCE(chain_request_timeout_ms,0) FROM lb_rules WHERE name='chain-rule-renamed'`).Scan(&raceInterval, &requestTimeout); err != nil {
		t.Fatalf("read back: %v", err)
	}
	if raceInterval != 800 || requestTimeout != 3000 {
		t.Fatalf("nil 合并应保留原值: race=%d timeout=%d, want 800/3000", raceInterval, requestTimeout)
	}

	// 显式携带：覆盖
	raw2, _ := json.Marshal(map[string]any{"chain_race_interval_ms": 1200})
	rec2 := httptest.NewRecorder()
	req2 := httptest.NewRequest(http.MethodPut, "/api/v1/rules/"+caddyID, bytes.NewReader(raw2))
	req2.Header.Set("Content-Type", "application/json")
	router.ServeHTTP(rec2, req2)
	if rec2.Code != http.StatusOK {
		t.Fatalf("显式参数更新 status=%d body=%s, want 200", rec2.Code, rec2.Body.String())
	}
	if err := db.DB.QueryRow(`SELECT COALESCE(chain_race_interval_ms,0) FROM lb_rules WHERE name='chain-rule-renamed'`).Scan(&raceInterval); err != nil {
		t.Fatalf("read back 2: %v", err)
	}
	if raceInterval != 1200 {
		t.Fatalf("显式覆盖失败: race=%d, want 1200", raceInterval)
	}
}
