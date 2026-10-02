package handlers

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/gin-gonic/gin"
)

// F-W1（第 66 轮）：主上游负权重拒绝——与路径规则上游（rule_features.go
// validatePathRuleUpstreams 400）口径对齐；此前仅 ==0→1 归一，负值放行落库，
// 渲染层钳制为 1 而 UI 回读显示负值（校验不对称）。

// Given 创建载荷携带负权重主上游。
// When POST /rules。
// Then 400「上游权重不能为负数」（今日 201 放行——RED）。
func TestCreateRule_rejectsNegativeUpstreamWeight(t *testing.T) {
	handler := newRuleFeatureTestHandlers(t)
	gin.SetMode(gin.TestMode)
	router := gin.New()
	router.POST("/api/v1/rules", handler.CreateRule)

	body := map[string]any{
		"name": "neg-weight", "protocol": "http", "domain": "neg.example.test",
		"listen_port": 443, "strategy": "weighted_round_robin",
		"enable_tls": false, "tls_source": "manual", "enabled": false,
		"upstreams": []map[string]any{{"host": "10.0.0.1", "port": 8080, "weight": -5, "enabled": true}},
	}
	raw, _ := json.Marshal(body)
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/api/v1/rules", bytes.NewReader(raw))
	req.Header.Set("Content-Type", "application/json")
	router.ServeHTTP(rec, req)

	if rec.Code != http.StatusBadRequest {
		t.Fatalf("负权重上游 status=%d body=%s, want 400", rec.Code, rec.Body.String())
	}
	if !bytes.Contains(rec.Body.Bytes(), []byte("权重不能为负数")) {
		t.Fatalf("错误文案应点名负权重, body=%s", rec.Body.String())
	}
}

// Given 创建载荷 weight=0（回归形状：归一为 1 放行）。
// Then 201（不受新校验影响）。
func TestCreateRule_zeroWeightStillNormalized(t *testing.T) {
	handler := newRuleFeatureTestHandlers(t)
	gin.SetMode(gin.TestMode)
	router := gin.New()
	router.POST("/api/v1/rules", handler.CreateRule)

	body := map[string]any{
		"name": "zero-weight", "protocol": "http", "domain": "zero.example.test",
		"listen_port": 443, "strategy": "weighted_round_robin",
		"enable_tls": false, "tls_source": "manual", "enabled": false,
		"upstreams": []map[string]any{{"host": "10.0.0.1", "port": 8080, "weight": 0, "enabled": true}},
	}
	raw, _ := json.Marshal(body)
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/api/v1/rules", bytes.NewReader(raw))
	req.Header.Set("Content-Type", "application/json")
	router.ServeHTTP(rec, req)

	if rec.Code != http.StatusCreated {
		t.Fatalf("weight=0 status=%d body=%s, want 201（归一放行回归形状）", rec.Code, rec.Body.String())
	}
}
