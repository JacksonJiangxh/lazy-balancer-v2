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

// RH-1(历史 历史问题):CreateRule 对禁用规则(enabled=false)不应创建
// ACME 签发任务——复制向导硬编码 enabled:false,每次复制白烧 1 次 LE 配额。
// UpdateRule 已有此门（needJob 与 *req.Enabled 合取，函数内「禁用不签发」段），
// CreateRule 缺失(系统不变量:禁用⇒不签发)。
func TestCreateRule_disabledRuleDoesNotQueueCertJob(t *testing.T) {
	handler := newRuleFeatureTestHandlers(t)
	gin.SetMode(gin.TestMode)
	// Seed: DNS 提供商配置(通过 ACMEConfigID 引用)
	if _, err := db.DB.Exec(`INSERT OR REPLACE INTO certificate_configs (id, name, dns_provider, dns_credentials, enabled) VALUES (1, 'test-dns', 'dnspod', '{}', 1)`); err != nil {
		t.Fatal(err)
	}
	if _, err := db.DB.Exec(`UPDATE global_config SET default_ca_provider_id=1 WHERE id=1`); err != nil {
		t.Fatal(err)
	}

	router := gin.New()
	router.POST("/api/v1/rules", handler.CreateRule)

	enabled := false
	body := map[string]any{
		"name": "disabled-acme", "protocol": "http", "domain": "disabled-acme.test",
		"listen_port": 443, "strategy": "weighted_round_robin",
		"enable_tls": true, "tls_source": "acme_dns", "acme_config_id": 1, "enabled": enabled,
		"health_check_interval": 10, "health_check_timeout": 2, "health_check_unhealthy_threshold": 3, "health_check_healthy_threshold": 2,
		"upstreams": []map[string]any{{"host": "10.0.0.1", "port": 8080, "weight": 1, "enabled": true}},
	}
	raw, _ := json.Marshal(body)
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/api/v1/rules", bytes.NewReader(raw))
	req.Header.Set("Content-Type", "application/json")
	router.ServeHTTP(rec, req)

	if rec.Code != http.StatusCreated {
		t.Fatalf("create disabled rule status=%d body=%s", rec.Code, rec.Body.String())
	}
	// 从响应取 caddy_id 查 cert_jobs
	var resp struct {
		Data struct {
			CaddyID string `json:"caddy_id"`
		} `json:"data"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatal(err)
	}
	var count int
	if err := db.DB.QueryRow("SELECT COUNT(*) FROM cert_jobs WHERE rule_id=?", resp.Data.CaddyID).Scan(&count); err != nil {
		t.Fatal(err)
	}
	if count > 0 {
		t.Fatalf("禁用规则不应创建签发任务, got %d cert_jobs", count)
	}
}

// LBH79-历史问题：创建 ACME 规则的正向链路（生成 cert_jobs）此前无钉测——
// 仅覆盖禁用规则 count==0 的负向与补偿 500。此用例锁住「启用 + ACME 引用
// 有效 → 创建后确有证书任务行」。
func TestCreateRule_enabledACMECreatesCertJob(t *testing.T) {
	handler := newRuleFeatureTestHandlers(t)
	services.ResetCAQueueManagerForTest()
	services.InitCAQueueManager(func() error { return nil }, t.TempDir())
	t.Cleanup(services.ResetCAQueueManagerForTest)
	if _, err := db.DB.Exec(`INSERT OR REPLACE INTO certificate_configs (id, name, dns_provider, dns_credentials, enabled) VALUES (1, 'test-dns', 'dnspod', '{}', 1)`); err != nil {
		t.Fatal(err)
	}
	if _, err := db.DB.Exec(`INSERT OR REPLACE INTO ca_providers (id,name,provider,directory_url,enabled) VALUES (1,'le-test','letsencrypt','https://acme.test/directory',1)`); err != nil {
		t.Fatal(err)
	}
	gin.SetMode(gin.TestMode)
	router := gin.New()
	router.POST("/rules", handler.CreateRule)

	body := map[string]any{
		"name": "enabled-acme", "protocol": "http", "domain": "enabled-acme.test",
		"listen_port": 443, "strategy": "weighted_round_robin",
		"enable_tls": true, "tls_source": "acme_dns", "acme_config_id": 1, "ca_provider_id": 1,
		"health_check_interval": 10, "health_check_timeout": 2, "health_check_unhealthy_threshold": 3, "health_check_healthy_threshold": 2,
		"upstreams": []map[string]any{{"host": "10.0.0.1", "port": 8080, "weight": 1, "enabled": true}},
	}
	raw, _ := json.Marshal(body)
	response := httptest.NewRecorder()
	request := httptest.NewRequest(http.MethodPost, "/rules", bytes.NewReader(raw))
	request.Header.Set("Content-Type", "application/json")
	router.ServeHTTP(response, request)

	if response.Code != http.StatusCreated {
		t.Fatalf("create enabled ACME rule status=%d body=%s", response.Code, response.Body.String())
	}
	var created struct {
		Data struct {
			CaddyID string `json:"caddy_id"`
		} `json:"data"`
	}
	if err := json.Unmarshal(response.Body.Bytes(), &created); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	var count int
	if err := db.DB.QueryRow("SELECT COUNT(*) FROM cert_jobs WHERE rule_id=?", created.Data.CaddyID).Scan(&count); err != nil {
		t.Fatalf("count cert jobs: %v", err)
	}
	if count != 1 {
		t.Fatalf("cert_jobs count=%d, want 1（启用 ACME 规则必须创建签发任务）", count)
	}
}
