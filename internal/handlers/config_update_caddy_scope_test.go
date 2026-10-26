package handlers

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/gin-gonic/gin"

	"lazy-balancer-v2/internal/db"
	"lazy-balancer-v2/internal/services"
)

// 渲染消费字段清单决定保存是否触发 Caddy 重载。此表是「单一真相」的守卫：
// 任何渲染侧新增读取的 global_config 列，必须同时出现在 fieldAffectsCaddy
// 与这里的 true 组，否则保存只写库、运行配置永不更新。
func TestPlanConfigChanges_affectsCaddyClassification(t *testing.T) {
	caddyFields := []string{
		"caddy_log_level", "caddy_log_size_mb",
		"request_body_max_size_mb",
		"http_read_timeout", "http_write_timeout", "http_idle_timeout",
		"upstream_keepalive_timeout",
		"proxy_dial_timeout", "proxy_response_header_timeout",
		"proxy_read_timeout", "proxy_write_timeout", "proxy_stream_timeout",
		"proxy_flush_interval", "proxy_stream_close_delay",
		"server_tokens_hidden",
		"access_log_json", "access_log_format",
		"trusted_proxy_enabled", "trusted_proxy_ranges", "trusted_proxy_range_refs",
		"trusted_proxy_headers", "trusted_proxy_strict",
	}
	for _, field := range caddyFields {
		if !fieldAffectsCaddy(field) {
			t.Fatalf("%s 被渲染消费，必须影响 Caddy（否则保存不重载）", field)
		}
	}
	for _, field := range []string{
		"acme_email", "dns_provider", "cert_expiry_days", "cert_renewal_days",
		"cert_renewal_attempts", "default_ca_provider_id", "log_level", "timezone",
		"github_proxy_url", "github_token", "audit_retention_months",
		"jwt_expire_minutes", "mfa_write_guard", "mfa_lockout_enabled",
		"task_log_size_mb", "audit_log_size_mb", "runtime_log_size_mb",
		"server_map_lat", "server_map_lon", "threat_screen_mode",
		"threat_traffic_sample_n", "security_events_retention_days",
		"security_events_row_cap",
	} {
		if fieldAffectsCaddy(field) {
			t.Fatalf("%s 不进入渲染，不应触发 Caddy 重载", field)
		}
	}
}

type caddyScopeHarness struct {
	handlers   *Handlers
	router     *gin.Engine
	adminGets  atomic.Int32
	adminLoads atomic.Int32
	validator  atomic.Int32
}

func newCaddyScopeHarness(t *testing.T) *caddyScopeHarness {
	t.Helper()
	h := newBackupTestHandlers(t)
	harness := &caddyScopeHarness{handlers: h}
	fakeCaddy := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodGet && r.URL.Path == "/config/" {
			harness.adminGets.Add(1)
			_, _ = w.Write([]byte(`{}`))
			return
		}
		if r.Method == http.MethodPost && r.URL.Path == "/load" {
			harness.adminLoads.Add(1)
			w.WriteHeader(http.StatusOK)
			return
		}
		w.WriteHeader(http.StatusNotFound)
	}))
	t.Cleanup(fakeCaddy.Close)
	h.caddyService = services.NewCaddyService(fakeCaddy.URL)
	h.caddyService.SetCLIValidatorForTest(func([]byte) error {
		harness.validator.Add(1)
		return nil
	})
	gin.SetMode(gin.TestMode)
	harness.router = gin.New()
	harness.router.PUT("/config", h.UpdateConfig)
	return harness
}

func (h *caddyScopeHarness) save(t *testing.T, body string) *httptest.ResponseRecorder {
	t.Helper()
	request := httptest.NewRequest(http.MethodPut, "/config", strings.NewReader(body))
	request.Header.Set("Content-Type", "application/json")
	response := httptest.NewRecorder()
	h.router.ServeHTTP(response, request)
	return response
}

// Given 基础设置中不进入渲染的字段（登录过期时间），When 保存，Then 仅写库：
// 不读取运行配置、不 CLI 校验、不 /load——Caddy 可用性不得阻断这类保存。
func TestUpdateConfig_nonCaddyChangeSkipsCaddyEntirely(t *testing.T) {
	harness := newCaddyScopeHarness(t)

	response := harness.save(t, `{"jwt_expire_minutes":45}`)

	if response.Code != http.StatusOK {
		t.Fatalf("status=%d body=%s, want 200", response.Code, response.Body.String())
	}
	if got := harness.adminGets.Load(); got != 0 {
		t.Fatalf("非渲染变更读取运行配置次数=%d, want 0", got)
	}
	if got := harness.adminLoads.Load(); got != 0 {
		t.Fatalf("/load 次数=%d, want 0", got)
	}
	if got := harness.validator.Load(); got != 0 {
		t.Fatalf("CLI 校验次数=%d, want 0", got)
	}
	var stored int
	if err := db.DB.QueryRow(`SELECT jwt_expire_minutes FROM global_config WHERE id=1`).Scan(&stored); err != nil {
		t.Fatalf("读取写库结果: %v", err)
	}
	if stored != 45 {
		t.Fatalf("jwt_expire_minutes=%d, want 45（非渲染变更仍必须落库）", stored)
	}
	if strings.Contains(response.Body.String(), "并应用") {
		t.Fatalf("非渲染变更不应宣称已应用 Caddy 配置: %s", response.Body.String())
	}
}

// Given Caddy 不可达，When 保存非渲染字段，Then 仍成功（不再被 GetConfig 阻断）。
func TestUpdateConfig_nonCaddyChangeSurvivesUnreachableCaddy(t *testing.T) {
	harness := newCaddyScopeHarness(t)
	harness.handlers.caddyService = services.NewCaddyService("http://127.0.0.1:1")

	response := harness.save(t, `{"jwt_expire_minutes":50}`)

	if response.Code != http.StatusOK {
		t.Fatalf("status=%d body=%s, want 200（Caddy 不可达不得阻断设置保存）", response.Code, response.Body.String())
	}
	var stored int
	if err := db.DB.QueryRow(`SELECT jwt_expire_minutes FROM global_config WHERE id=1`).Scan(&stored); err != nil {
		t.Fatalf("读取写库结果: %v", err)
	}
	if stored != 50 {
		t.Fatalf("jwt_expire_minutes=%d, want 50", stored)
	}
}

// Given 渲染字段（日志大小），When 保存，Then 仍走 CLI 校验 + /load 全链。
func TestUpdateConfig_caddyChangeStillValidatesAndReloads(t *testing.T) {
	harness := newCaddyScopeHarness(t)

	response := harness.save(t, `{"caddy_log_size_mb":321}`)

	if response.Code != http.StatusOK {
		t.Fatalf("status=%d body=%s, want 200", response.Code, response.Body.String())
	}
	if got := harness.adminGets.Load(); got == 0 {
		t.Fatal("渲染变更必须读取运行配置快照")
	}
	if got := harness.validator.Load(); got == 0 {
		t.Fatal("渲染变更必须经过 CLI 校验")
	}
	if got := harness.adminLoads.Load(); got != 1 {
		t.Fatalf("/load 次数=%d, want 1", got)
	}
	if !strings.Contains(response.Body.String(), "并应用") {
		t.Fatalf("渲染变更成功响应应包含「并应用」: %s", response.Body.String())
	}
}
