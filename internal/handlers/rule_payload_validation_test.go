package handlers

// 历史问题(历史):host_header 字符校验(CRLF/控制字符注入
// reverse_proxy 头部)、dns_server 形状校验(空 host/非数字端口)、
// services.ExtractMetricLabel 精确键匹配(x_host 不得误归集 host)。

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/gin-gonic/gin"

	"lazy-balancer-v2/internal/models"
	"lazy-balancer-v2/internal/services"
)

func TestRulePayload_hostHeaderAndDnsServerValidation(t *testing.T) {
	handler := newRuleFeatureTestHandlers(t)
	gin.SetMode(gin.TestMode)
	router := gin.New()
	router.POST("/rules", handler.CreateRule)
	base := func(extra string) string {
		return `{"name":"payload-v","protocol":"http","domain":"payload.test","listen_port":18582,` +
			`"health_check_interval":10,"health_check_timeout":2,"health_check_unhealthy_threshold":3,"health_check_healthy_threshold":2,` +
			`"upstreams":[{"host":"127.0.0.1","port":9000,"enabled":true}],` + extra + `}`
	}
	create := func(body string) *httptest.ResponseRecorder {
		request := httptest.NewRequest(http.MethodPost, "/rules", strings.NewReader(body))
		request.Header.Set("Content-Type", "application/json")
		response := httptest.NewRecorder()
		router.ServeHTTP(response, request)
		return response
	}

	// 形状一:host_header 含 CRLF → 400
	rec := create(base(`"host_header":"evil.com\r\nX-Injected: 1"`))
	if rec.Code != http.StatusBadRequest || !strings.Contains(rec.Body.String(), "后端域名含非法字符") {
		t.Fatalf("CRLF host_header must 400, got %d %s", rec.Code, rec.Body.String())
	}

	// 形状二:垃圾 dns_server(非数字端口) → 400
	rec = create(base(`"dynamic_dns":true,"dns_server":"8.8.8.8:notaport"`))
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("garbage dns_server must 400, got %d %s", rec.Code, rec.Body.String())
	}

	// 形状三(回归):合法形状放行
	rec = create(base(`"host_header":"api.backend.local"`))
	if rec.Code != http.StatusCreated && rec.Code != http.StatusOK {
		t.Fatalf("legit host_header must pass, got %d %s", rec.Code, rec.Body.String())
	}
}

func TestExtractLabel_exactKeyMatch(t *testing.T) {
	// x_host 不得被 host 子串匹配误归集
	if got := services.ExtractMetricLabel(`caddy_http_requests_total{x_host="evil"}`, "host"); got != "" {
		t.Fatalf("host label must not match x_host, got %q", got)
	}
	if got := services.ExtractMetricLabel(`caddy_http_requests_total{x_host="evil",host="real"}`, "host"); got != "real" {
		t.Fatalf("host label must match exact key, got %q", got)
	}
	if got := services.ExtractMetricLabel(`caddy_http_requests_total{host="first",x_host="evil"}`, "host"); got != "first" {
		t.Fatalf("leading host label must match, got %q", got)
	}
	if got := services.ExtractMetricLabel(`caddy_http_requests_total{x_host="evil"}`, "x_host"); got != "evil" {
		t.Fatalf("x_host label must match its own key, got %q", got)
	}
}

// 历史修复：共享保存门收录 tls_source 白名单与 request_body_max_size_mb 值域
// ——新增写路径只调共享门也不得落库跨模式 TLS 形态/越界值。
func TestRulePayloadSaveGateRejectsTLSSourceAndBodyLimit(t *testing.T) {
	h := newBackupTestHandlers(t)
	valid := func() models.CreateRuleRequest {
		return models.CreateRuleRequest{
			Name: "gate", Protocol: "http", Domain: "gate.example.test", ListenPort: 8443,
			Strategy: "weighted_round_robin", HealthCheckPath: "/", HealthCheckInterval: 10,
			HealthCheckTimeout: 2, HealthCheckUnhealthyThreshold: 3, HealthCheckHealthyThreshold: 2,
			Upstreams: []models.Upstream{{Host: "127.0.0.1", Port: 9000, Weight: 1, Enabled: true, Protocol: "http"}},
		}
	}

	baseline := valid()
	if err := h.validateRulePayloadBeforeSave(baseline); err != nil {
		t.Fatalf("基线载荷应通过共享门: %v", err)
	}

	badSource := valid()
	badSource.EnableTLS = true
	badSource.TLSSource = "https"
	if err := h.validateRulePayloadBeforeSave(badSource); err == nil || !strings.Contains(err.Error(), "证书来源") {
		t.Fatalf("tls_source=https 应被共享门拒绝, err=%v", err)
	}

	badBody := valid()
	badBody.RequestBodyMaxSizeMB = 5000
	if err := h.validateRulePayloadBeforeSave(badBody); err == nil || !strings.Contains(err.Error(), "0-4096") {
		t.Fatalf("request_body_max_size_mb=5000 应被共享门拒绝, err=%v", err)
	}
}

// 历史修复：DNS 服务器 host 不得「含点即 FQDN」——非法字符保存即拒。
func TestValidateSingleDnsAddress_rejectsIllegalHostCharacters(t *testing.T) {
	for _, bad := range []string{"a!b.example.com", "x/y.example.com", "dns example.com", `dns"bad.example.com`, "a:b:c"} {
		if err := validateSingleDnsAddress(bad); err == nil {
			t.Errorf("validateSingleDnsAddress(%q)=nil, want error", bad)
		}
	}
	for _, good := range []string{"8.8.8.8", "8.8.8.8:53", "dns.example.com", "dns.example.com:5353", "[2001:db8::1]:53", "localhost"} {
		if err := validateSingleDnsAddress(good); err != nil {
			t.Errorf("validateSingleDnsAddress(%q)=%v, want nil", good, err)
		}
	}
}
