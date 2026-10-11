package handlers

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/gin-gonic/gin"

	"lazy-balancer-v2/internal/config"
	"lazy-balancer-v2/internal/services"
)

func TestGetAppLogs_reads_configured_log_file(t *testing.T) {
	// Given：超过 500 行的自定义路径日志文件
	logPath := filepath.Join(t.TempDir(), "custom-app.log")
	var builder strings.Builder
	for index := 1; index <= 600; index++ {
		builder.WriteString(fmt.Sprintf("log-line-%d\n", index))
	}
	if err := os.WriteFile(logPath, []byte(builder.String()), 0o644); err != nil {
		t.Fatalf("write log file: %v", err)
	}
	handler := &Handlers{cfg: &config.Config{LogFile: logPath}}
	router := gin.New()
	router.GET("/system/logs", handler.GetAppLogs)
	response := httptest.NewRecorder()

	// When
	router.ServeHTTP(response, httptest.NewRequest(http.MethodGet, "/system/logs", nil))

	// Then：读取配置路径且仅保留尾部 500 行
	if response.Code != http.StatusOK {
		t.Fatalf("status=%d body=%s, want 200", response.Code, response.Body.String())
	}
	var envelope struct {
		Data struct {
			Content string `json:"content"`
		} `json:"data"`
	}
	if err := json.Unmarshal(response.Body.Bytes(), &envelope); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	if !strings.Contains(envelope.Data.Content, "log-line-102") || !strings.Contains(envelope.Data.Content, "log-line-600") {
		t.Fatalf("log content missing expected tail lines: %q", envelope.Data.Content)
	}
	if strings.Contains(envelope.Data.Content, "log-line-101\n") {
		t.Fatalf("log content kept more than 500 lines: %q", envelope.Data.Content)
	}
}

func TestGetAppLogs_returns_empty_content_when_log_file_missing(t *testing.T) {
	// Given
	handler := &Handlers{cfg: &config.Config{LogFile: filepath.Join(t.TempDir(), "missing.log")}}
	router := gin.New()
	router.GET("/system/logs", handler.GetAppLogs)
	response := httptest.NewRecorder()

	// When
	router.ServeHTTP(response, httptest.NewRequest(http.MethodGet, "/system/logs", nil))

	// Then
	if response.Code != http.StatusOK || !strings.Contains(response.Body.String(), `"content":""`) {
		t.Fatalf("status=%d body=%s, want 200 with empty content", response.Code, response.Body.String())
	}
}

// GetProxyPorts 返回部署侧 HTTP/HTTPS 默认口与面板口（ISSUE #7）：
// 读 services 注入值 + cfg.Port，前端向导默认值同源。
func TestGetProxyPorts_returnsConfiguredPorts(t *testing.T) {
	// Given
	services.SetDefaultProxyPorts(8080, 8443)
	t.Cleanup(func() { services.SetDefaultProxyPorts(80, 443) })
	handler := &Handlers{cfg: &config.Config{Port: 9000}}
	router := gin.New()
	router.GET("/system/ports", handler.GetProxyPorts)
	response := httptest.NewRecorder()

	// When
	router.ServeHTTP(response, httptest.NewRequest(http.MethodGet, "/system/ports", nil))

	// Then
	if response.Code != http.StatusOK {
		t.Fatalf("status=%d body=%s, want 200", response.Code, response.Body.String())
	}
	var envelope struct {
		Code int `json:"code"`
		Data struct {
			HTTPPort  int `json:"http_port"`
			HTTPSPort int `json:"https_port"`
			PanelPort int `json:"panel_port"`
		} `json:"data"`
	}
	if err := json.Unmarshal(response.Body.Bytes(), &envelope); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	if envelope.Data.HTTPPort != 8080 || envelope.Data.HTTPSPort != 8443 || envelope.Data.PanelPort != 9000 {
		t.Fatalf("unexpected ports: %+v", envelope.Data)
	}
}

// GetProxyPorts 的 cfg 缺省（测试直构/未注入）回落出厂默认而非零值。
func TestGetProxyPorts_fallsBackToFactoryDefaults(t *testing.T) {
	// Given
	services.SetDefaultProxyPorts(80, 443)
	handler := &Handlers{cfg: &config.Config{}}
	router := gin.New()
	router.GET("/system/ports", handler.GetProxyPorts)
	response := httptest.NewRecorder()

	// When
	router.ServeHTTP(response, httptest.NewRequest(http.MethodGet, "/system/ports", nil))

	// Then
	var envelope struct {
		Data struct {
			HTTPPort  int `json:"http_port"`
			HTTPSPort int `json:"https_port"`
			PanelPort int `json:"panel_port"`
		} `json:"data"`
	}
	if err := json.Unmarshal(response.Body.Bytes(), &envelope); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	if envelope.Data.HTTPPort != 80 || envelope.Data.HTTPSPort != 443 || envelope.Data.PanelPort != 8000 {
		t.Fatalf("unexpected fallback ports: %+v", envelope.Data)
	}
}

// ruleMetricHosts 的 TLS/默认口 host 匹配跟随部署侧默认口（ISSUE #7）：
// 改 HTTPS_PORT 后按新口匹配 —— 否则换口部署的 TLS 规则指标恒查不到（空指标）。
func TestRuleMetricHosts_followsDeploymentDefaultPorts(t *testing.T) {
	services.SetDefaultProxyPorts(80, 443)
	t.Cleanup(func() { services.SetDefaultProxyPorts(80, 443) })

	// Given: 换口部署
	services.SetDefaultProxyPorts(8080, 8443)

	// When: 无 TLS 且端口未显式指定（0）→ 按 HTTP 默认口匹配
	plain := ruleMetricHosts(ruleMetricTarget{domain: "a.test", listenPort: 0})
	// 显式等于 HTTP 默认口
	onDefault := ruleMetricHosts(ruleMetricTarget{domain: "b.test", listenPort: 8080})
	// TLS 规则 → 另按 HTTPS 默认口匹配
	secure := ruleMetricHosts(ruleMetricTarget{domain: "c.test", listenPort: 8443, enableTLS: true})

	// Then
	if _, ok := plain["a.test:8080"]; !ok {
		t.Fatalf("listenPort=0 应按 HTTP 默认口 8080 匹配, got %v", plain)
	}
	if _, ok := onDefault["b.test:8080"]; !ok {
		t.Fatalf("listenPort=8080（=HTTP 默认口）应额外匹配 8080, got %v", onDefault)
	}
	if _, ok := secure["c.test:8443"]; !ok {
		t.Fatalf("TLS 规则应按 HTTPS 默认口 8443 匹配, got %v", secure)
	}
	if _, leaked := secure["c.test:443"]; leaked {
		t.Fatalf("HTTPS_PORT 已改 8443，不应再匹配旧口 443, got %v", secure)
	}
}
