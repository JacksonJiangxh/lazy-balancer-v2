package handlers

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/gin-gonic/gin"

	"lazy-balancer-v2/internal/config"
	"lazy-balancer-v2/internal/db"
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
	if !strings.Contains(envelope.Data.Content, "log-line-101") || !strings.Contains(envelope.Data.Content, "log-line-600") {
		t.Fatalf("log content missing expected tail lines: %q", envelope.Data.Content)
	}
	if strings.Contains(envelope.Data.Content, "log-line-100\n") {
		t.Fatalf("log content kept more than 500 lines: %q", envelope.Data.Content)
	}
}

// 以 \n 结尾的窗口按真实行数切片：行终止符产生的尾部空元素
// 不计行数，超限窗口必须显示满 500 条真实行。
func TestGetAppLogs_maxLinesCountsRealLines(t *testing.T) {
	// Given：505 行且以 \n 结尾的日志文件
	logPath := filepath.Join(t.TempDir(), "tail-lines.log")
	var builder strings.Builder
	for index := 1; index <= 505; index++ {
		builder.WriteString(fmt.Sprintf("line-%d\n", index))
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

	// Then：恰好保留最后 500 条真实行（line-6…line-505）
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
	lines := strings.Split(envelope.Data.Content, "\n")
	if len(lines) != 500 || lines[0] != "line-6" || lines[499] != "line-505" {
		t.Fatalf("以 \\n 结尾的 505 行应保留最后 500 条真实行（line-6…line-505），实得 %d 个元素，首 %q 尾 %q", len(lines), lines[0], lines[len(lines)-1])
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

// 节点角色查询失败/库未装配时 node_mode 为 unknown，
// 不得静默冒充 master（排障窗口的误导；同域写门对同一故障响亮 500）。
func TestGetSystemInfo_nodeModeUnknownWhenRoleUnavailable(t *testing.T) {
	oldDB := db.DB
	db.DB = nil
	db.SetDB(nil)
	t.Cleanup(func() {
		db.DB = oldDB
		db.SetDB(oldDB)
	})

	gin.SetMode(gin.TestMode)
	h := &Handlers{cfg: &config.Config{DataDir: t.TempDir()}}
	router := gin.New()
	router.GET("/system/info", h.GetSystemInfo)

	recorder := httptest.NewRecorder()
	router.ServeHTTP(recorder, httptest.NewRequest(http.MethodGet, "/system/info", nil))
	if recorder.Code != http.StatusOK {
		t.Fatalf("status=%d body=%s, want 200", recorder.Code, recorder.Body.String())
	}
	var payload struct {
		Data struct {
			NodeMode string `json:"node_mode"`
		} `json:"data"`
	}
	if err := json.Unmarshal(recorder.Body.Bytes(), &payload); err != nil {
		t.Fatalf("decode system info: %v", err)
	}
	if payload.Data.NodeMode != "unknown" {
		t.Fatalf("node_mode=%q, want unknown（查询失败不得冒充 master）", payload.Data.NodeMode)
	}
}

// /system/logs 只读常规文件：FIFO/设备节点/目录必须 500 拒绝（open(2) 对无
// 写端 FIFO 会无超时阻塞），且固定文案不得回显路径。
func TestGetAppLogs_rejectsNonRegularFile(t *testing.T) {
	dir := t.TempDir() // 目录本身即非常规目标
	handler := &Handlers{cfg: &config.Config{LogFile: dir}}
	router := gin.New()
	router.GET("/system/logs", handler.GetAppLogs)

	recorder := httptest.NewRecorder()
	router.ServeHTTP(recorder, httptest.NewRequest(http.MethodGet, "/system/logs", nil))
	if recorder.Code != http.StatusInternalServerError {
		t.Fatalf("status=%d body=%s, want 500（非常规文件不得被打开）", recorder.Code, recorder.Body.String())
	}
	body := recorder.Body.String()
	if !strings.Contains(body, "读取日志失败") {
		t.Fatalf("body=%s, want 固定文案", body)
	}
	if strings.Contains(body, dir) || strings.Contains(body, "is a directory") {
		t.Fatalf("响应泄漏内部结构: %s", body)
	}
}

// 「固定文案 + 服务端留痕」500 装配器的响应面回归钉：底层错误（路径/SQL/
// errno）只能进日志，不得拼进 message。
func TestInternalError_doesNotLeakCause(t *testing.T) {
	cause := fmt.Errorf("open /app/secret/admin_tls.key: permission denied")
	resp := systemInternalFailure("读取系统指标失败", cause)
	if resp.Code != http.StatusInternalServerError || resp.Message != "读取系统指标失败" {
		t.Fatalf("resp=%+v, want 固定文案 500", resp)
	}
	if strings.Contains(resp.Message, "/app/") || strings.Contains(resp.Message, "permission") {
		t.Fatalf("响应泄漏底层错误: %q", resp.Message)
	}
}

// 真实 FIFO 防护：判定必须落在已打开的 fd 上。无写端 FIFO 的阻塞 open(2)
// 会把请求 goroutine 永久挂住——此处断言请求在超时内返回 500。
func TestGetAppLogs_fifoDoesNotBlock(t *testing.T) {
	fifo := filepath.Join(t.TempDir(), "app.log")
	if err := syscall.Mkfifo(fifo, 0o600); err != nil {
		t.Skipf("mkfifo 不可用: %v", err)
	}
	handler := &Handlers{cfg: &config.Config{LogFile: fifo}}
	router := gin.New()
	router.GET("/system/logs", handler.GetAppLogs)

	done := make(chan *httptest.ResponseRecorder, 1)
	go func() {
		rec := httptest.NewRecorder()
		router.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/system/logs", nil))
		done <- rec
	}()
	select {
	case rec := <-done:
		if rec.Code != http.StatusInternalServerError || !strings.Contains(rec.Body.String(), "读取日志失败") {
			t.Fatalf("status=%d body=%s, want 500 固定文案", rec.Code, rec.Body.String())
		}
	case <-time.After(3 * time.Second):
		t.Fatal("FIFO 打开被阻塞（非常规文件判定未落在已打开 fd 上）")
	}
}

// 节点角色读必须脱离客户端生命周期：请求 ctx 已取消时仍应解析出真实角色，
// 不得把「客户端断开」记成角色查询失败（unknown + 每条请求一条 warn）。
func TestGetSystemInfo_roleReadIndependentOfClientCancel(t *testing.T) {
	h := newBackupTestHandlers(t)
	h.cfg.DataDir = t.TempDir()
	router := gin.New()
	router.GET("/system/info", h.GetSystemInfo)

	req := httptest.NewRequest(http.MethodGet, "/system/info", nil)
	ctx, cancel := context.WithCancel(req.Context())
	cancel() // 客户端在角色读之前断开
	recorder := httptest.NewRecorder()
	router.ServeHTTP(recorder, req.WithContext(ctx))

	if recorder.Code != http.StatusOK {
		t.Fatalf("status=%d body=%s, want 200", recorder.Code, recorder.Body.String())
	}
	var payload struct {
		Data struct {
			NodeMode string `json:"node_mode"`
		} `json:"data"`
	}
	if err := json.Unmarshal(recorder.Body.Bytes(), &payload); err != nil {
		t.Fatalf("decode system info: %v", err)
	}
	if payload.Data.NodeMode == "unknown" {
		t.Fatal("node_mode=unknown：角色读被客户端取消影响（必须用脱离取消的上下文）")
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
