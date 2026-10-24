package middleware

import (
	"compress/gzip"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/gin-gonic/gin"
)

// newGzipCorsRouter 装配 CORS + 压缩（与 SetupRouter 的先后次序一致），三条
// 形态：200 JSON 体、404 JSON 错误体、204 无体。
func newGzipCorsRouter() *gin.Engine {
	gin.SetMode(gin.TestMode)
	router := gin.New()
	router.Use(corsMiddleware())
	router.Use(gzipMiddleware())
	router.GET("/ok", func(c *gin.Context) {
		c.JSON(http.StatusOK, gin.H{"code": 0, "message": strings.Repeat("payload", 32)})
	})
	router.GET("/missing", func(c *gin.Context) {
		c.JSON(http.StatusNotFound, gin.H{"code": 404, "message": "资源不存在"})
	})
	router.DELETE("/no-content", func(c *gin.Context) { c.Status(http.StatusNoContent) })
	return router
}

func performGzipRequest(router *gin.Engine, method, path, acceptEncoding string) *httptest.ResponseRecorder {
	request := httptest.NewRequest(method, path, nil)
	request.Header.Set("Origin", "https://panel.example.com")
	if acceptEncoding != "" {
		request.Header.Set("Accept-Encoding", acceptEncoding)
	}
	response := httptest.NewRecorder()
	router.ServeHTTP(response, request)
	return response
}

// TestGzipMiddleware_errorResponseKeepsVaryOrigin 钉住「错误响应不得丢 Vary」：
// 上游 gin-contrib/gzip 在 status>=400 时会 Del("Vary")，把 CORS 写入的
// Vary: Origin 一并删除，共享缓存遂可按错误码跨源复用 ACAO。
func TestGzipMiddleware_errorResponseKeepsVaryOrigin(t *testing.T) {
	router := newGzipCorsRouter()
	response := performGzipRequest(router, http.MethodGet, "/missing", "gzip")

	if response.Code != http.StatusNotFound {
		t.Fatalf("status=%d, want 404", response.Code)
	}
	if encoding := response.Header().Get("Content-Encoding"); encoding != "" {
		t.Errorf("404 响应不应压缩，Content-Encoding=%q", encoding)
	}
	if vary := response.Header().Values("Vary"); !headerValuesContain(vary, "Origin") {
		t.Errorf("404 响应丢失 Vary: Origin（vary=%v）——CORS 缓存契约破裂", vary)
	}
	if body := response.Body.String(); !strings.Contains(body, "资源不存在") {
		t.Errorf("404 响应体被破坏：%q", body)
	}
}

// TestGzipMiddleware_emptyBodyKeepsVaryOrigin 钉住 204 无体响应同样保留 Vary。
func TestGzipMiddleware_emptyBodyKeepsVaryOrigin(t *testing.T) {
	router := newGzipCorsRouter()
	response := performGzipRequest(router, http.MethodDelete, "/no-content", "gzip")

	if response.Code != http.StatusNoContent {
		t.Fatalf("status=%d, want 204", response.Code)
	}
	if response.Body.Len() != 0 {
		t.Errorf("204 响应不应有体：%q", response.Body.String())
	}
	if vary := response.Header().Values("Vary"); !headerValuesContain(vary, "Origin") {
		t.Errorf("204 响应丢失 Vary: Origin（vary=%v）", vary)
	}
	if encoding := response.Header().Get("Content-Encoding"); encoding != "" {
		t.Errorf("204 响应不应声明压缩，Content-Encoding=%q", encoding)
	}
}

// TestGzipMiddleware_successCompressesAndKeepsBothVary 钉住正常压缩路径：
// 压缩生效、体可解压、Vary 同时含 Origin 与 Accept-Encoding。
func TestGzipMiddleware_successCompressesAndKeepsBothVary(t *testing.T) {
	router := newGzipCorsRouter()
	response := performGzipRequest(router, http.MethodGet, "/ok", "gzip")

	if response.Code != http.StatusOK {
		t.Fatalf("status=%d, want 200", response.Code)
	}
	if encoding := response.Header().Get("Content-Encoding"); encoding != "gzip" {
		t.Fatalf("Content-Encoding=%q, want gzip", encoding)
	}
	vary := response.Header().Values("Vary")
	if !headerValuesContain(vary, "Origin") || !headerValuesContain(vary, "Accept-Encoding") {
		t.Errorf("Vary=%v, want 同时含 Origin 与 Accept-Encoding", vary)
	}
	reader, err := gzip.NewReader(response.Body)
	if err != nil {
		t.Fatalf("解压响应失败: %v", err)
	}
	defer reader.Close()
	body, err := io.ReadAll(reader)
	if err != nil {
		t.Fatalf("读取解压响应失败: %v", err)
	}
	if !strings.Contains(string(body), `"code":0`) {
		t.Errorf("解压后响应体异常：%q", string(body))
	}
	if response.Header().Get("Content-Length") != "" {
		t.Errorf("压缩响应不应携带 Content-Length")
	}
}

// TestGzipMiddleware_clientWithoutGzipPassesThrough 钉住不接受 gzip 的客户端
// 原样透传（不得声明 Content-Encoding，体保持明文）。
func TestGzipMiddleware_clientWithoutGzipPassesThrough(t *testing.T) {
	router := newGzipCorsRouter()
	response := performGzipRequest(router, http.MethodGet, "/ok", "identity")

	if encoding := response.Header().Get("Content-Encoding"); encoding != "" {
		t.Errorf("未协商 gzip 的客户端不应收到压缩，Content-Encoding=%q", encoding)
	}
	if !strings.Contains(response.Body.String(), `"code":0`) {
		t.Errorf("响应体应为明文 JSON：%q", response.Body.String())
	}
}

func headerValuesContain(values []string, want string) bool {
	for _, value := range values {
		for _, part := range strings.Split(value, ",") {
			if strings.EqualFold(strings.TrimSpace(part), want) {
				return true
			}
		}
	}
	return false
}
