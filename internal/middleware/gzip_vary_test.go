package middleware

import (
	"compress/gzip"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strconv"
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

// TestGzipMiddleware_panicStillRenders500 钉住 panic 恢复链路：defer 不得在
// panic 在途时无条件 WriteHeaderNow——先落默认 200 会让 gin.Recovery 的 500
// 无法生效，客户端拿到「200 + 空体」。
func TestGzipMiddleware_panicStillRenders500(t *testing.T) {
	gin.SetMode(gin.TestMode)
	router := gin.New()
	// 与生产链同序：Recovery 在外、压缩在内（SetupRouter 的 Use 顺序）。
	router.Use(gin.Recovery())
	router.Use(gzipMiddleware())
	router.GET("/panic", func(c *gin.Context) {
		panic("boom")
	})

	response := performGzipRequest(router, http.MethodGet, "/panic", "gzip")

	if response.Code != http.StatusInternalServerError {
		t.Fatalf("status=%d, want 500——panic 必须由 gin.Recovery 写成 500", response.Code)
	}
	if encoding := response.Header().Get("Content-Encoding"); encoding != "" {
		t.Errorf("500 响应不应压缩，Content-Encoding=%q", encoding)
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

// TestGzipMiddleware_partialContentNotCompressed 钉住「206 不压缩」的守卫：
// 206 一旦被 gzip 包住，Content-Range 声明的字节区间与「整包 gzip」语义冲突
// （压缩分支还会删除 Content-Length），按分片拼接的客户端得到不可解内容。
//
// 形态说明：静态资产走 http.ServeContent，它在写体前已落头（gin 的
// written=true），prepare 会在状态门之前提前返回——因此真实静态路径本来就不
// 压缩（下方 staticFile 用例钉住该回归）。本用例用一个「先设头+状态、后写体」
// 的 206 handler 覆盖状态门本身：这是守卫真正生效的形态，删除
// StatusPartialContent 排除即复现压缩。
func TestGzipMiddleware_partialContentNotCompressed(t *testing.T) {
	gin.SetMode(gin.TestMode)
	router := gin.New()
	router.Use(gzipMiddleware())
	router.GET("/ranged", func(c *gin.Context) {
		body := []byte("0123456789")
		c.Header("Content-Type", "text/plain")
		c.Header("Content-Range", "bytes 0-9/1024")
		c.Header("Content-Length", strconv.Itoa(len(body)))
		c.Status(http.StatusPartialContent)
		_, _ = c.Writer.Write(body)
	})

	request := httptest.NewRequest(http.MethodGet, "/ranged", nil)
	request.Header.Set("Accept-Encoding", "gzip")
	response := httptest.NewRecorder()
	router.ServeHTTP(response, request)

	if response.Code != http.StatusPartialContent {
		t.Fatalf("status=%d, want 206", response.Code)
	}
	if encoding := response.Header().Get("Content-Encoding"); encoding != "" {
		t.Fatalf("206 响应被压缩：Content-Encoding=%q（与 Content-Range 语义冲突）", encoding)
	}
	if got := response.Header().Get("Content-Length"); got != "10" {
		t.Fatalf("Content-Length=%q, want 10（压缩会删除该头）", got)
	}
	if got := response.Header().Get("Content-Range"); got != "bytes 0-9/1024" {
		t.Fatalf("Content-Range=%q", got)
	}
	if body := response.Body.String(); body != "0123456789" {
		t.Fatalf("分片体被改写：%q", body)
	}
}

// 真实静态资产路径的 206（http.ServeContent + Range）不得压缩：头在写体前已
// 落盘，prepare 提前返回；若将来中间件改成先落头再判定，本用例会变红。
func TestGzipMiddleware_staticFilePartialContentNotCompressed(t *testing.T) {
	gin.SetMode(gin.TestMode)
	assetPath := filepath.Join(t.TempDir(), "app.js")
	content := strings.Repeat("console.log('partial');\n", 32)
	if err := os.WriteFile(assetPath, []byte(content), 0o644); err != nil {
		t.Fatalf("write asset: %v", err)
	}
	router := gin.New()
	router.Use(gzipMiddleware())
	router.StaticFile("/assets/app.js", assetPath)

	request := httptest.NewRequest(http.MethodGet, "/assets/app.js", nil)
	request.Header.Set("Accept-Encoding", "gzip")
	request.Header.Set("Range", "bytes=0-9")
	response := httptest.NewRecorder()
	router.ServeHTTP(response, request)

	if response.Code != http.StatusPartialContent {
		t.Fatalf("status=%d, want 206", response.Code)
	}
	if encoding := response.Header().Get("Content-Encoding"); encoding != "" {
		t.Fatalf("206 静态分片被压缩：Content-Encoding=%q", encoding)
	}
	if got := response.Header().Get("Content-Length"); got != "10" {
		t.Fatalf("Content-Length=%q, want 10", got)
	}
	if got, want := response.Header().Get("Content-Range"), "bytes 0-9/"+strconv.Itoa(len(content)); got != want {
		t.Fatalf("Content-Range=%q, want %q", got, want)
	}
	if response.Body.Len() != 10 {
		t.Fatalf("分片体长度=%d, want 10", response.Body.Len())
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
