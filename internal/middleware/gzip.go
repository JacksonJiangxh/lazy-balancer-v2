// Package-internal gzip 压缩中间件（替代 github.com/gin-contrib/gzip 的装配）。
//
// 与上游实现的行为差异只有一处：错误响应（状态码 ≥400）与无体响应（204/304）
// **不再删除 Vary 头**。上游在 removeGzipHeaders 里执行 Del("Vary")，把 CORS
// 早先写入的 `Vary: Origin` 一起删掉——而 `Vary: Origin` 正是「响应按 Origin
// 区分缓存」的唯一载体（CORS 反射 Origin 是既定设计）。丢失后，共享缓存/反代
// 可把 A 源的 Access-Control-Allow-Origin 复用到 B 源请求，浏览器按 ACAO 不匹配
// 拒读（误拒，非泄露）。
//
// 保留其余口径：按 Content-Type 白名单决定是否压缩、只压缩 gzip 客户端、
// 已带 Content-Encoding 的响应不动、压缩时不写 Content-Length。
package middleware

import (
	"compress/gzip"
	"net/http"
	"strings"

	"github.com/gin-gonic/gin"
)

// gzipContentTypes 是可压缩的 Content-Type 前缀白名单（与 gin-contrib/gzip 的
// 默认集合同口径）。
var gzipContentTypes = []string{
	"text/html", "text/css", "text/plain", "text/xml", "text/x-component", "text/javascript",
	"application/javascript", "application/x-javascript", "application/json",
	"application/manifest+json", "application/xml", "application/xhtml+xml",
	"application/rss+xml", "application/atom+xml", "image/svg+xml", "image/x-icon",
	"image/vnd.microsoft.icon", "font/ttf", "font/eot", "font/otf", "font/opentype",
	"application/vnd.ms-fontobject", "application/x-font-ttf", "application/x-font-opentype",
	"application/x-font-truetype",
}

func gzipCompressibleContentType(contentType string) bool {
	if contentType == "" {
		return false
	}
	for _, candidate := range gzipContentTypes {
		if strings.HasPrefix(contentType, candidate) {
			return true
		}
	}
	return false
}

type gzipResponseWriter struct {
	gin.ResponseWriter
	compressor *gzip.Writer
	decided    bool
}

// prepare 在首次写体前决定是否压缩。必须在 gin 的 responseWriter.Write 之前
// 完成——Write 内部会 WriteHeaderNow 把响应头落盘，之后再改头对客户端无效。
func (w *gzipResponseWriter) prepare() {
	if w.decided {
		return
	}
	w.decided = true
	if w.ResponseWriter.Written() {
		return
	}
	// 错误与无体响应不压缩：既不发 Content-Encoding，也不动 Vary/ETag
	// （上游实现在这两类分支里删整个 Vary，正是本实现要消除的回归）。
	if status := w.ResponseWriter.Status(); status >= http.StatusBadRequest ||
		status == http.StatusNoContent || status == http.StatusNotModified ||
		status < http.StatusOK {
		return
	}
	if w.Header().Get("Content-Encoding") != "" {
		return
	}
	if !gzipCompressibleContentType(w.Header().Get("Content-Type")) {
		return
	}
	w.Header().Del("Content-Length")
	w.Header().Add("Vary", "Accept-Encoding")
	w.Header().Set("Content-Encoding", "gzip")
	w.compressor = gzip.NewWriter(w.ResponseWriter)
}

func (w *gzipResponseWriter) Write(body []byte) (int, error) {
	w.prepare()
	if w.compressor == nil {
		return w.ResponseWriter.Write(body)
	}
	return w.compressor.Write(body)
}

func (w *gzipResponseWriter) WriteString(body string) (int, error) {
	w.prepare()
	if w.compressor == nil {
		return w.ResponseWriter.WriteString(body)
	}
	return w.compressor.Write([]byte(body))
}

func (w *gzipResponseWriter) Flush() {
	if w.compressor != nil {
		_ = w.compressor.Flush()
	}
	w.ResponseWriter.Flush()
}

// gzipMiddleware 按 Accept-Encoding 压缩响应；不接受的客户端原样透传。
func gzipMiddleware() gin.HandlerFunc {
	return func(c *gin.Context) {
		if (c.Request.Method == http.MethodHead) ||
			!strings.Contains(c.Request.Header.Get("Accept-Encoding"), "gzip") {
			c.Next()
			return
		}
		writer := &gzipResponseWriter{ResponseWriter: c.Writer}
		c.Writer = writer
		defer func() {
			// 无体的成功响应（204/304 或不写体的 handler）也要把头落盘，
			// 与 gin 默认行为一致；此时未设 Content-Encoding，Vary 不受影响。
			if writer.compressor != nil {
				_ = writer.compressor.Close()
			}
			c.Writer.WriteHeaderNow()
		}()
		c.Next()
	}
}
