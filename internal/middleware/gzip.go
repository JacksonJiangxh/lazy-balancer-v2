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
	"strconv"
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
	// 206 Partial Content 同列：压缩分支会删除 Content-Length，而 Content-Range
	// 仍声明「整包的第 N–M 字节」——响应同时声称「这是分片」与「整包是 gzip」，
	// 按 Range 拼接分片的客户端会得到不可解内容。
	if status := w.ResponseWriter.Status(); status >= http.StatusBadRequest ||
		status == http.StatusNoContent || status == http.StatusNotModified ||
		status == http.StatusPartialContent || status < http.StatusOK {
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

// acceptsGzip 按 RFC 9110 §12.5.3 解析 Accept-Encoding：q=0 表示「不可接受」，
// 显式 `gzip;q=0`（或 `gzip;q=0, *`）必须视为拒绝——只做子串包含会把 gzip
// 回给明确声明不要 gzip 的客户端，其解不开 body。显式列出 gzip 时以它的 q 为准；
// 未列出才回落到通配 `*` 的 q（同受 q=0 约束）。
func acceptsGzip(header string) bool {
	gzipQ, wildcardQ := -1.0, -1.0
	for _, rawPart := range strings.Split(header, ",") {
		fields := strings.Split(rawPart, ";")
		coding := strings.ToLower(strings.TrimSpace(fields[0]))
		if coding == "" {
			continue
		}
		q := 1.0
		for _, param := range fields[1:] {
			name, value, found := strings.Cut(strings.TrimSpace(param), "=")
			if !found || !strings.EqualFold(strings.TrimSpace(name), "q") {
				continue
			}
			// 非法 q 值按「未声明」处理（宽松：默认接受）。
			if parsed, err := strconv.ParseFloat(strings.TrimSpace(value), 64); err == nil {
				q = parsed
			}
		}
		switch coding {
		case "gzip", "x-gzip": // RFC 9110：x-gzip 为 gzip 的别名
			gzipQ = q
		case "*":
			if wildcardQ < 0 {
				wildcardQ = q
			}
		}
	}
	if gzipQ >= 0 {
		return gzipQ > 0
	}
	return wildcardQ > 0
}

// gzipMiddleware 按 Accept-Encoding 压缩响应；不接受的客户端原样透传。
func gzipMiddleware() gin.HandlerFunc {
	return func(c *gin.Context) {
		if (c.Request.Method == http.MethodHead) ||
			!acceptsGzip(c.Request.Header.Get("Accept-Encoding")) {
			c.Next()
			return
		}
		writer := &gzipResponseWriter{ResponseWriter: c.Writer}
		c.Writer = writer
		panicking := true
		defer func() {
			// 无体的成功响应（204/304 或不写体的 handler）也要把头落盘，
			// 与 gin 默认行为一致；此时未设 Content-Encoding，Vary 不受影响。
			if writer.compressor != nil {
				_ = writer.compressor.Close()
			}
			// panic 在途时不得 WriteHeaderNow：此刻尚未写头，先落盘等于把
			// 默认 200 提交给客户端，上层 gin.Recovery 的 500 再也写不进去
			// （只能得到「200 + 空体」）。恢复成功后由 Recovery 写 500。
			if !panicking {
				c.Writer.WriteHeaderNow()
			}
		}()
		c.Next()
		panicking = false
	}
}
