package handlers

// LBH-B-U1（历史 历史问题）：GetCaddyLogs 尾窗「无换行/残段」行为与 GetAppLogs
// 统一 SYSB44-3 口径（抽享 tailLogWindow）——修复前 GetCaddyLogs 在窗口内无
// '\n' 时返回整段原始中段（历史只收敛了 system.go，R-12 漏扫点）：
// 单行 JSON 巨行（大请求头/大 body 访问日志可达 >128KB）时输出为巨行中段，
// 首字节切在多字节 rune 中间时带无效字节，JSON 编码后以 U+FFFD 污染。
// 统一口径：起点非零丢弃首行残段；窗口内无 '\n'（整窗为同一巨行中段）输出为空。

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/gin-gonic/gin"
)

// tailLogWindow 三形状钉：起点 0 原样 / 含换行丢弃首行残段 / 无换行整窗为空。
func TestTailLogWindow_shapes(t *testing.T) {
	if got := tailLogWindow([]byte("abc\ndef"), 0); string(got) != "abc\ndef" {
		t.Fatalf("startOffset=0 应原样返回, got %q", got)
	}
	if got := tailLogWindow([]byte("残段abc\n完整行\n"), 100); string(got) != "完整行\n" {
		t.Fatalf("含换行应丢弃首行残段, got %q", got)
	}
	if got := tailLogWindow([]byte("巨行中段无换行"), 100); got != nil {
		t.Fatalf("无换行应返回空（整窗为同一巨行中段）, got %q", got)
	}
}

// GetCaddyLogs 巨行形状：单条 >128KB 无换行日志，窗口整体落在行中段 → 内容为空。
func TestGetCaddyLogs_tailWindowGiantLineReturnsEmpty(t *testing.T) {
	// Given
	h := newBackupTestHandlers(t)
	logPath := filepath.Join(t.TempDir(), "caddy.log")
	if err := os.WriteFile(logPath, []byte(strings.Repeat("a", 200*1024)), 0o644); err != nil {
		t.Fatalf("write log: %v", err)
	}
	oldPaths := caddyLogPaths
	caddyLogPaths = map[string]string{"runtime": logPath}
	t.Cleanup(func() { caddyLogPaths = oldPaths })

	gin.SetMode(gin.TestMode)
	router := gin.New()
	router.GET("/caddy/logs", h.GetCaddyLogs)
	response := httptest.NewRecorder()

	// When
	router.ServeHTTP(response, httptest.NewRequest(http.MethodGet, "/caddy/logs?type=runtime", nil))

	// Then
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
	if envelope.Data.Content != "" {
		t.Fatalf("巨行中段应输出为空（与 GetAppLogs 同口径）, got %d 字节（首 64 字符: %q）",
			len(envelope.Data.Content), logContentPreview(envelope.Data.Content, 64))
	}
}

// GetCaddyLogs 残段形状（镜像 SYSB44-3 夹具）：起点恰落在「中」（3 字节）的
// 第 2 字节——首行残段整体丢弃，输出恰为后续完整行，零 U+FFFD 污染。
func TestGetCaddyLogs_tailWindowDropsFirstLineFragment(t *testing.T) {
	// Given
	const maxBytes = 128 * 1024
	pad := strings.Repeat("a", 100) + "\n"               // 101 字节
	boundaryRune := "中"                                  // 占字节 101/102/103
	restOfBoundaryLine := strings.Repeat("c", 50) + "\n" // 边界行残余部分
	targetTotal := len(pad) + 1 + maxBytes               // startOffset=102=「中」第 2 字节
	fillerLen := targetTotal - len(pad) - len(boundaryRune) - len(restOfBoundaryLine)
	var fb strings.Builder
	longLine := strings.Repeat("d", 299) + "\n" // 300 字节长行,行数 <<500
	for fb.Len()+len(longLine) <= fillerLen {
		fb.WriteString(longLine)
	}
	if remaining := fillerLen - fb.Len(); remaining > 0 {
		fb.WriteString(strings.Repeat("e", remaining-1) + "\n")
	}
	filler := fb.String()
	if fillerLen <= 0 || len(filler) != fillerLen {
		t.Fatalf("夹具构造错误: fillerLen=%d len(filler)=%d", fillerLen, len(filler))
	}
	h := newBackupTestHandlers(t)
	logPath := filepath.Join(t.TempDir(), "caddy.log")
	if err := os.WriteFile(logPath, []byte(pad+boundaryRune+restOfBoundaryLine+filler), 0o644); err != nil {
		t.Fatalf("write log: %v", err)
	}
	oldPaths := caddyLogPaths
	caddyLogPaths = map[string]string{"runtime": logPath}
	t.Cleanup(func() { caddyLogPaths = oldPaths })

	gin.SetMode(gin.TestMode)
	router := gin.New()
	router.GET("/caddy/logs", h.GetCaddyLogs)
	response := httptest.NewRecorder()

	// When
	router.ServeHTTP(response, httptest.NewRequest(http.MethodGet, "/caddy/logs?type=runtime", nil))

	// Then
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
	if strings.Contains(envelope.Data.Content, string(rune(0xFFFD))) {
		t.Fatalf("输出含 U+FFFD 替换符——窗口起点切断多字节 rune,残段污染首行（首 64 字符: %q）", logContentPreview(envelope.Data.Content, 64))
	}
	if envelope.Data.Content != filler {
		t.Fatalf("输出须恰好为截断后的完整行内容: 长度=%d, want %d（首行残段整体丢弃）", len(envelope.Data.Content), len(filler))
	}
}

// logContentPreview 截取日志内容预览（LBH79-历史问题）：断言失败消息里直接
// content[:64] 会在内容不足 64 字节（含空串）时 panic，掩盖真实诊断。
func logContentPreview(content string, limit int) string {
	if limit <= 0 {
		return ""
	}
	runes := []rune(content)
	if len(runes) > limit {
		return string(runes[:limit]) + "…"
	}
	return string(runes)
}

func TestLogContentPreview_shortContentDoesNotPanic(t *testing.T) {
	if got := logContentPreview("short", 64); got != "short" {
		t.Fatalf("preview=%q, want short", got)
	}
	if got := logContentPreview("", 64); got != "" {
		t.Fatalf("preview=%q, want empty", got)
	}
	if got := logContentPreview("abcdef", 3); got != "abc…" {
		t.Fatalf("preview=%q, want abc…", got)
	}
}

// 历史问题（历史 历史问题，族内一致性）：GetCaddyLogs 先 os.Stat 得 size 再
// Seek(size-128KB) 后 io.ReadAll(f) 无 LimitReader——Stat 与 Read 之间日志
// 增长时本次返回可超 128KB 上限（certjobs.readCertJobLogFile 同族已用
// io.LimitReader）。测试钩子在 Stat 之后追加 200KB，钉住读取严格受窗口约束。
func TestGetCaddyLogs_capsWindowReadAt128KB(t *testing.T) {
	h := newBackupTestHandlers(t)
	logPath := filepath.Join(t.TempDir(), "caddy.log")
	line := strings.Repeat("a", 1023) + "\n" // 1024 字节/行
	writeLines := func(n int) {
		t.Helper()
		var builder strings.Builder
		for builder.Len() < n {
			builder.WriteString(line)
		}
		f, err := os.OpenFile(logPath, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o644)
		if err != nil {
			t.Fatalf("open log: %v", err)
		}
		if _, err := f.WriteString(builder.String()); err != nil {
			f.Close()
			t.Fatalf("append log: %v", err)
		}
		if err := f.Close(); err != nil {
			t.Fatalf("close log: %v", err)
		}
	}
	writeLines(300 * 1024)
	oldPaths := caddyLogPaths
	caddyLogPaths = map[string]string{"runtime": logPath}
	t.Cleanup(func() { caddyLogPaths = oldPaths })
	oldHook := caddyLogsStatHook
	// Stat 与读取之间的增长窗口：追加 200KB（轮转滞后/高流量形态）。
	caddyLogsStatHook = func() { writeLines(200 * 1024) }
	t.Cleanup(func() { caddyLogsStatHook = oldHook })

	gin.SetMode(gin.TestMode)
	router := gin.New()
	router.GET("/caddy/logs", h.GetCaddyLogs)
	response := httptest.NewRecorder()
	router.ServeHTTP(response, httptest.NewRequest(http.MethodGet, "/caddy/logs?type=runtime", nil))
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
	if len(envelope.Data.Content) > 128*1024 {
		t.Fatalf("content=%d 字节, want ≤128KB（Stat/Read 窗口增长必须受 LimitReader 约束）", len(envelope.Data.Content))
	}
	if envelope.Data.Content == "" {
		t.Fatal("content 为空——夹具日志应命中完整行窗口")
	}
}
