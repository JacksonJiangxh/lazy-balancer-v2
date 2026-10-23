package handlers

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/gin-gonic/gin"
	"lazy-balancer-v2/internal/config"
	"lazy-balancer-v2/internal/db"
)

// 500 响应只回固定文案：底层错误（SQL 文本/表列名、文件路径与 errno）
// 只进运行日志。这些端点属 business 组，任意登录用户可读，直出 err 会
// 暴露内部结构与文件布局。
func TestGetCrawlerLib_500BodyHidesSQLDetails(t *testing.T) {
	router := newCrawlerTestRouter(t)
	seedCrawlerSource(t, 1, "googlebot", 170)
	if _, err := db.DB.Exec(`DROP TABLE security_ip_lists`); err != nil {
		t.Fatal(err)
	}
	resp := httptest.NewRecorder()
	router.ServeHTTP(resp, httptest.NewRequest(http.MethodGet, "/security/crawler-lib", nil))

	if resp.Code != http.StatusInternalServerError {
		t.Fatalf("status=%d body=%s, want 500", resp.Code, resp.Body.String())
	}
	body := resp.Body.String()
	for _, leak := range []string{"security_ip_lists", "no such table", "SELECT", "sql:"} {
		if strings.Contains(body, leak) {
			t.Fatalf("500 body 泄露内部细节 %q: %s", leak, body)
		}
	}
	if !strings.Contains(body, "读取爬虫源失败") {
		t.Fatalf("500 body 缺少固定文案: %s", body)
	}
}

func TestGetAppLogs_500BodyHidesPathAndErrno(t *testing.T) {
	// Given：LOG_FILE 指向目录（stat 成功、读取失败 EISDIR）——错误文本
	// 原本会带上绝对路径与 errno。
	dir := t.TempDir()
	handler := &Handlers{cfg: &config.Config{LogFile: dir}}
	gin.SetMode(gin.TestMode)
	router := gin.New()
	router.GET("/system/logs", handler.GetAppLogs)
	resp := httptest.NewRecorder()

	// When
	router.ServeHTTP(resp, httptest.NewRequest(http.MethodGet, "/system/logs", nil))

	// Then
	if resp.Code != http.StatusInternalServerError {
		t.Fatalf("status=%d body=%s, want 500", resp.Code, resp.Body.String())
	}
	body := resp.Body.String()
	if strings.Contains(body, dir) || strings.Contains(body, "is a directory") {
		t.Fatalf("500 body 泄露路径/errno: %s", body)
	}
	if !strings.Contains(body, "读取日志失败") {
		t.Fatalf("500 body 缺少固定文案: %s", body)
	}
}
