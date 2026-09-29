package handlers

// Round 62 第三批钉：更新日志同源——三端点读任务日志文件（单一数据源）。

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/gin-gonic/gin"

	"lazy-balancer-v2/internal/taskengine"
)

// Given tasks/crs.log 写入 tee 流水（单一数据源）。
// When GetCRSUpdateLogs 端点读取。
// Then 返回任务日志文件内容（规则集页弹框与任务监控同文件同内容）。
func TestGetCRSUpdateLogs_ReadsTaskLogFile(t *testing.T) {
	dir := t.TempDir()
	taskengine.SetLogDir(dir)
	t.Cleanup(func() { taskengine.SetLogDir("") })
	taskengine.TeeTaskLog("crs", "2026/09/29 23:00:00", "INFO", "checking", "查询最新 CRS 版本")

	h := newBackupTestHandlers(t)
	gin.SetMode(gin.TestMode)
	router := gin.New()
	router.GET("/security/crs/update-logs", h.GetCRSUpdateLogs)
	req := httptest.NewRequest(http.MethodGet, "/security/crs/update-logs", nil)
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("status=%d", w.Code)
	}
	if !strings.Contains(w.Body.String(), "查询最新 CRS 版本") {
		t.Fatalf("更新日志端点应读任务日志文件（同源）: %s", w.Body.String())
	}
}
