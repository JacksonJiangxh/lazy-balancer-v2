package handlers

// 行为钉：规则指标历史端点属 business 组（任意登录用户可读），5xx
// 只回固定文案——底层错误（SQL 文本/表列名/数据目录路径）只进运行日志。

import (
	"database/sql"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/gin-gonic/gin"

	"lazy-balancer-v2/internal/db"
)

func TestGetRuleMetricsHistory_5xxHidesInternalError(t *testing.T) {
	initializeRuleFeatureTestDB(t)
	if _, err := db.DB.Exec(`INSERT INTO lb_rules (caddy_id,name,protocol,domain,listen_port,enabled)
		VALUES ('lb_metrics_5xx','metrics-5xx','http','metrics5xx.example.test',8080,1)`); err != nil {
		t.Fatalf("seed rule: %v", err)
	}
	// MetricsDB 指向已关闭的库：查询必然失败且错误文本含驱动内部结构。
	closed, err := sql.Open("sqlite", t.TempDir()+"/metrics.db")
	if err != nil {
		t.Fatalf("open metrics db: %v", err)
	}
	if err := closed.Close(); err != nil {
		t.Fatalf("close metrics db: %v", err)
	}
	previous := db.MetricsDB
	db.MetricsDB = closed
	t.Cleanup(func() { db.MetricsDB = previous })

	gin.SetMode(gin.TestMode)
	router := gin.New()
	router.GET("/rules/:caddy_id/metrics-history", (&Handlers{}).GetRuleMetricsHistory)

	response := httptest.NewRecorder()
	router.ServeHTTP(response, httptest.NewRequest(http.MethodGet, "/rules/lb_metrics_5xx/metrics-history", nil))

	if response.Code != http.StatusInternalServerError {
		t.Fatalf("status=%d body=%s, want 500", response.Code, response.Body.String())
	}
	body := response.Body.String()
	if !strings.Contains(body, "读取历史指标失败") {
		t.Fatalf("body=%s, want 固定文案「读取历史指标失败」", body)
	}
	for _, leak := range []string{"database is closed", "sql:", ".db", "/var/", "/tmp/"} {
		if strings.Contains(body, leak) {
			t.Fatalf("body=%s, want 不含内部错误细节 %q", body, leak)
		}
	}
}
