package handlers

// 日志统计响应的字段契约：/logs/stats 不携带 cert_jobs_truncated——该披露位
// 只属于 /system/tasks（任务监控页消费），在日志统计响应里是无人消费的契约
// 噪声（历史同类：已删除的 coraza_audit 行）。含 task: 键的请求仍必须枚举任务
// 行（证书动态行照常出现）。

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/gin-gonic/gin"

	"lazy-balancer-v2/internal/db"
)

func TestGetLogStats_doesNotCarryTaskTruncationField(t *testing.T) {
	h := newBackupTestHandlers(t)
	initTaskEngineForTest(t)
	h.cfg.DataDir = t.TempDir()
	for i := range 3 {
		if _, err := db.DB.Exec(`INSERT INTO cert_jobs (rule_id, domain, status, created_at, updated_at) VALUES ('lb_keys',?, 'issued', datetime('now'), datetime('now'))`,
			"keys"+itoa64(int64(i))+".example.test"); err != nil {
			t.Fatalf("seed cert job %d: %v", i, err)
		}
	}

	gin.SetMode(gin.TestMode)
	router := gin.New()
	router.GET("/logs/stats", h.GetLogStats)

	for _, query := range []string{"", "?keys=task:cert-job:1", "?keys=runtime"} {
		rec := httptest.NewRecorder()
		router.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/logs/stats"+query, nil))
		if rec.Code != http.StatusOK {
			t.Fatalf("%s status=%d body=%s", query, rec.Code, rec.Body.String())
		}
		if strings.Contains(rec.Body.String(), "cert_jobs_truncated") {
			t.Fatalf("%s 响应仍携带 cert_jobs_truncated（孤儿字段，披露位归 /system/tasks）: %s", query, rec.Body.String())
		}
	}

	// 全量请求仍枚举证书动态行（字段删除不等于停止枚举）。
	rec := httptest.NewRecorder()
	router.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/logs/stats", nil))
	var resp struct {
		Data struct {
			Logs []struct {
				Key string `json:"key"`
			} `json:"logs"`
		} `json:"data"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatalf("decode: %v", err)
	}
	certJobRows := 0
	for _, row := range resp.Data.Logs {
		if strings.HasPrefix(row.Key, "task:cert-job:") {
			certJobRows++
		}
	}
	if certJobRows == 0 {
		t.Fatal("证书动态行缺失：删除截断字段不得停止任务族枚举")
	}
}
