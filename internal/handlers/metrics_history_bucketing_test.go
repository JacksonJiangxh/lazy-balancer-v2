package handlers

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/gin-gonic/gin"

	"lazy-balancer-v2/internal/db"
)

// U8a-P4-1（第 66 轮）：GET /metrics/history 无行数上限无分桶——默认配置
// 7 天窗可达 ~2 万行（5s 间隔更甚）。修复=镜像 get_rule_metrics_history 的
// 窗口函数分桶（每桶末行样本，≤720 桶上限）。

// Given 1h 窗内 1500 行全局指标（2s 间隔——密集采样形态）。
// When GET /api/v1/metrics/history?interval=1h。
// Then 返回行数 ≤720（今日全量 1500 行——RED）。
func TestGetMetricsHistory_bucketsDenseRowsToCap(t *testing.T) {
	newMetricsTestDatabase(t)
	h := &Handlers{}
	gin.SetMode(gin.TestMode)
	router := gin.New()
	router.GET("/api/v1/metrics/history", h.GetMetricsHistory)

	base := time.Now().UTC().Add(-1500 * 2 * time.Second)
	for i := 0; i < 1500; i++ {
		ts := base.Add(time.Duration(i*2) * time.Second).Format("2006-01-02 15:04:05")
		if _, err := db.MetricsDB.Exec(
			`INSERT INTO metrics_history (rule_id, timestamp, requests_total, requests_2xx, requests_3xx, requests_4xx, requests_5xx, bytes_in, bytes_out)
			 VALUES (NULL, ?, ?, ?, 0, 0, 0, 0, 0)`, ts, i, i); err != nil {
			t.Fatalf("seed row %d: %v", i, err)
		}
	}
	_ = fmt.Sprint()

	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/api/v1/metrics/history?interval=1h", nil)
	router.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("status=%d body=%s", rec.Code, rec.Body.String())
	}
	var resp struct {
		Data []map[string]any `json:"data"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if len(resp.Data) > 720 {
		t.Fatalf("metrics history rows=%d, want ≤720（密集窗必须分桶）", len(resp.Data))
	}
	if len(resp.Data) == 0 {
		t.Fatal("分桶后不应为空")
	}
}
