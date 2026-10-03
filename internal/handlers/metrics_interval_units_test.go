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

// Review66-Head 发现 ①（2026-10-03 用户裁定核实后全修）：
// metricsIntervalSeconds 的 m 单位漏乘 60——30m 窗口被算成 30s，桶宽钳位
// 1s，升序 LIMIT 720 保留最旧桶，静默丢弃最近数据。

func TestMetricsIntervalSeconds_unitAgreement(t *testing.T) {
	cases := []struct {
		in   string
		want int64
	}{
		{"30m", 1800},
		{"10080m", 604800},
		{"2h", 7200},
		{"7d", 604800},
		{"", 3600},
	}
	for _, c := range cases {
		if got := metricsIntervalSeconds(c.in); got != c.want {
			t.Errorf("metricsIntervalSeconds(%q)=%d, want %d（与 modifier 同解析同上限）", c.in, got, c.want)
		}
	}
}

// 端到端形状：30m 窗口 1500 行（2s 间隔，最新行贴近 now）→ 分桶后必须
// 覆盖到最近（最新桶时间戳在 60s 内）——今日返回最旧 720 桶（RED）。
func TestGetMetricsHistory_miniteWindowKeepsRecentData(t *testing.T) {
	newMetricsTestDatabase(t)
	h := &Handlers{}
	gin.SetMode(gin.TestMode)
	router := gin.New()
	router.GET("/api/v1/metrics/history", h.GetMetricsHistory)
	_ = fmt.Sprint()
	for i := 0; i < 1500; i++ {
		ts := time.Now().UTC().Add(-time.Duration(i*2) * time.Second).Format("2006-01-02 15:04:05")
		if _, err := db.MetricsDB.Exec(
			`INSERT INTO metrics_history (rule_id, timestamp, requests_total, requests_2xx, requests_3xx, requests_4xx, requests_5xx, bytes_in, bytes_out)
			 VALUES (NULL, ?, ?, ?, 0, 0, 0, 0, 0)`, ts, 1500-i, 1500-i); err != nil {
			t.Fatalf("seed row %d: %v", i, err)
		}
	}
	rec := httptest.NewRecorder()
	router.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/api/v1/metrics/history?interval=30m", nil))
	if rec.Code != http.StatusOK {
		t.Fatalf("status=%d body=%s", rec.Code, rec.Body.String())
	}
	var resp struct {
		Data []struct {
			Timestamp time.Time `json:"timestamp"`
		} `json:"data"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatal(err)
	}
	if len(resp.Data) == 0 || len(resp.Data) > 720 {
		t.Fatalf("rows=%d, want 1..720", len(resp.Data))
	}
	last := resp.Data[len(resp.Data)-1].Timestamp
	if time.Since(last) > 60*time.Second {
		t.Fatalf("最新桶 %v 距 now %v——30m 窗口不得静默丢弃最近数据（最旧 720 桶形态）", last, time.Since(last))
	}
}
