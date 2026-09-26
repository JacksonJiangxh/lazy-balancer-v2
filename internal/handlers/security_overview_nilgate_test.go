package handlers

import (
	"encoding/json"
	"net/http"
	"testing"

	"lazy-balancer-v2/internal/db"
	"lazy-balancer-v2/internal/models"
)

// 第 59 轮 R59-P3（U1-1）：GetSecurityOverview 在 MetricsDB==nil 时必须返回
// 空面板 200 而非 nil 解引用 panic——对齐第 57 轮 P5-4 家族口径
// （ListSecurityEvents:3088 / GetIPEventCount:2977 / GetRuleStageStats）。
func TestGetSecurityOverview_metricsDBNilReturnsEmptyPanel(t *testing.T) {
	setupSecurityPolicyTestDB(t)
	router := newSecurityEventsRouter(t)

	saved := db.MetricsDB
	db.MetricsDB = nil
	t.Cleanup(func() { db.MetricsDB = saved })

	recorder := getRequest(t, router, "/security/overview")
	if recorder.Code != http.StatusOK {
		t.Fatalf("overview status=%d body=%s", recorder.Code, recorder.Body.String())
	}
	var resp struct {
		Code int                     `json:"code"`
		Data models.SecurityOverview `json:"data"`
	}
	if err := json.Unmarshal(recorder.Body.Bytes(), &resp); err != nil {
		t.Fatal(err)
	}
	if resp.Data.TodayBlocked != 0 || resp.Data.TodayDetected != 0 || len(resp.Data.Trend) != 0 {
		t.Fatalf("空面板应为零值: %+v", resp.Data)
	}
}
