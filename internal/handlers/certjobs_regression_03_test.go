package handlers

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"lazy-balancer-v2/internal/db"

	"github.com/gin-gonic/gin"
)

// 过期天数取整口径钉死——certjobs 与 certinfo.go:174 同表达式
// （int() 向零截断）。-int(Ceil(-x)) 与 floor(x) 恒等（空操作）未被
// 任何测试捕获；本表驱动测试按小时偏移断言全部边界形态。
func TestListCertJobs_daysRemainingTruncation(t *testing.T) {
	h := newBackupTestHandlers(t)
	gin.SetMode(gin.TestMode)
	router := gin.New()
	router.GET("/certificates/jobs", h.ListCertJobs)

	now := time.Now().UTC()
	cases := []struct {
		hoursRemaining float64 // 负=已过期
		wantDays       int
		wantStatus     string
	}{
		{-12, 0, "expired"},  // 过期半日 → -0（截断）
		{-23, 0, "expired"},  // 差一小时满一天 → 0
		{-24, -1, "expired"}, // 恰一天 → -1
		{-27, -1, "expired"}, // 1 天 3 小时 → -1
		{-47, -1, "expired"},
		{-72, -3, "expired"},
		{1, 0, "expiring"},  // 剩 1 小时 → 0（原 Ceil 为 1）
		{23, 0, "expiring"}, // 差一小时满一天 → 0（原 Ceil 为 1）
		{25, 1, "expiring"},
		{24*90 + 12, 90, "valid"}, // 90.5 天 → 90（非整日边界防微秒漂移），超默认 30 天临期窗 → valid
	}
	for _, tc := range cases {
		t.Run(fmt.Sprintf("%vH", tc.hoursRemaining), func(t *testing.T) {
			expires := now.Add(time.Duration(tc.hoursRemaining * float64(time.Hour)))
			if _, err := db.DB.Exec(`INSERT OR REPLACE INTO cert_jobs (id,rule_id,domain,status,expires_at) VALUES (9101,'lb_trunc','trunc.test','issued',?)`,
				expires.Format("2006-01-02 15:04:05")); err != nil {
				t.Fatalf("seed: %v", err)
			}
			recorder := httptest.NewRecorder()
			router.ServeHTTP(recorder, httptest.NewRequest(http.MethodGet, "/certificates/jobs?page=1&page_size=50", nil))
			if recorder.Code != http.StatusOK {
				t.Fatalf("status=%d body=%s", recorder.Code, recorder.Body.String())
			}
			body := recorder.Body.String()
			// 断言限定到该任务行窗口：同 body 内多行同值时全 body 匹配会命中
			// 他行（覆盖缺口伪装成通过）。
			idx := strings.Index(body, `"rule_id":"lb_trunc"`)
			if idx < 0 {
				t.Fatalf("seeded job not in response")
			}
			segment := body[idx:]
			window := segment[:min(len(segment), 600)]
			want := fmt.Sprintf(`"days_remaining":%d`, tc.wantDays)
			if !strings.Contains(window, want) {
				t.Fatalf("hours=%v: row 缺少 %q（截断口径被破坏？）: %s", tc.hoursRemaining, want, window)
			}
			if !strings.Contains(window, `"certificate_status":"`+tc.wantStatus+`"`) {
				t.Fatalf("hours=%v: certificate_status != %q near rule row", tc.hoursRemaining, tc.wantStatus)
			}
		})
	}
}
