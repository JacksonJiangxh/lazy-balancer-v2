package handlers

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/gin-gonic/gin"

	"lazy-balancer-v2/internal/services"
)

// 采集健康位必须覆盖三处消费面（事件列表/安全总览/威胁大屏）且同源：
// 三处都输出同一 services 快照对象的同名字段。
func TestSecurityOverviewAndThreatScreen_discloseIngestionHealth(t *testing.T) {
	setupSecurityPolicyTestDB(t)
	services.SecurityEventsSetIngestionHealthForTest(services.SecurityEventsIngestionStatus{
		Observed:            true,
		Healthy:             false,
		ConsecutiveFailures: 4,
		LastError:           "injected ingest failure",
	})
	t.Cleanup(func() { services.SecurityEventsSetIngestionHealthForTest(services.SecurityEventsIngestionStatus{}) })

	cases := []struct {
		name   string
		router *gin.Engine
		path   string
	}{
		{"overview", newSecurityEventsRouter(t), "/security/overview"},
		{"threat-screen", newThreatScreenRouter(t, newThreatMetricsServer(t).URL), "/security/overview/threat-screen?hours=24"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			w := httptest.NewRecorder()
			tc.router.ServeHTTP(w, httptest.NewRequest(http.MethodGet, tc.path, nil))
			if w.Code != http.StatusOK {
				t.Fatalf("%s status=%d body=%s", tc.name, w.Code, w.Body.String())
			}
			var resp struct {
				Data struct {
					Ingestion *services.SecurityEventsIngestionStatus `json:"ingestion"`
				} `json:"data"`
			}
			if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
				t.Fatalf("%s decode: %v", tc.name, err)
			}
			got := resp.Data.Ingestion
			if got == nil {
				t.Fatalf("%s response missing ingestion health: %s", tc.name, w.Body.String())
			}
			if got.Healthy || got.ConsecutiveFailures != 4 || got.LastError != "injected ingest failure" {
				t.Fatalf("%s ingestion=%+v, want the shared unhealthy snapshot", tc.name, got)
			}
			// 任务实态由 overlay 从 taskengine 读取（未装配=unknown），不得沿用
			// 注入快照里的旧值——字段契约是闭合的 running/stopped/unknown 三态。
			if got.TaskRunning || got.TaskState != "unknown" {
				t.Fatalf("%s ingestion task state=%q running=%v, want unknown（未装配引擎）", tc.name, got.TaskState, got.TaskRunning)
			}
		})
	}
}
