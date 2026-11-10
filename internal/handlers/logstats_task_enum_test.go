package handlers

// 日志存储统计的单行轮询不得枚举任务族：只有请求含 task:<id> 行（或无 keys
// 的全量请求）才调 CollectSystemTasks（引擎 DescribeAll + cert_jobs 查询 +
// task_runs 统计）；此前单行请求也全量枚举，纯白付。

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/gin-gonic/gin"

	"lazy-balancer-v2/internal/services"
)

func TestGetLogStats_singleRowRequestDoesNotEnumerateTasks(t *testing.T) {
	h := newBackupTestHandlers(t)
	h.cfg.DataDir = t.TempDir()
	router := gin.New()
	router.GET("/logs/stats", h.GetLogStats)

	get := func(query string) {
		t.Helper()
		rec := httptest.NewRecorder()
		router.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/logs/stats"+query, nil))
		if rec.Code != http.StatusOK {
			t.Fatalf("status=%d body=%s", rec.Code, rec.Body.String())
		}
	}

	// Given 单行请求（日志弹框只看运行日志）。
	services.ResetCollectSystemTasksCallsForTest()
	get("?keys=runtime")

	// Then 不得触发任务族枚举。
	if calls := services.CollectSystemTasksCallsForTest(); calls != 0 {
		t.Fatalf("单行请求触发任务族枚举 %d 次, want 0", calls)
	}

	// When 请求含 task: 行。
	services.ResetCollectSystemTasksCallsForTest()
	get("?keys=task:autoban,runtime")

	// Then 必须枚举一次（逐任务日志行需要任务清单）。
	if calls := services.CollectSystemTasksCallsForTest(); calls != 1 {
		t.Fatalf("含 task: 行的请求枚举 %d 次, want 1", calls)
	}

	// And 全量请求（无 keys）仍枚举一次——旧全量语义不变。
	services.ResetCollectSystemTasksCallsForTest()
	get("")
	if calls := services.CollectSystemTasksCallsForTest(); calls != 1 {
		t.Fatalf("全量请求枚举 %d 次, want 1", calls)
	}
}
