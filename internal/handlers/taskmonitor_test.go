package handlers

// 任务监控 handlers 测试（v2.3.4）：聚合形状、触发映射、取消语义、暂停开关、
// 主节点门。直接 handler 调用（与既有测试同模式——鉴权由路由组中间件承担，
// 此处测 handler 内的门与映射）。

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/gin-gonic/gin"

	"lazy-balancer-v2/internal/db"
	"lazy-balancer-v2/internal/services"
)

func initTaskEngineForTest(t *testing.T) {
	t.Helper()
	if services.TaskEngine() == nil {
		oldDB, oldM, oldA := db.DB, db.MetricsDB, db.AuditDB
		if err := db.Initialize(t.TempDir()); err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() {
			services.StopTaskEngine()
			_ = db.Close()
			db.DB, db.MetricsDB, db.AuditDB = oldDB, oldM, oldA
		})
		services.InitTaskEngine("", t.TempDir()+"/app.log")
	}
}

func taskMonitorRouter() (*gin.Engine, *Handlers) {
	gin.SetMode(gin.TestMode)
	h := &Handlers{}
	r := gin.New()
	r.GET("/system/tasks", h.ListSystemTasks)
	r.POST("/system/tasks/:id/trigger", h.TriggerSystemTask)
	r.POST("/system/tasks/:id/toggle", h.ToggleSystemTask)
	r.POST("/system/tasks/:id/cancel", h.CancelSystemTask)
	return r, h
}

// Given 空库（迁移种子三威胁源）。
// Then 聚合返回全部 8 个任务族，字段形状完整，threat 含三源摘要。
func TestListSystemTasks_allFamiliesPresent(t *testing.T) {
	newBackupTestHandlers(t)
	initTaskEngineForTest(t)
	r, _ := taskMonitorRouter()
	resp := httptest.NewRecorder()
	r.ServeHTTP(resp, httptest.NewRequest(http.MethodGet, "/system/tasks", nil))
	if resp.Code != http.StatusOK {
		t.Fatalf("status=%d body=%s", resp.Code, resp.Body.String()[:min(300, len(resp.Body.String()))])
	}
	var payload struct {
		Data struct {
			Tasks []struct {
				ID       string `json:"id"`
				Name     string `json:"name"`
				Category string `json:"category"`
				Kind     string `json:"kind"`
				Status   string `json:"status"`
				Enabled  bool   `json:"enabled"`
			} `json:"tasks"`
		} `json:"data"`
	}
	if err := json.Unmarshal(resp.Body.Bytes(), &payload); err != nil {
		t.Fatal(err)
	}
	got := map[string]string{}
	for _, tk := range payload.Data.Tasks {
		got[tk.ID] = tk.Category
	}
	want := []string{"threat", "crs", "ip2region", "auto-backup", "cluster-sync", "config-watchdog", "audit-retention", "security-events-ingestion", "log-cleanup", "cert-renewal-scan", "startup:config-load"}
	for _, id := range want {
		if _, ok := got[id]; !ok {
			t.Fatalf("任务族 %s 缺失; got=%v", id, got)
		}
	}
	if got["threat"] != "安全防护" || got["cert-renewal-scan"] != "证书" || got["startup:config-load"] != "系统" {
		t.Fatalf("分类错配: %v", got)
	}
}

// 不可触发族 → 400；从节点 → 403。
func TestTriggerSystemTask_gatesAndMapping(t *testing.T) {
	initTaskEngineForTest(t)
	newBackupTestHandlers(t)
	r, _ := taskMonitorRouter()

	// cert-queue 不支持触发 → 400
	resp := httptest.NewRecorder()
	r.ServeHTTP(resp, httptest.NewRequest(http.MethodPost, "/system/tasks/cert-queue/trigger", nil))
	if resp.Code != http.StatusBadRequest {
		t.Fatalf("cert-queue 触发应 400, got %d", resp.Code)
	}

	// 从节点 → 403
	if _, err := db.DB.Exec(`UPDATE global_config SET is_master=0 WHERE id=1`); err != nil {
		t.Fatal(err)
	}
	resp2 := httptest.NewRecorder()
	r.ServeHTTP(resp2, httptest.NewRequest(http.MethodPost, "/system/tasks/crs/trigger", nil))
	if resp2.Code != http.StatusForbidden {
		t.Fatalf("从节点触发应 403, got %d", resp2.Code)
	}
}

// toggle：v2.0 统一调度开关——threat 关调度 → 200 + 引擎循环态翻转
// （业务自动更新开关不受影响——那是安全设置页的字段）。
func TestToggleSystemTask_threatSwitch(t *testing.T) {
	initTaskEngineForTest(t)
	newBackupTestHandlers(t)
	if _, err := db.DB.Exec(`UPDATE global_config SET is_master=1, threat_auto_update=1 WHERE id=1`); err != nil {
		t.Fatal(err)
	}
	services.InitThreatUpdateManager()
	te := services.TaskEngine()
	r, _ := taskMonitorRouter()
	resp := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/system/tasks/threat/toggle", strings.NewReader(`{"enabled":false}`))
	req.Header.Set("Content-Type", "application/json")
	r.ServeHTTP(resp, req)
	if resp.Code != http.StatusOK {
		t.Fatalf("toggle status=%d body=%s", resp.Code, resp.Body.String())
	}
	if te.IsRunning("threat") {
		t.Fatal("toggle off 后 threat 调度应关闭（IsRunning=false）")
	}
	if !services.ThreatAutoUpdateEnabled() {
		t.Fatal("业务自动更新开关不应被调度开关联动（v2.0 两层独立）")
	}
	// 恢复（避免污染其他测试）
	te.StartLoop("threat")
}

// cancel：未运行 → 409；非下载类 → 400。
func TestCancelSystemTask_semantics(t *testing.T) {
	initTaskEngineForTest(t)
	newBackupTestHandlers(t)
	r, _ := taskMonitorRouter()

	// auto-backup Cancelable=false → 引擎 Cancel 返 false → 409
	resp := httptest.NewRecorder()
	r.ServeHTTP(resp, httptest.NewRequest(http.MethodPost, "/system/tasks/auto-backup/cancel", nil))
	if resp.Code != http.StatusConflict {
		t.Fatalf("auto-backup 取消（不可取消族）应 409, got %d", resp.Code)
	}

	// threat 未运行 → 409
	services.InitThreatUpdateManager()
	resp2 := httptest.NewRecorder()
	r.ServeHTTP(resp2, httptest.NewRequest(http.MethodPost, "/system/tasks/threat/cancel", nil))
	if resp2.Code != http.StatusConflict {
		t.Fatalf("未运行取消应 409, got %d body=%s", resp2.Code, resp2.Body.String())
	}
}
