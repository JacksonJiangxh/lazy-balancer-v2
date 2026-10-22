package handlers

// 任务监控 handlers 测试（v2.3.4）：聚合形状、触发映射、取消语义、暂停开关、
// 主节点门。直接 handler 调用（与既有测试同模式——鉴权由路由组中间件承担，
// 此处测 handler 内的门与映射）。

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/gin-gonic/gin"

	"lazy-balancer-v2/internal/db"
	"lazy-balancer-v2/internal/services"
	"lazy-balancer-v2/internal/taskengine"
)

func initTaskEngineForTest(t *testing.T) {
	t.Helper()
	if services.TaskEngine() == nil || services.TaskEngine().IsStopped() {
		oldDB, oldM, oldA := db.DB, db.MetricsDB, db.AuditDB
		if err := db.Initialize(t.TempDir()); err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() {
			services.StopTaskEngine()
			_ = db.Close()
			db.DB, db.MetricsDB, db.AuditDB = oldDB, oldM, oldA
			db.SetDB(oldDB)
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

// 历史端点与 trigger/toggle 同口径做注册存在性门；
// 已注册但零历史的任务仍返回 200 + 空数组。
func TestGetSystemTaskHistory_checksTaskExistence(t *testing.T) {
	newBackupTestHandlers(t)
	initTaskEngineForTest(t)
	te := services.TaskEngine()
	if err := te.Register(taskengine.Descriptor{
		ID: "history-empty", Family: "test", Name: "空历史任务", Kind: taskengine.KindOneshot, RunsOn: taskengine.RoleAny,
		Run: func(taskengine.RunContext) error { return nil },
	}); err != nil {
		t.Fatal(err)
	}
	router := gin.New()
	h := &Handlers{}
	router.GET("/system/tasks/:id/history", h.GetSystemTaskHistory)

	t.Run("unknown", func(t *testing.T) {
		recorder := httptest.NewRecorder()
		router.ServeHTTP(recorder, httptest.NewRequest(http.MethodGet, "/system/tasks/not-a-task/history", nil))
		if recorder.Code != http.StatusNotFound {
			t.Fatalf("不存在任务 status=%d body=%s, want 404", recorder.Code, recorder.Body.String())
		}
	})
	t.Run("registered empty", func(t *testing.T) {
		recorder := httptest.NewRecorder()
		router.ServeHTTP(recorder, httptest.NewRequest(http.MethodGet, "/system/tasks/history-empty/history", nil))
		if recorder.Code != http.StatusOK || !strings.Contains(recorder.Body.String(), `"runs":[]`) {
			t.Fatalf("已注册空历史 status=%d body=%s, want 200 runs=[]", recorder.Code, recorder.Body.String())
		}
	})
}

// Given 空库（迁移种子三威胁源）。
// Then 聚合返回全部任务族，字段形状完整，threat 含三源摘要。
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
				ID             string `json:"id"`
				Name           string `json:"name"`
				Category       string `json:"category"`
				Kind           string `json:"kind"`
				Status         string `json:"status"`
				BusinessDriven bool   `json:"business_driven"`
			} `json:"tasks"`
		} `json:"data"`
	}
	if err := json.Unmarshal(resp.Body.Bytes(), &payload); err != nil {
		t.Fatal(err)
	}
	// 任务视图只承载 loop_on，不暴露诊断字段 enabled。
	if strings.Contains(resp.Body.String(), `"enabled"`) {
		t.Error("任务列表 JSON 不应含 enabled 键（调度语义只由 loop_on 表达）")
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
	for _, tk := range payload.Data.Tasks {
		if tk.ID == "threat" && !tk.BusinessDriven {
			t.Error("threat 应标记 business_driven=true")
		}
		if tk.ID == "config-watchdog" && tk.BusinessDriven {
			t.Error("config-watchdog 不应标记 business_driven")
		}
	}
	if got["threat"] != "安全防护" || got["cert-renewal-scan"] != "证书" || got["startup:config-load"] != "系统" {
		t.Fatalf("分类错配: %v", got)
	}
}

func TestInitTaskEngineForTest_replacesStoppedEngine(t *testing.T) {
	// Given：全局引擎已被直接 Stop（模拟跨测试 stopped 残留）。
	initTaskEngineForTest(t)
	services.TaskEngine().Stop()

	// When：再次经测试装配初始化。
	initTaskEngineForTest(t)

	// Then：必须替换为新实例，后续 Trigger 不得返回 ErrEngineStopped。
	if services.TaskEngine().IsStopped() {
		t.Fatal("initTaskEngineForTest 复用了 stopped 引擎")
	}
	if err := services.TaskEngine().Trigger("log-cleanup", "manual", ""); err != nil {
		t.Fatalf("重建后 Trigger 仍失败: %v", err)
	}
}

func TestTaskWriteHandlers_slaveRejectedConsistently(t *testing.T) {
	// Given：从节点 DB 实态 + RoleAny 任务（排除 RunsOn 差异）。
	initTaskEngineForTest(t)
	newBackupTestHandlers(t)
	if _, err := db.DB.Exec(`UPDATE global_config SET is_master=0 WHERE id=1`); err != nil {
		t.Fatal(err)
	}
	gin.SetMode(gin.TestMode)
	h := &Handlers{}
	router := gin.New()
	router.POST("/system/tasks/:id/trigger", h.TriggerSystemTask)
	router.POST("/system/tasks/:id/toggle", h.ToggleSystemTask)
	router.POST("/system/tasks/:id/cancel", h.CancelSystemTask)
	router.POST("/system/tasks/:id/control", h.ControlSystemTask)
	for _, tc := range []struct{ name, path, body string }{
		{name: "trigger", path: "/system/tasks/log-cleanup/trigger", body: ""},
		{name: "toggle", path: "/system/tasks/log-cleanup/toggle", body: `{"enabled":true}`},
		{name: "cancel", path: "/system/tasks/cluster-sync/cancel", body: ""},
		{name: "control", path: "/system/tasks/cluster-sync/control", body: `{"action":"restart"}`},
	} {
		t.Run(tc.name, func(t *testing.T) {
			// When/Then：四个写端点都必须同步返回 403，不得在引擎异步错误前假成功。
			response := httptest.NewRecorder()
			router.ServeHTTP(response, httptest.NewRequest(http.MethodPost, tc.path, strings.NewReader(tc.body)))
			if response.Code != http.StatusForbidden {
				t.Fatalf("从节点写任务 status=%d body=%s，want 403", response.Code, response.Body.String())
			}
		})
	}
}

// 不可触发族 → 400；从节点 → 403。
func TestTriggerSystemTask_gatesAndMapping(t *testing.T) {
	initTaskEngineForTest(t)
	newBackupTestHandlers(t)
	r, _ := taskMonitorRouter()

	// 类型派生（2026-10-11 用户裁定，取代 ManualRun 白名单）：config-watchdog
	//（循环）类型派生可触发 → 200；常驻族（cluster-sync daemon）恒不可触发 →
	// 400「不支持手动触发（常驻族启停即可/镜像族）」。
	resp := httptest.NewRecorder()
	r.ServeHTTP(resp, httptest.NewRequest(http.MethodPost, "/system/tasks/config-watchdog/trigger", nil))
	if resp.Code != http.StatusOK {
		t.Fatalf("config-watchdog（循环，类型派生可触发）触发应 200, got %d: %s", resp.Code, resp.Body.String())
	}
	respDaemon := httptest.NewRecorder()
	r.ServeHTTP(respDaemon, httptest.NewRequest(http.MethodPost, "/system/tasks/cluster-sync/trigger", nil))
	if respDaemon.Code != http.StatusBadRequest {
		t.Fatalf("cluster-sync（常驻族）触发应 400, got %d", respDaemon.Code)
	}
	if !strings.Contains(respDaemon.Body.String(), "不支持手动触发（常驻族启停即可/镜像族）") {
		t.Fatalf("应命中 !CanTrigger 分支文案（常驻族恒不可触发）: %s", respDaemon.Body.String())
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

// toggle：业务驱动任务只读——threat 调度开关由业务页自动更新控制，
// 任务监控不得反写业务配置或另开第二入口。
func TestToggleSystemTask_threatBusinessDrivenReadOnly(t *testing.T) {
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
	if resp.Code != http.StatusBadRequest {
		t.Fatalf("业务驱动任务 toggle 应 400 read-only, got %d body=%s", resp.Code, resp.Body.String())
	}
	if !te.IsRunning("threat") {
		t.Fatal("只读拒绝不得改变既有调度运行态")
	}
	if !services.ThreatAutoUpdateEnabled() {
		t.Fatal("只读拒绝不得反写业务自动更新")
	}
}

// cancel：未运行 → 409；不可取消族 → 409（引擎 Cancel 返 false——handler
// 不再有 400 分支，回退 switch 已删，无引擎时统一 503）。
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

func TestToggleSystemTask_businessDrivenTasksReadOnly(t *testing.T) {
	cases := []struct {
		id    string
		table string
		col   string
	}{
		{"threat", "global_config", "threat_auto_update"},
		{"crs", "security_crs_version", "auto_update"},
		{"ip2region", "security_ip2region_version", "auto_update"},
		{"crawlerbot-update", "global_config", "crawler_auto_update"},
		{"auto-backup", "global_config", "auto_backup_enabled"},
		{"autoban", "global_config", "autoban_enabled"},
	}
	for _, tc := range cases {
		t.Run(tc.id, func(t *testing.T) {
			initTaskEngineForTest(t)
			newBackupTestHandlers(t)
			r, _ := taskMonitorRouter()
			te := services.TaskEngine()
			te.StopLoop(tc.id)
			if tc.table != "global_config" {
				if _, err := db.DB.Exec(`INSERT OR IGNORE INTO ` + tc.table + ` (id,version,auto_update) VALUES (1,'test',0)`); err != nil {
					t.Fatal(err)
				}
			}
			if _, err := db.DB.Exec(`UPDATE ` + tc.table + ` SET ` + tc.col + `=0`); err != nil {
				t.Fatal(err)
			}

			// When：试图从任务监控改变业务驱动任务调度
			resp := httptest.NewRecorder()
			r.ServeHTTP(resp, httptest.NewRequest(http.MethodPost, "/system/tasks/"+tc.id+"/toggle", strings.NewReader(`{"enabled":true}`)))

			// Then：只读拒绝，业务字段与 loop_on 均不得被反写
			if resp.Code != http.StatusBadRequest {
				t.Fatalf("status=%d body=%s, want 400 read-only", resp.Code, resp.Body.String())
			}
			var enabled int
			if err := db.DB.QueryRow(`SELECT ` + tc.col + ` FROM ` + tc.table).Scan(&enabled); err != nil {
				t.Fatal(err)
			}
			m, _ := te.Lookup(tc.id)
			if enabled != 0 || m.LoopOn {
				t.Fatalf("只读语义被破坏: business=%d loop_on=%v", enabled, m.LoopOn)
			}
		})
	}
}

// 四个任务写端点的状态码统一——引擎未初始化 503、任务不存在 404
// （语义拒绝仍 400，见各端点既有用例）。
func TestTaskWriteHandlers_unifiedStatusCodes(t *testing.T) {
	initTaskEngineForTest(t)
	newBackupTestHandlers(t)
	gin.SetMode(gin.TestMode)
	h := &Handlers{}
	router := gin.New()
	router.POST("/system/tasks/:id/trigger", h.TriggerSystemTask)
	router.POST("/system/tasks/:id/toggle", h.ToggleSystemTask)
	router.POST("/system/tasks/:id/cancel", h.CancelSystemTask)
	router.POST("/system/tasks/:id/control", h.ControlSystemTask)

	writes := []struct{ name, path, body string }{
		{name: "trigger", path: "/system/tasks/no-such-task/trigger", body: ""},
		{name: "toggle", path: "/system/tasks/no-such-task/toggle", body: `{"enabled":true}`},
		{name: "cancel", path: "/system/tasks/no-such-task/cancel", body: ""},
		{name: "control", path: "/system/tasks/no-such-task/control", body: `{"action":"restart"}`},
	}

	// Given 引擎已初始化：未知任务 → 404
	for _, tc := range writes {
		t.Run("404/"+tc.name, func(t *testing.T) {
			resp := httptest.NewRecorder()
			router.ServeHTTP(resp, httptest.NewRequest(http.MethodPost, tc.path, strings.NewReader(tc.body)))
			if resp.Code != http.StatusNotFound {
				t.Fatalf("未知任务 status=%d body=%s, want 404", resp.Code, resp.Body.String())
			}
		})
	}

	// Given 引擎未初始化：四个端点 → 503（统一「任务引擎未初始化」语义）
	services.StopTaskEngine()
	for _, tc := range writes {
		t.Run("503/"+tc.name, func(t *testing.T) {
			resp := httptest.NewRecorder()
			router.ServeHTTP(resp, httptest.NewRequest(http.MethodPost, tc.path, strings.NewReader(tc.body)))
			if resp.Code != http.StatusServiceUnavailable {
				t.Fatalf("引擎未初始化 status=%d body=%s, want 503", resp.Code, resp.Body.String())
			}
		})
	}
}

func TestSystemTaskLogPath_certJobAndFallbackShapes(t *testing.T) {
	// Given 普通任务、有效/空 rule_id 的 cert-job，以及缺失与畸形 job id。
	newBackupTestHandlers(t)
	var validJobID, emptyRuleJobID int
	if err := db.DB.QueryRow(`INSERT INTO cert_jobs (rule_id,domain,status) VALUES ('lb_path','path.example','queued') RETURNING id`).Scan(&validJobID); err != nil {
		t.Fatal(err)
	}
	if err := db.DB.QueryRow(`INSERT INTO cert_jobs (rule_id,domain,status) VALUES ('','empty.example','queued') RETURNING id`).Scan(&emptyRuleJobID); err != nil {
		t.Fatal(err)
	}

	// When/Then 单条入口保持既有路径语义，批量解析重构不得改变这些形状。
	if got, err := systemTaskLogPath("crs"); err != nil || got != taskengine.TaskLogPath("crs") {
		t.Fatalf("ordinary task path=%q err=%v, want %q", got, err, taskengine.TaskLogPath("crs"))
	}
	if got, err := systemTaskLogPath(fmt.Sprintf("cert-job:%d", validJobID)); err != nil || got != services.CertJobLogPath("lb_path") {
		t.Fatalf("cert job path=%q err=%v, want %q", got, err, services.CertJobLogPath("lb_path"))
	}
	for _, id := range []string{fmt.Sprintf("cert-job:%d", emptyRuleJobID), "cert-job:999999", "cert-job:not-a-number"} {
		if got, err := systemTaskLogPath(id); err != nil || got != "" {
			t.Fatalf("%s path=%q err=%v, want empty path", id, got, err)
		}
	}

	oldDB := db.DB
	db.DB = nil
	db.SetDB(nil)
	t.Cleanup(func() { db.DB = oldDB; db.SetDB(oldDB) })
	if got, err := systemTaskLogPath(fmt.Sprintf("cert-job:%d", validJobID)); err != nil || got != "" {
		t.Fatalf("nil DB path=%q err=%v, want empty path", got, err)
	}
}

// 任务日志只读尾窗；偏移起点的残段（含整窗无换行的
// 巨型行）统一经 tailLogWindow 丢弃，小文件保持原样。
func TestGetSystemTaskLogs_boundedTailDropsPartialFirstLine(t *testing.T) {
	dir := t.TempDir()
	oldLogDir := taskengine.LogDir()
	taskengine.SetLogDir(dir)
	t.Cleanup(func() { taskengine.SetLogDir(oldLogDir) })
	h := &Handlers{}
	router := gin.New()
	router.GET("/system/tasks/:id/logs", h.GetSystemTaskLogs)

	for _, tc := range []struct {
		name    string
		content string
		want    string
	}{
		{name: "small unchanged", content: "first\nsecond\n", want: "first\nsecond\n"},
		{name: "partial line dropped", content: strings.Repeat("x", 256<<10) + "\ncomplete\n", want: "complete\n"},
		{name: "giant line window empty", content: strings.Repeat("x", (256<<10)+32), want: ""},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if err := os.WriteFile(taskengine.TaskLogPath("bounded"), []byte(tc.content), 0644); err != nil {
				t.Fatal(err)
			}
			response := httptest.NewRecorder()
			router.ServeHTTP(response, httptest.NewRequest(http.MethodGet, "/system/tasks/bounded/logs", nil))
			if response.Code != http.StatusOK {
				t.Fatalf("status=%d body=%s", response.Code, response.Body.String())
			}
			var payload struct {
				Data map[string]string `json:"data"`
			}
			if err := json.Unmarshal(response.Body.Bytes(), &payload); err != nil {
				t.Fatal(err)
			}
			if got := payload.Data["content"]; got != tc.want {
				t.Fatalf("content length=%d value=%q, want length=%d %q", len(got), got, len(tc.want), tc.want)
			}
		})
	}
}

func TestGetSystemTaskLogs_rotationBudgetUsesConcatenatedTail(t *testing.T) {
	const tail = 256 << 10
	fetchContent := func(t *testing.T, h *Handlers, taskID string) string {
		t.Helper()
		router := gin.New()
		router.GET("/system/tasks/:id/logs", h.GetSystemTaskLogs)
		response := httptest.NewRecorder()
		router.ServeHTTP(response, httptest.NewRequest(http.MethodGet, "/system/tasks/"+taskID+"/logs", nil))
		if response.Code != http.StatusOK {
			t.Fatalf("status=%d body=%s", response.Code, response.Body.String())
		}
		var payload struct {
			Data map[string]string `json:"data"`
		}
		if err := json.Unmarshal(response.Body.Bytes(), &payload); err != nil {
			t.Fatal(err)
		}
		return payload.Data["content"]
	}

	t.Run("plain task rotation is included in 256KiB budget", func(t *testing.T) {
		dir := t.TempDir()
		oldLogDir := taskengine.LogDir()
		taskengine.SetLogDir(dir)
		t.Cleanup(func() { taskengine.SetLogDir(oldLogDir) })
		path := taskengine.TaskLogPath("budget")
		rotation := strings.Repeat("old-line-0123456789\n", 200)
		active := strings.Repeat("active-line-123456789\n", 12000) + "ACTIVE-END\n"
		if err := os.WriteFile(path+".1", []byte(rotation), 0o644); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, []byte(active), 0o644); err != nil {
			t.Fatal(err)
		}
		content := fetchContent(t, &Handlers{}, "budget")
		if len(content) > tail {
			t.Fatalf("content=%d bytes, want ≤%d", len(content), tail)
		}
		if !strings.Contains(content, "ACTIVE-END") || strings.Contains(content, "old-line-") {
			t.Fatalf("want latest active tail only; len=%d", len(content))
		}
	})

	t.Run("cert-job five rotations share the same budget", func(t *testing.T) {
		h := newBackupTestHandlers(t)
		dir := t.TempDir()
		oldLogDir := taskengine.LogDir()
		taskengine.SetLogDir(dir)
		t.Cleanup(func() { taskengine.SetLogDir(oldLogDir) })
		var jobID int
		if err := db.DB.QueryRow(`INSERT INTO cert_jobs (rule_id,domain,status) VALUES ('lb_budget','budget.example','queued') RETURNING id`).Scan(&jobID); err != nil {
			t.Fatal(err)
		}
		path := services.CertJobLogPath("lb_budget")
		if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
			t.Fatal(err)
		}
		rotation := func(n int) string {
			return fmt.Sprintf("FILE%d-FIRST\n", n) + strings.Repeat(fmt.Sprintf("file%d-line-%s\n", n, strings.Repeat("x", 4800)), 20)
		}
		for i := 1; i <= 5; i++ {
			if err := os.WriteFile(fmt.Sprintf("%s.%d", path, i), []byte(rotation(i)), 0o644); err != nil {
				t.Fatal(err)
			}
		}
		active := "ACTIVE-FIRST\n" + strings.Repeat("active-line-"+strings.Repeat("y", 4800)+"\n", 20) + "ACTIVE-END\n"
		if err := os.WriteFile(path, []byte(active), 0o644); err != nil {
			t.Fatal(err)
		}
		content := fetchContent(t, h, fmt.Sprintf("cert-job:%d", jobID))
		if len(content) > tail {
			t.Fatalf("cert-job content=%d bytes, want ≤%d", len(content), tail)
		}
		if !strings.Contains(content, "ACTIVE-END") || strings.Contains(content, "FILE5-FIRST") || strings.Contains(content, "FILE4-FIRST") {
			t.Fatalf("want newest tail across five rotations; len=%d", len(content))
		}
	})

	t.Run("short rotations preserved verbatim", func(t *testing.T) {
		dir := t.TempDir()
		oldLogDir := taskengine.LogDir()
		taskengine.SetLogDir(dir)
		t.Cleanup(func() { taskengine.SetLogDir(oldLogDir) })
		path := taskengine.TaskLogPath("short")
		rotation := strings.Repeat("short-old-line\n", 200)
		active := "short-active-first\nshort-active-last\n"
		if err := os.WriteFile(path+".1", []byte(rotation), 0o644); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, []byte(active), 0o644); err != nil {
			t.Fatal(err)
		}
		if got, want := fetchContent(t, &Handlers{}, "short"), rotation+active; got != want {
			t.Fatalf("short content length=%d, want %d", len(got), len(want))
		}
	})
}

// 普通任务写侧只保留 1 份轮转副本，读侧不得按证书任务
// 扫描 .1～.5；仅最近 .1 前置到活动日志，避免读取不存在/越权保留代。
func TestGetSystemTaskLogs_includesOnlyLatestOrdinaryRotation(t *testing.T) {
	dir := t.TempDir()
	oldLogDir := taskengine.LogDir()
	taskengine.SetLogDir(dir)
	t.Cleanup(func() { taskengine.SetLogDir(oldLogDir) })
	path := taskengine.TaskLogPath("rotated")
	if err := os.WriteFile(path, []byte("current\n"), 0644); err != nil {
		t.Fatal(err)
	}
	for i := 1; i <= 5; i++ {
		if err := os.WriteFile(fmt.Sprintf("%s.%d", path, i), []byte(fmt.Sprintf("archive-%d\n", i)), 0644); err != nil {
			t.Fatal(err)
		}
	}
	h := &Handlers{}
	router := gin.New()
	router.GET("/system/tasks/:id/logs", h.GetSystemTaskLogs)
	response := httptest.NewRecorder()
	router.ServeHTTP(response, httptest.NewRequest(http.MethodGet, "/system/tasks/rotated/logs", nil))
	if response.Code != http.StatusOK {
		t.Fatalf("status=%d body=%s", response.Code, response.Body.String())
	}
	var payload struct {
		Data map[string]string `json:"data"`
	}
	if err := json.Unmarshal(response.Body.Bytes(), &payload); err != nil {
		t.Fatal(err)
	}
	want := "archive-1\ncurrent\n"
	if got := payload.Data["content"]; got != want {
		t.Fatalf("content=%q, want %q", got, want)
	}
}

// 同一响应的活动文件+轮转副本合计仍受 256KB 文档容量约束。
func TestGetSystemTaskLogs_rotationContentStaysWithinTailBudget(t *testing.T) {
	dir := t.TempDir()
	oldLogDir := taskengine.LogDir()
	taskengine.SetLogDir(dir)
	t.Cleanup(func() { taskengine.SetLogDir(oldLogDir) })
	path := taskengine.TaskLogPath("budgeted")
	line := strings.Repeat("a", 1023) + "\n"
	lastLine := strings.Repeat("b", 1024-len("active-tail\n")) + "active-tail\n"
	active := strings.Repeat(line, 255) + lastLine // 恰好 256KB，且均为完整行
	if len(active) != 256<<10 {
		t.Fatalf("fixture size=%d", len(active))
	}
	if err := os.WriteFile(path, []byte(active), 0644); err != nil {
		t.Fatal(err)
	}
	for i, content := range []string{"", "archive-one\n", "archive-two\n"} {
		if i == 0 {
			continue
		}
		if err := os.WriteFile(fmt.Sprintf("%s.%d", path, i), []byte(content), 0644); err != nil {
			t.Fatal(err)
		}
	}
	h := &Handlers{}
	router := gin.New()
	router.GET("/system/tasks/:id/logs", h.GetSystemTaskLogs)
	response := httptest.NewRecorder()
	router.ServeHTTP(response, httptest.NewRequest(http.MethodGet, "/system/tasks/budgeted/logs", nil))
	if response.Code != http.StatusOK {
		t.Fatalf("status=%d body=%s", response.Code, response.Body.String())
	}
	var payload struct {
		Data map[string]string `json:"data"`
	}
	if err := json.Unmarshal(response.Body.Bytes(), &payload); err != nil {
		t.Fatal(err)
	}
	content := payload.Data["content"]
	if len(content) > 256<<10 {
		t.Fatalf("活动+轮转内容=%d bytes, want <= %d", len(content), 256<<10)
	}
	if !strings.Contains(content, "active-tail\n") {
		t.Fatal("容量截断不得丢失活动文件最新完整行")
	}
}

// 并发双击下「触发」审计行数必须等于实际 manual task_runs 行数——
// 审计只在 Trigger 成功后记录，CAS 落败者不得留下孤儿「触发」行。
func TestTriggerSystemTask_triggerAuditMatchesManualRuns(t *testing.T) {
	initTaskEngineForTest(t)
	newBackupTestHandlers(t)
	te := services.TaskEngine()
	entered := make(chan struct{}, 1)
	release := make(chan struct{})
	if err := te.Register(taskengine.Descriptor{
		ID: "audit-race-probe", Family: "t", Name: "审计竞态探针", Kind: taskengine.KindOneshot,
		Run: func(taskengine.RunContext) error {
			select {
			case entered <- struct{}{}:
			default:
			}
			<-release
			return nil
		},
	}); err != nil {
		t.Fatal(err)
	}
	r, _ := taskMonitorRouter()

	before := countTriggerAudit(t)
	rec1, rec2 := httptest.NewRecorder(), httptest.NewRecorder()
	done := make(chan struct{}, 2)
	go func() {
		r.ServeHTTP(rec1, httptest.NewRequest(http.MethodPost, "/system/tasks/audit-race-probe/trigger", nil))
		done <- struct{}{}
	}()
	go func() {
		r.ServeHTTP(rec2, httptest.NewRequest(http.MethodPost, "/system/tasks/audit-race-probe/trigger", nil))
		done <- struct{}{}
	}()
	<-done
	<-done
	<-entered
	close(release)

	var manualRuns int
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		if err := db.DB.QueryRow(`SELECT COUNT(*) FROM task_runs WHERE task_id='audit-race-probe' AND trigger='manual'`).Scan(&manualRuns); err == nil && manualRuns > 0 {
			break
		}
		time.Sleep(10 * time.Millisecond)
	}
	// Trigger 返回后异步写审计：按实际条件轮询至与 manual task_runs 收敛，
	// 不再固定等待 200ms。
	got := 0
	deadline = time.Now().Add(2 * time.Second)
	for {
		got = countTriggerAudit(t) - before
		if got == manualRuns {
			break
		}
		if got > manualRuns || time.Now().After(deadline) {
			t.Fatalf("「触发」审计=%d 与实际 manual task_runs=%d 不一致（孤儿/缺失审计）", got, manualRuns)
		}
		time.Sleep(10 * time.Millisecond)
	}
}
