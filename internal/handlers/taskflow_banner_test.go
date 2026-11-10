package handlers

// 任务流/横幅域修复钉测：退化提交两态横幅文案、规则 apply 失败横幅分类
// （配置拒绝不写 / 传输失败写）、任务日志轮转副本兜底、cert-job 日志路径单行查询。

import (
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"

	"github.com/gin-gonic/gin"

	"lazy-balancer-v2/internal/db"
	"lazy-balancer-v2/internal/services"
	"lazy-balancer-v2/internal/taskengine"
)

// Given finishTxApply 退化提交形态（传输失败：候选已 /load、响应断连）。
// When 事务提交成功。
// Then 横幅文案为「已保存但未生效」态——与「未保存（旧配置已保留）」分态，
// 防止管理员误读为「没保存」而重复提交。
func TestFinishTxApply_degradedCommitWritesSavedNotLiveBanner(t *testing.T) {
	h := newBackupTestHandlers(t)
	_, fake := newApplyThenDropServer(t, 1)
	h.caddyService = services.NewCaddyService(fake.URL)
	// CLI 校验可用（通过）——传输失败才走退化提交分支（CLI 不可用+
	// 传输失败=未校验回滚 500 分支，由既有钉测覆盖）。
	h.caddyService.SetCLIValidatorForTest(func([]byte) error { return nil })
	seedCommittedRuleForApplyTest(t, "lb_degraded", "committed.example.test")
	tx := beginPendingDomainTx(t, "lb_degraded")
	c, rec := newApplyTestContext()

	h.finishTxApply(c, tx, txApplyFinish{Resource: "安全策略", AuditAction: "更新", AuditDetail: "策略保存", SuccessMsg: "已保存"})

	if rec.Code != http.StatusOK {
		t.Fatalf("退化提交应 200 带告警, status=%d body=%s", rec.Code, rec.Body.String())
	}
	banner := readApplyError(t)
	if !strings.Contains(banner, "已保存") || !strings.Contains(banner, "未生效") {
		t.Fatalf("退化提交横幅应为「已保存但未生效」态, got %q", banner)
	}
	if strings.Contains(banner, "旧配置已保留") {
		t.Fatalf("退化提交横幅不得与「未保存」态共用文案, got %q", banner)
	}
}

// Given 规则更新的事务内 apply 被 Caddy 拒绝（CLI/admin 4xx）。
// When UpdateRule 走 apply 失败分支。
// Then 返回 400、DB 回滚、且不写 caddy_apply_error 横幅——配置拒绝时候选未
// /load、运行配置仍是提交前形态，库态与运行态无分叉；写横幅会让用户追一个
// 不存在的不一致（与 finishTxApply 拒绝分支同口径）。
func TestUpdateRule_configRejectionDoesNotPersistBanner(t *testing.T) {
	harness := newUpdateAuditRuleHandlers(t, "lb_banner", 1, false)
	handler := harness.handler
	seedAuditRule(t, "lb_banner", "before", "banner.example.test", 8080, true, "manual", false)
	seedAuditUpstream(t, "lb_banner")
	router := gin.New()
	router.PUT("/rules/:caddy_id", handler.UpdateRule)
	request := httptest.NewRequest(http.MethodPut, "/rules/lb_banner", strings.NewReader(`{"name":"after","domain":"banner-new.example.test"}`))
	request.Header.Set("Content-Type", "application/json")
	response := httptest.NewRecorder()

	router.ServeHTTP(response, request)

	// 夹具失败形态=Caddy 400 拒绝（IsConfigRejected）。
	if response.Code != http.StatusBadRequest {
		t.Fatalf("apply 拒绝应 400, status=%d body=%s", response.Code, response.Body.String())
	}
	if banner := readApplyError(t); banner != "" {
		t.Fatalf("配置拒绝不得写失败横幅（无分叉事实）, got %q", banner)
	}
	// 拒绝仍须留操作审计（Explicit 策略下中间件不补）。
	var auditCount int
	if err := db.AuditDB.QueryRow(`SELECT COUNT(*) FROM audit_log WHERE action='更新失败' AND resource='负载规则' AND detail LIKE '%Caddy 配置应用失败%'`).Scan(&auditCount); err != nil {
		t.Fatalf("count audit: %v", err)
	}
	if auditCount == 0 {
		t.Fatal("配置拒绝缺少操作审计")
	}
	// DB 回滚不破（同钉测家族口径）。
	var name string
	if err := db.DB.QueryRow("SELECT name FROM lb_rules WHERE caddy_id='lb_banner'").Scan(&name); err != nil {
		t.Fatal(err)
	}
	if name != "before" {
		t.Fatalf("apply 失败后 DB 应回滚, name=%q", name)
	}
}

// Given 规则更新的事务内 apply 传输失败（admin 5xx，非配置拒绝）。
// When UpdateRule 走 apply 失败分支。
// Then 持久化 caddy_apply_error 横幅——运行配置可能已吸收候选（传输错误
// 发生在请求断连/超时），刷新页面后分叉必须可见。
func TestUpdateRule_transportFailurePersistsBanner(t *testing.T) {
	handler, _ := newFailingLoadHandlers(t)
	seedAuditRule(t, "lb_banner_tx", "before", "banner-tx.example.test", 8080, true, "manual", false)
	seedAuditUpstream(t, "lb_banner_tx")
	router := gin.New()
	router.PUT("/rules/:caddy_id", handler.UpdateRule)
	request := httptest.NewRequest(http.MethodPut, "/rules/lb_banner_tx", strings.NewReader(`{"name":"after"}`))
	request.Header.Set("Content-Type", "application/json")
	response := httptest.NewRecorder()

	router.ServeHTTP(response, request)

	if response.Code != http.StatusInternalServerError {
		t.Fatalf("传输失败应 500, status=%d body=%s", response.Code, response.Body.String())
	}
	banner := readApplyError(t)
	if !strings.Contains(banner, "Caddy 配置应用失败") || !strings.Contains(banner, caddyApplyOldConfigKeptLabel) {
		t.Fatalf("传输失败未持久化「旧配置已保留」横幅, got %q", banner)
	}
}

// Given 活动任务日志缺失、轮转副本 .1 有内容（外部删除活动文件，或轮转
// rename 完成后写入失败）。
// When GetSystemTaskLogs。
// Then 返回轮转副本内容而非空页。
func TestGetSystemTaskLogs_readsRotatedCopyWhenActiveMissing(t *testing.T) {
	h := newBackupTestHandlers(t)
	dir := t.TempDir()
	taskengine.SetLogDir(dir)
	t.Cleanup(func() { taskengine.SetLogDir("") })
	if err := os.WriteFile(filepath.Join(dir, "threat.log.1"), []byte("2026/10/22 03:00:00 [INFO] update - 轮转副本行\n"), 0644); err != nil {
		t.Fatal(err)
	}

	gin.SetMode(gin.TestMode)
	router := gin.New()
	router.GET("/system/tasks/:id/logs", h.GetSystemTaskLogs)
	recorder := httptest.NewRecorder()
	router.ServeHTTP(recorder, httptest.NewRequest(http.MethodGet, "/system/tasks/threat/logs", nil))

	if recorder.Code != http.StatusOK {
		t.Fatalf("status=%d body=%s, want 200", recorder.Code, recorder.Body.String())
	}
	if !strings.Contains(recorder.Body.String(), "轮转副本行") {
		t.Fatalf("活动文件缺失时应返回轮转副本内容, body=%s", recorder.Body.String())
	}
}

// Given cert_jobs 在册行。
// When 单条日志路径解析（日志弹框/MCP 入口）。
// Then 单行查询命中映射到规则证书日志路径；未知/非法 id 为空串（与批量
// resolver 的 map-miss 语义一致）。
func TestSystemTaskLogPath_singleRowLookup(t *testing.T) {
	newBackupTestHandlers(t)
	dir := t.TempDir()
	taskengine.SetLogDir(dir)
	t.Cleanup(func() { taskengine.SetLogDir("") })
	result, err := db.DB.Exec(`INSERT INTO cert_jobs (rule_id, domain, status, created_at, updated_at)
		VALUES ('lb_t10','t10.example.test','queued','2026-10-20T04:00:00Z','2026-10-20T04:00:00Z')`)
	if err != nil {
		t.Fatalf("seed cert job: %v", err)
	}
	jobID, _ := result.LastInsertId()

	path, err := systemTaskLogPath("cert-job:" + strconv.FormatInt(jobID, 10))
	if err != nil {
		t.Fatalf("resolve: %v", err)
	}
	if path != services.CertJobLogPath("lb_t10") {
		t.Fatalf("cert-job 日志路径=%q, want %q", path, services.CertJobLogPath("lb_t10"))
	}
	if p, err := systemTaskLogPath("cert-job:999999"); err != nil || p != "" {
		t.Fatalf("未知 job 应解析为空串, got %q err=%v", p, err)
	}
	if p, err := systemTaskLogPath("cert-job:bad"); err != nil || p != "" {
		t.Fatalf("非法 job id 应解析为空串, got %q err=%v", p, err)
	}
	// 普通注册任务不受影响。
	if p, err := systemTaskLogPath("threat"); err != nil || p != taskengine.TaskLogPath("threat") {
		t.Fatalf("普通任务路径=%q err=%v, want %q", p, err, taskengine.TaskLogPath("threat"))
	}
}
