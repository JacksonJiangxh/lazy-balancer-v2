package services

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"lazy-balancer-v2/internal/db"
	"lazy-balancer-v2/internal/taskengine"
)

// useCertSweepTickTestEnv 注入独立 DB 与任务日志目录，并清空活动证书服务
// （清理恢复原值）。供孤儿清扫计数与证书循环空转日志测试共用。
func useCertSweepTickTestEnv(t *testing.T) {
	t.Helper()
	oldDB, oldMetricsDB, oldAuditDB := db.DB, db.MetricsDB, db.AuditDB
	if err := db.Initialize(t.TempDir()); err != nil {
		t.Fatalf("init db: %v", err)
	}
	oldDir := taskengine.LogDir()
	taskengine.SetLogDir(filepath.Join(t.TempDir(), "logs", "tasks"))
	t.Cleanup(func() {
		db.DB, db.MetricsDB, db.AuditDB = oldDB, oldMetricsDB, oldAuditDB
		taskengine.SetLogDir(oldDir)
		SetActiveCertificateService(nil)
		lastCertServiceMissing.Store(false)
	})
	SetActiveCertificateService(nil)
	lastCertServiceMissing.Store(false)
}

func seedOrphanCertJob(t *testing.T, ruleID, domain, status string) int {
	t.Helper()
	result, err := db.DB.Exec(`INSERT INTO cert_jobs (rule_id,domain,status) VALUES (?,?,?)`, ruleID, domain, status)
	if err != nil {
		t.Fatalf("seed cert job (%s,%s,%s): %v", ruleID, domain, status, err)
	}
	id, err := result.LastInsertId()
	if err != nil {
		t.Fatalf("read seeded job id: %v", err)
	}
	return int(id)
}

func TestCertJobsActive_nilDBSkipsWithoutMaskingQueryErrors(t *testing.T) {
	useCertSweepTickTestEnv(t)
	seedOrphanCertJob(t, "lb_nil_guard", "nil-guard.example.test", "queued")
	if !certJobsActive() {
		t.Fatal("non-terminal certificate job was not reported active")
	}

	// Given/When：DB 尚未装配的启动窗口。
	database := db.DB
	db.DB = nil

	// Then：按无活处理并静默跳过，不得 nil dereference。
	if certJobsActive() {
		t.Fatal("nil database must not report certificate work as runnable")
	}
	CertWaitingCATickOnce()

	// 回归：普通查询错误仍维持「宁扫勿漏」，不被 nil 守卫吞掉。
	db.DB = database
	if err := database.Close(); err != nil {
		t.Fatalf("close test database: %v", err)
	}
	if !certJobsActive() {
		t.Fatal("query errors must retain fail-visible active=true safety semantics")
	}
}

// 历史问题-02：sweepOrphanedCertJobs 返回值必须等于实际收敛的孤儿任务数——
// CertReconcileOnce 的「孤儿清理 %d 个」任务日志行直接消费该值，swept 恒 0
// 使对账轮永远上报「清理 0 个」。
func TestSweepOrphanedCertJobs_countsDisabledOrphans(t *testing.T) {
	useCertSweepTickTestEnv(t)

	// Given：两条指向不存在规则的孤儿任务（queued + waiting_ca），外加一条
	// 已 disabled 的孤儿（终态：不扫、不计数）
	queuedID := seedOrphanCertJob(t, "lb_ghost_a", "ghost-a.example.test", "queued")
	waitingID := seedOrphanCertJob(t, "lb_ghost_b", "ghost-b.example.test", "waiting_ca")
	disabledID := seedOrphanCertJob(t, "lb_ghost_c", "ghost-c.example.test", "disabled")

	// When
	swept := sweepOrphanedCertJobs(context.Background())

	// Then：计数=实际翻转行数；disabled 行不被触碰
	if swept != 2 {
		t.Fatalf("swept=%d, want 2（返回值必须等于实际收敛的孤儿任务数）", swept)
	}
	for _, tc := range []struct {
		id   int
		want string
	}{
		{queuedID, "disabled"},
		{waitingID, "disabled"},
		{disabledID, "disabled"},
	} {
		var status string
		if err := db.DB.QueryRow("SELECT status FROM cert_jobs WHERE id=?", tc.id).Scan(&status); err != nil {
			t.Fatalf("read job %d: %v", tc.id, err)
		}
		if status != tc.want {
			t.Fatalf("job %d status=%q, want %q", tc.id, status, tc.want)
		}
	}
}

// 历史问题-11 + 历史问题 收敛（2026-10-03 裁定）：证书服务缺失行收敛为状态变化——
// nil 持续期仅 false→true 转换记一次跳过行，持续缺失静默，恢复（true→false）
// 记一次恢复行；三个证书 tick 任务共享同一状态门（全局单例服务指针）。
// 设计变更披露：原 历史问题-11「每轮一行跳过说明」按新裁定收敛，非弱化。
func TestCertTicks_skipAndRecoveryLinesTransitionOnce(t *testing.T) {
	useCertSweepTickTestEnv(t)

	// 连续两轮 nil：仅一行跳过说明（原每轮一行）
	CertRenewalScanOnce()
	CertRenewalScanOnce()
	data, err := os.ReadFile(taskengine.TaskLogPath("cert-renewal-scan"))
	if err != nil {
		t.Fatalf("read task log: %v", err)
	}
	if got := strings.Count(string(data), "证书服务未运行，跳过本轮"); got != 1 {
		t.Fatalf("skip lines=%d, want 1（状态门：缺失期只记一次）: %q", got, string(data))
	}

	// 共享状态：第二个任务同处缺失期，不重复记行
	CertManualCheckOnce()
	if data, err := os.ReadFile(taskengine.TaskLogPath("cert-manual-poll")); err == nil && strings.Contains(string(data), "证书服务未运行") {
		t.Fatalf("共享状态门失效：cert-manual-poll 重复记缺失行: %q", string(data))
	}

	// 恢复：true→false 转换记一次恢复行，随后正常执行不再记
	resetCertificateServiceForTest(t)
	SetActiveCertificateService(NewCertificateService())
	CertRenewalScanOnce()
	data, err = os.ReadFile(taskengine.TaskLogPath("cert-renewal-scan"))
	if err != nil {
		t.Fatalf("reread task log: %v", err)
	}
	if got := strings.Count(string(data), "证书服务已恢复"); got != 1 {
		t.Fatalf("recovery lines=%d, want 1: %q", got, string(data))
	}
	CertRenewalScanOnce()
	data, err = os.ReadFile(taskengine.TaskLogPath("cert-renewal-scan"))
	if err != nil {
		t.Fatalf("reread task log: %v", err)
	}
	if got := strings.Count(string(data), "证书服务已恢复"); got != 1 {
		t.Fatalf("恢复后持续运行不得追加恢复行: got %d", got)
	}
}

// 历史问题-11（cert-waiting-ca 形态）+ 历史问题 收敛：门控放行（有非终态任务）但服务
// 未运行时记一次跳过行（状态门新文案）；门控拦截（全部终态）时保持静默
// （2026-09-29 裁定的零扫描门控不得被空转日志破坏）。
func TestCertWaitingCATickOnce_skipLineGatedOnActiveJobs(t *testing.T) {
	useCertSweepTickTestEnv(t)

	// 有非终态任务：门控放行，服务未运行 → 跳过行
	jobID := seedOrphanCertJob(t, "lb_ghost_tick", "ghost-tick.example.test", "queued")
	CertWaitingCATickOnce()
	data, err := os.ReadFile(taskengine.TaskLogPath("cert-waiting-ca"))
	if err != nil {
		t.Fatalf("read task log: %v", err)
	}
	if got := strings.Count(string(data), "证书服务未运行，跳过本轮"); got != 1 {
		t.Fatalf("skip lines=%d, want 1（有非终态任务且服务未运行须记一行）: %q", got, string(data))
	}

	// 全部终态：门控静默退出，不追加跳过行
	if _, err := db.DB.Exec("UPDATE cert_jobs SET status='disabled' WHERE id=?", jobID); err != nil {
		t.Fatalf("disable job: %v", err)
	}
	CertWaitingCATickOnce()
	data, err = os.ReadFile(taskengine.TaskLogPath("cert-waiting-ca"))
	if err != nil {
		t.Fatalf("reread task log: %v", err)
	}
	if got := strings.Count(string(data), "证书服务未运行，跳过本轮"); got != 1 {
		t.Fatalf("skip lines=%d, want 1（全终态时门控静默，不得追加空转行）", got)
	}
}

// 证书周期任务体此前把扫描/对账错误吞成日志（Once 无返回
// 值、Run 恒 return nil），DB 抖动时任务监控显示 success；reconcileMissingCertFiles
// 查询失败后摘要还报「状态对账完成 0」。修复后：读失败上抛 + 失败轮摘要写
// 「状态对账失败」而非「完成」。
func TestCertReconcileOnce_propagates_read_failure(t *testing.T) {
	useCertSweepTickTestEnv(t)
	// Given：cert_jobs 读故障（表缺失=迁移中断/库损坏形态）
	if _, err := db.DB.Exec(`DROP TABLE cert_jobs`); err != nil {
		t.Fatalf("drop cert_jobs: %v", err)
	}

	// When
	err := CertReconcileOnce()

	// Then 1：读失败上抛（Run 随之返回 error → task_runs 失败终态）
	if err == nil {
		t.Fatal("CertReconcileOnce err=nil, want 对账读故障上抛（fail-visible）")
	}
	// Then 2：失败轮摘要不得写「完成」
	data, readErr := os.ReadFile(taskengine.TaskLogPath("cert-reconcile"))
	if readErr != nil {
		t.Fatalf("read task log: %v", readErr)
	}
	if strings.Contains(string(data), "状态对账完成") {
		t.Fatalf("失败轮摘要谎报完成: %q", string(data))
	}
	if !strings.Contains(string(data), "状态对账失败") {
		t.Fatalf("失败轮摘要缺失「状态对账失败」: %q", string(data))
	}
}

// 回归形状：健康库上对账轮必须返回 nil 且照常写「完成」摘要——上抛改造不得把
// 正常轮次变成失败轮。
func TestCertReconcileOnce_healthy_round_reports_completion(t *testing.T) {
	useCertSweepTickTestEnv(t)

	if err := CertReconcileOnce(); err != nil {
		t.Fatalf("CertReconcileOnce err=%v, want nil", err)
	}
	data, err := os.ReadFile(taskengine.TaskLogPath("cert-reconcile"))
	if err != nil {
		t.Fatalf("read task log: %v", err)
	}
	if !strings.Contains(string(data), "状态对账完成") {
		t.Fatalf("健康轮摘要缺失「状态对账完成」: %q", string(data))
	}
}

// 续期扫描的候选查询/遍历失败必须上抛（此前只落任务日志，Run 恒 nil）。
func TestCertRenewalScanOnce_propagates_scan_failure(t *testing.T) {
	useCertSweepTickTestEnv(t)
	resetCertificateServiceForTest(t)
	SetActiveCertificateService(NewCertificateService())
	t.Cleanup(func() { SetActiveCertificateService(nil) })
	// Given：cert_jobs 读故障（CheckExpiration 候选查询失败）
	if _, err := db.DB.Exec(`DROP TABLE cert_jobs`); err != nil {
		t.Fatalf("drop cert_jobs: %v", err)
	}

	// When
	err := CertRenewalScanOnce()

	// Then：扫描失败上抛，且摘要不得写「扫描完成」
	if err == nil {
		t.Fatal("CertRenewalScanOnce err=nil, want 扫描读故障上抛（fail-visible）")
	}
	if data, readErr := os.ReadFile(taskengine.TaskLogPath("cert-renewal-scan")); readErr == nil && strings.Contains(string(data), "扫描完成") {
		t.Fatalf("失败轮摘要谎报完成: %q", string(data))
	}
}

// 回归形状：服务缺失跳过不是失败（Run 返回 nil，任务不进入失败终态）。
func TestCertRenewalScanOnce_service_missing_is_not_a_failure(t *testing.T) {
	useCertSweepTickTestEnv(t)

	if err := CertRenewalScanOnce(); err != nil {
		t.Fatalf("err=%v, want nil（服务未运行=跳过，不是失败）", err)
	}
}

// Run 体必须上抛 Once 的失败——task_runs 终态与任务监控依赖该返回值。
func TestTaskEngineWire_certTasksPropagateRunFailures(t *testing.T) {
	te := newWireTestEngine(t)
	resetCertificateServiceForTest(t)
	SetActiveCertificateService(NewCertificateService())
	t.Cleanup(func() { SetActiveCertificateService(nil) })
	// Given：cert_jobs 读故障（上述两条 Read 路径必然失败；task_runs 写入不受影响）
	if _, err := db.DB.Exec(`DROP TABLE cert_jobs`); err != nil {
		t.Fatalf("drop cert_jobs: %v", err)
	}

	// Then：两个周期任务的 Run 都必须返回 error
	if err := te.Trigger("cert-reconcile", "manual", ""); err == nil {
		t.Fatal("cert-reconcile Run 未上抛对账读失败（任务监控会显示 success）")
	}
	if err := te.Trigger("cert-renewal-scan", "manual", ""); err == nil {
		t.Fatal("cert-renewal-scan Run 未上抛扫描失败（任务监控会显示 success）")
	}
}

// 历史问题-15：手动证书到期巡检读失败必须上抛（此前仅应用日志 Logf+return，
// Run 恒 nil，task_runs 落 success——任务监控呈现假健康）。对齐
// cert-renewal-scan/cert-reconcile 同族口径。
func TestCertManualCheckOnce_propagates_query_failure(t *testing.T) {
	useCertSweepTickTestEnv(t)
	resetCertificateServiceForTest(t)
	SetActiveCertificateService(NewCertificateService())
	// Given：lb_rules 读故障（巡检候选查询必然失败）
	if _, err := db.DB.Exec(`DROP TABLE lb_rules`); err != nil {
		t.Fatalf("drop lb_rules: %v", err)
	}

	// When
	err := CertManualCheckOnce()

	// Then 1：读失败上抛（Run 随之返回 error → task_runs 失败终态）
	if err == nil {
		t.Fatal("CertManualCheckOnce err=nil, want 巡检读故障上抛（fail-visible）")
	}
	// Then 2：失败轮任务日志必须有失败行
	data, readErr := os.ReadFile(taskengine.TaskLogPath("cert-manual-poll"))
	if readErr != nil {
		t.Fatalf("read task log: %v", readErr)
	}
	if !strings.Contains(string(data), "巡检失败") {
		t.Fatalf("失败轮任务日志缺失失败行: %q", string(data))
	}
}

// 历史问题-15 接线钉：cert-manual-poll 的 Run 必须上抛 Once 的失败——
// task_runs 终态与任务监控依赖该返回值（此前 Run 恒 return nil）。
func TestTaskEngineWire_certManualPollPropagatesRunFailure(t *testing.T) {
	te := newWireTestEngine(t)
	resetCertificateServiceForTest(t)
	SetActiveCertificateService(NewCertificateService())
	t.Cleanup(func() { SetActiveCertificateService(nil) })
	// Given：lb_rules 读故障（巡检查询必然失败；task_runs 写入不受影响）
	if _, err := db.DB.Exec(`DROP TABLE lb_rules`); err != nil {
		t.Fatalf("drop lb_rules: %v", err)
	}

	// Then
	if err := te.Trigger("cert-manual-poll", "manual", ""); err == nil {
		t.Fatal("cert-manual-poll Run 未上抛巡检读失败（任务监控会显示 success）")
	}
}
