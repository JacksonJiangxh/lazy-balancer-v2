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

// L4-66-02：sweepOrphanedCertJobs 返回值必须等于实际收敛的孤儿任务数——
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

// U1-66-11 + R66 收敛（2026-10-03 裁定）：证书服务缺失行收敛为状态变化——
// nil 持续期仅 false→true 转换记一次跳过行，持续缺失静默，恢复（true→false）
// 记一次恢复行；三个证书 tick 任务共享同一状态门（全局单例服务指针）。
// 设计变更披露：原 U1-66-11「每轮一行跳过说明」按新裁定收敛，非弱化。
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

// U1-66-11（cert-waiting-ca 形态）+ R66 收敛：门控放行（有非终态任务）但服务
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
