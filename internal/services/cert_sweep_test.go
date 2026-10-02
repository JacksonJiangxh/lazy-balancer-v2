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
	})
	SetActiveCertificateService(nil)
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

// U1-66-11：证书循环空转轮（活动证书服务未注入）必须在任务日志留一行跳过
// 说明，面板任务日志不再静默空转。
func TestCertTicks_logSkipLineWhenServiceNotRunning(t *testing.T) {
	useCertSweepTickTestEnv(t)

	CertRenewalScanOnce()
	CertManualCheckOnce()

	for _, id := range []string{"cert-renewal-scan", "cert-manual-poll"} {
		data, err := os.ReadFile(taskengine.TaskLogPath(id))
		if err != nil {
			t.Fatalf("read task log %s: %v", id, err)
		}
		if !strings.Contains(string(data), "证书服务未运行，本轮跳过") {
			t.Fatalf("task log %s 缺少空转跳过行: %q", id, string(data))
		}
	}
}

// U1-66-11（cert-waiting-ca 形态）：门控放行（有非终态任务）但服务未运行时
// 记跳过行；门控拦截（全部终态）时保持静默（2026-09-29 裁定的零扫描门控
// 不得被空转日志破坏）。
func TestCertWaitingCATickOnce_skipLineGatedOnActiveJobs(t *testing.T) {
	useCertSweepTickTestEnv(t)

	// 有非终态任务：门控放行，服务未运行 → 跳过行
	jobID := seedOrphanCertJob(t, "lb_ghost_tick", "ghost-tick.example.test", "queued")
	CertWaitingCATickOnce()
	data, err := os.ReadFile(taskengine.TaskLogPath("cert-waiting-ca"))
	if err != nil {
		t.Fatalf("read task log: %v", err)
	}
	if got := strings.Count(string(data), "证书服务未运行，本轮跳过"); got != 1 {
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
	if got := strings.Count(string(data), "证书服务未运行，本轮跳过"); got != 1 {
		t.Fatalf("skip lines=%d, want 1（全终态时门控静默，不得追加空转行）", got)
	}
}
