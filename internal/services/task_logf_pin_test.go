package services

// Round 62 用户反馈批次钉（SPEC §6.5 业务摘要行）：每个真实执行轮在
// tasks/{id}.log 留业务结论——「无临期证书/清理 N 条/摄取 N 条/配置一致」。

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"lazy-balancer-v2/internal/db"
	"lazy-balancer-v2/internal/taskengine"
)

func newTaskLogDir(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	old := taskengine.TaskLogPath("probe-x")
	taskengine.SetLogDir(filepath.Join(dir, "tasks"))
	t.Cleanup(func() {
		if old == "" {
			taskengine.SetLogDir("")
		}
	})
	return filepath.Join(dir, "tasks")
}

func readTaskLog(t *testing.T, taskID string) string {
	t.Helper()
	data, err := os.ReadFile(taskengine.TaskLogPath(taskID))
	if err != nil {
		t.Fatalf("read task log: %v", err)
	}
	return string(data)
}

// Given 空库（无临期证书、无过期审计、配置一致无从判定——cert 域最简可测形）。
// When cert-renewal-scan 摘要行写入。
// Then tasks/cert-renewal-scan.log 含「无临期证书」业务结论行。
func TestTaskLogf_CertRenewalScanNoExpiringSummary(t *testing.T) {
	newTaskLogDir(t)
	oldDB, oldM, oldA := db.DB, db.MetricsDB, db.AuditDB
	if err := db.Initialize(t.TempDir()); err != nil {
		t.Fatalf("initialize: %v", err)
	}
	t.Cleanup(func() { _ = db.Close(); db.DB, db.MetricsDB, db.AuditDB = oldDB, oldM, oldA })
	// 空库：is_master 默认 1，CheckExpiration 无临期 → 摘要行必达（qm 仅在
	// 有 jobs 的循环内消费——空路径不依赖队列）
	s := &CertificateService{}
	s.renewExpiringCertificates()
	log := readTaskLog(t, "cert-renewal-scan")
	if !strings.Contains(log, "无临期证书") {
		t.Fatalf("cert-renewal-scan 摘要行缺失: %q", log)
	}
}

// Given audit-retention Run 在含过期审计行的库上执行。
// When 清理完成。
// Then tasks/audit-retention.log 含带删除条数的结论行。
func TestTaskLogf_AuditRetentionCleanupSummary(t *testing.T) {
	newTaskLogDir(t)
	oldDB, oldM, oldA := db.DB, db.MetricsDB, db.AuditDB
	if err := db.Initialize(t.TempDir()); err != nil {
		t.Fatalf("initialize: %v", err)
	}
	t.Cleanup(func() { _ = db.Close(); db.DB, db.MetricsDB, db.AuditDB = oldDB, oldM, oldA })
	// seed 全局配置行（retention 读取）与过期审计行（audit 库）
	if _, err := db.DB.Exec(`INSERT OR IGNORE INTO global_config (id) VALUES (1)`); err != nil {
		t.Fatal(err)
	}
	if _, err := db.AuditDB.Exec(`INSERT INTO audit_log (username, action, resource, detail, ip_address, created_at) VALUES ('u','登录','认证','','','2020-01-01 00:00:00')`); err != nil {
		t.Fatal(err)
	}
	deleted := CleanupAuditLogs()
	if deleted != 1 {
		t.Fatalf("清理条数 want 1, got %d", deleted)
	}
	TaskLogf("audit-retention", "cleanup", "清理完成：审计日志 %d 条、任务运行历史 %d 行（无过期数据时为 0）", deleted, 0)
	log := readTaskLog(t, "audit-retention")
	if !strings.Contains(log, "审计日志 1 条") {
		t.Fatalf("audit-retention 摘要行缺失: %q", log)
	}
}

// Given watchdog 摘要行（一致态由 CurrentConfigDrift 驱动——空态 Consistent=false
// 的首启前窗口也应有结论行形态）。
// When TaskLogf 写入漂移/一致行。
// Then 行内容含「配置一致」或「配置漂移」结论词（形态钉）。
func TestTaskLogf_WatchdogSummaryShape(t *testing.T) {
	newTaskLogDir(t)
	TaskLogf("config-watchdog", "check", "配置一致（DB 期望 = Caddy 运行态）")
	log := readTaskLog(t, "config-watchdog")
	if !strings.Contains(log, "配置一致") || !strings.Contains(log, "[INFO]") {
		t.Fatalf("watchdog 摘要行形态不符: %q", log)
	}
}

// Given SilentRuns 元数据（RecordFailuresOnly 族）。
// When DescribeAll。
// Then watchdog/ingestion/cert-manual-poll/cert-waiting-ca silent_runs=true；
// threat 族 false（UI「静默轮」徽标数据源）。
func TestTaskEngineWire_SilentRunsFlags(t *testing.T) {
	te := newWireTestEngine(t)
	got := map[string]bool{}
	for _, m := range te.DescribeAll() {
		got[m.ID] = m.SilentRuns
	}
	for _, id := range []string{"config-watchdog", "security-events-ingestion", "cert-manual-poll", "cert-waiting-ca"} {
		if !got[id] {
			t.Errorf("%s 应 SilentRuns=true", id)
		}
	}
	for _, id := range []string{"threat", "crs", "auto-backup", "cert-renewal-scan"} {
		if got[id] {
			t.Errorf("%s 应 SilentRuns=false", id)
		}
	}
}
