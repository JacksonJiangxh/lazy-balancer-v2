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

// Given audit-retention 已在引擎注册（真实 Run 体：CleanupAuditLogs→
// PurgeTaskRuns→TaskLogf），库中含过期审计行。
// When 经引擎 Trigger 执行真实 Run 体（U1-66-10 接线钉——曾由测试自调
// CleanupAuditLogs+自写 TaskLogf，删 Run 体内 TaskLogf 调用不会红）。
// Then tasks/audit-retention.log 含 Run 体写出的带删除条数的结论行。
func TestTaskLogf_AuditRetentionCleanupSummary(t *testing.T) {
	newTaskLogDir(t)
	te := newWireTestEngine(t)
	// seed 全局配置行（retention 读取）与过期审计行（audit 库）
	if _, err := db.DB.Exec(`INSERT OR IGNORE INTO global_config (id) VALUES (1)`); err != nil {
		t.Fatal(err)
	}
	if _, err := db.AuditDB.Exec(`INSERT INTO audit_log (username, action, resource, detail, ip_address, created_at) VALUES ('u','登录','认证','','','2020-01-01 00:00:00')`); err != nil {
		t.Fatal(err)
	}
	if err := te.Trigger("audit-retention", "manual", ""); err != nil {
		t.Fatalf("trigger audit-retention: %v", err)
	}
	log := readTaskLog(t, "audit-retention")
	if !strings.Contains(log, "清理完成：审计日志 1 条") {
		t.Fatalf("audit-retention Run 体摘要行缺失（接线断）: %q", log)
	}
}

// Given config-watchdog 已在引擎注册（真实 Run 体：WatchdogCheckOnce——每轮
// 恰写一行「配置一致/配置漂移」结论）。
// When 经引擎 Trigger 执行真实 Run 体（U1-66-10 接线钉——watchdog admin 为空
// 时检查按不可达跳过，结论行形态恒可达：无外部依赖）。
// Then tasks/config-watchdog.log 含「配置一致」或「配置漂移」结论行。
func TestTaskLogf_WatchdogSummaryShape(t *testing.T) {
	newTaskLogDir(t)
	te := newWireTestEngine(t)
	if err := te.Trigger("config-watchdog", "manual", ""); err != nil {
		t.Fatalf("trigger config-watchdog: %v", err)
	}
	log := readTaskLog(t, "config-watchdog")
	if !strings.Contains(log, "配置一致") && !strings.Contains(log, "配置漂移") {
		t.Fatalf("watchdog Run 体结论行缺失（接线断）: %q", log)
	}
	if !strings.Contains(log, "[INFO]") {
		t.Fatalf("watchdog 摘要行形态不符: %q", log)
	}
}

// Given v2.0 四类型标准全量注册。
// When DescribeAll。
// Then Kind 映射：定时 4（threat/crs/ip2region/auto-backup）、循环 8、
// 常驻 3（ingestion/cert-issuance/cluster-sync）、触发 1（startup:config-load）；
// cert-waiting-ca 默认 LoopOn=false（调度关闭——续期扫描唤醒）。
func TestTaskEngineWire_KindMapping(t *testing.T) {
	te := newWireTestEngine(t)
	got := map[string]taskengine.TaskMeta{}
	for _, m := range te.DescribeAll() {
		got[m.ID] = m
	}
	want := map[string]taskengine.Kind{
		"threat": taskengine.KindScheduled, "crs": taskengine.KindScheduled,
		"ip2region": taskengine.KindScheduled, "auto-backup": taskengine.KindScheduled,
		"config-watchdog": taskengine.KindPeriodic, "log-cleanup": taskengine.KindPeriodic,
		"audit-retention": taskengine.KindPeriodic, "security-events-retention": taskengine.KindPeriodic,
		"cert-renewal-scan": taskengine.KindPeriodic, "cert-reconcile": taskengine.KindPeriodic,
		"cert-manual-poll": taskengine.KindPeriodic, "cert-waiting-ca": taskengine.KindPeriodic,
		"security-events-ingestion": taskengine.KindDaemon, "cert-issuance": taskengine.KindDaemon,
		"cluster-sync":        taskengine.KindDaemon,
		"startup:config-load": taskengine.KindOneshot,
	}
	for id, kind := range want {
		m, ok := got[id]
		if !ok {
			t.Errorf("%s 未注册", id)
			continue
		}
		if m.Kind != kind {
			t.Errorf("%s Kind=%s, want %s", id, m.Kind, kind)
		}
	}
	if m, ok := got["cert-waiting-ca"]; ok && m.LoopOn {
		t.Error("cert-waiting-ca 默认调度应关闭（LoopOn=false，续期扫描唤醒）")
	}
}
