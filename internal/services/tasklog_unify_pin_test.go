package services

// Round 62 第三批钉：cert-job 终态计数 / 常驻族 started_at+loop_on /
// 更新日志同源（三端点读任务日志文件）。

import (
	"strings"
	"testing"
	"time"

	"lazy-balancer-v2/internal/db"
)

// Given cert_jobs 一行 issued（24h 内更新）+一行 failed。
// When collectCertJobRows。
// Then issued 行 Success24h=1、failed 行 Fail24h=1（终态映射——签发成功应成功+1）。
func TestCollectCertJobRows_TerminalCounts(t *testing.T) {
	oldDB, oldM, oldA := db.DB, db.MetricsDB, db.AuditDB
	if err := db.Initialize(t.TempDir()); err != nil {
		t.Fatalf("initialize: %v", err)
	}
	t.Cleanup(func() { _ = db.Close(); db.DB, db.MetricsDB, db.AuditDB = oldDB, oldM, oldA })
	now := time.Now().UTC().Format("2006-01-02 15:04:05")
	db.DB.Exec(`INSERT INTO cert_jobs (rule_id, domain, status, updated_at) VALUES ('r1','a.test','issued',?)`, now)
	db.DB.Exec(`INSERT INTO cert_jobs (rule_id, domain, status, updated_at) VALUES ('r2','b.test','failed',?)`, now)
	rows := collectCertJobRows()
	byDomain := map[string]TaskInfo{}
	for _, r := range rows {
		byDomain[strings.TrimPrefix(r.Name, "ACME 签发 · ")] = r
	}
	if byDomain["a.test"].Success24h != 1 {
		t.Fatalf("issued 行 Success24h want 1, got %d", byDomain["a.test"].Success24h)
	}
	if byDomain["b.test"].Fail24h != 1 {
		t.Fatalf("failed 行 Fail24h want 1, got %d", byDomain["b.test"].Fail24h)
	}
}

// Given 引擎启动并按 v2.0 四类型注册。
// When CollectSystemTasks 视图聚合。
// Then 常驻族（Daemon）started_at 非空且 loop_on=true；循环族（Periodic）
// loop_on=true 但 started_at 为空；定时族（Scheduled）started_at 为空；
// cert-waiting-ca 默认 loop_on=false（调度关闭）。
func TestCollectSystemTasks_ContinuousStartedAtAndLoopOn(t *testing.T) {
	te := newWireTestEngine(t)
	got := map[string]TaskInfo{}
	for _, ti := range collectEngineFamilies(te) {
		got[ti.ID] = ti
	}
	for _, id := range []string{"security-events-ingestion", "cert-issuance", "cluster-sync"} {
		if got[id].StartedAt == "" {
			t.Fatalf("%s（常驻）started_at 应非空", id)
		}
		if !got[id].LoopOn {
			t.Fatalf("%s（常驻）loop_on 应 true（StartLoop 默认开启）", id)
		}
	}
	w := got["config-watchdog"]
	if w.StartedAt != "" {
		t.Fatal("循环族 started_at 应为空（仅常驻族有启动时刻）")
	}
	if !w.LoopOn {
		t.Fatal("循环族 loop_on 应 true")
	}
	if got["threat"].StartedAt != "" {
		t.Fatal("定时族 started_at 应为空")
	}
	if got["cert-waiting-ca"].LoopOn {
		t.Fatal("cert-waiting-ca 默认调度应关闭（loop_on=false）")
	}
}
