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

// Given 引擎启动并注册常驻族。
// When CollectSystemTasks 视图聚合。
// Then 常驻族 started_at 非空（引擎启动时刻）且 loop_on=true（调度列常驻开关联动值）；
// 定时族 started_at 为空。
func TestCollectSystemTasks_ContinuousStartedAtAndLoopOn(t *testing.T) {
	te := newWireTestEngine(t)
	got := map[string]TaskInfo{}
	for _, ti := range collectEngineFamilies(te) {
		got[ti.ID] = ti
	}
	w := got["config-watchdog"]
	if w.StartedAt == "" {
		t.Fatal("常驻族 started_at 应非空（引擎启动时刻）")
	}
	if !w.LoopOn {
		t.Fatal("常驻族 loop_on 应 true（StartLoop 默认开启）")
	}
	if got["threat"].StartedAt != "" {
		t.Fatal("定时族 started_at 应为空")
	}
}
