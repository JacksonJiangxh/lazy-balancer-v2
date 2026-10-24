package services

// 任务视图的角色适用性由服务端派生：从节点上 master-only 族照常展示调度
// 开关与下次执行会误导排障（永不投递），视图需要「仅主节点运行」的显性结论。

import (
	"testing"
	"time"

	"lazy-balancer-v2/internal/db"
)

func TestCollectEngineFamilies_roleApplicability(t *testing.T) {
	te := newWireTestEngine(t)
	masterOnly := []string{"crs", "threat", "ip2region", "cert-renewal-scan", "autoban", "auto-backup"}
	roleAny := []string{"cluster-sync", securityEventsIngestionTaskID}

	check := func(wantApplicable bool, label string) {
		t.Helper()
		rows := collectEngineFamilies(te)
		for _, id := range masterOnly {
			for _, ti := range rows {
				if ti.ID == id && ti.RoleApplicable != wantApplicable {
					t.Fatalf("%s: %s RoleApplicable=%v, want %v", label, id, ti.RoleApplicable, wantApplicable)
				}
			}
		}
		for _, id := range roleAny {
			for _, ti := range rows {
				if ti.ID == id && !ti.RoleApplicable {
					t.Fatalf("%s: %s（RoleAny）RoleApplicable=false", label, id)
				}
			}
		}
	}

	te.SetRole(true)
	check(true, "主节点")
	te.SetRole(false)
	check(false, "从节点")
}

// Given 从节点（master-only 周期族 RoleApplicable=false）与其最近运行行。
// When 聚合任务视图。
// Then 不推算「下次执行」（该族永不投递，推算出的具体时间与角色不适用标注
// 自相矛盾）；主节点同形态照常推算。
func TestCollectEngineFamilies_masterOnlyNextRunAtGatedByRole(t *testing.T) {
	te := newWireTestEngine(t)
	const id = "cert-renewal-scan"
	if _, err := db.DB.Exec(`INSERT INTO task_runs (task_id, family, trigger, status, started_at)
		VALUES (?, 'cert', 'auto', 'success', ?)`, id, time.Now().In(CurrentLocation()).Format("2006-01-02 15:04:05")); err != nil {
		t.Fatal(err)
	}
	te.SetRole(true)
	master := findTaskInfo(t, collectEngineFamilies(te), id)
	if !master.RoleApplicable || master.NextRunAt == "" {
		t.Fatalf("主节点上周期任务应推算下次执行, RoleApplicable=%v NextRunAt=%q", master.RoleApplicable, master.NextRunAt)
	}
	te.SetRole(false)
	slave := findTaskInfo(t, collectEngineFamilies(te), id)
	if slave.RoleApplicable {
		t.Fatal("前置条件：从节点上 master-only 任务应不适用")
	}
	if slave.NextRunAt != "" {
		t.Fatalf("角色不适用任务不得推算下次执行（实际永不投递）, got %q", slave.NextRunAt)
	}
}
