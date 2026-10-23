package services

// 任务视图的角色适用性由服务端派生：从节点上 master-only 族照常展示调度
// 开关与下次执行会误导排障（永不投递），视图需要「仅主节点运行」的显性结论。

import (
	"testing"
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
