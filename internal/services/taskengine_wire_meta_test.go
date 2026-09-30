package services

// Round 62 修复钉（引擎接线元数据）：NextSlotFn SQL（P2-③）/更新族单飞与
// 调度开关（P3-7/U1-P4-2）/证书族角色门（U7-P3-2）。

import (
	"testing"
	"time"

	"lazy-balancer-v2/internal/db"
	"lazy-balancer-v2/internal/taskengine"
)

func newWireTestEngine(t *testing.T) *taskengine.Engine {
	t.Helper()
	oldDB, oldMetricsDB, oldAuditDB := db.DB, db.MetricsDB, db.AuditDB
	if err := db.Initialize(t.TempDir()); err != nil {
		t.Fatalf("initialize test database: %v", err)
	}
	t.Cleanup(func() {
		StopTaskEngine()
		_ = db.Close()
		db.DB, db.MetricsDB, db.AuditDB = oldDB, oldMetricsDB, oldAuditDB
	})
	// runtimeLogFile 指向临时目录——避免默认 /app/logs 写出测试沙箱
	return InitTaskEngine("", t.TempDir()+"/app.log")
}

// Given 存在 waiting_ca 证书任务且 ca_available_after 非空。
// When DescribeAll 读取 cert-waiting-ca 元数据。
// Then NextSlot 非空（P2-③：原 SQL 缺 2 右括号+NULLIF 3 参——恒语法错误，
// 「下次 CA 可用时间」上线即恒空）。
func TestTaskEngineWire_CertWaitingCANextSlotResolves(t *testing.T) {
	te := newWireTestEngine(t)
	future := time.Now().UTC().Add(2 * time.Hour).Format("2006-01-02 15:04:05")
	if _, err := db.DB.Exec(`INSERT INTO cert_jobs (rule_id, domain, status, ca_available_after) VALUES ('r1','a.example.com','waiting_ca',?)`, future); err != nil {
		t.Fatal(err)
	}
	for _, m := range te.DescribeAll() {
		if m.ID != "cert-waiting-ca" {
			continue
		}
		if m.NextSlot == "" {
			t.Fatal("waiting_ca 存在时 cert-waiting-ca NextSlot 应非空（SQL 曾恒语法错误）")
		}
		return
	}
	t.Fatal("cert-waiting-ca 未注册")
}

// Given 引擎完成全量注册。
// When DescribeAll。
// Then 更新族四描述符 Kind=Scheduled（v2.0 排程槽驱动）；三更新族
// Toggleable+审计名（U1-P4-2 元数据化）。
func TestTaskEngineWire_UpdateFamilyFlags(t *testing.T) {
	te := newWireTestEngine(t)
	got := map[string]taskengine.TaskMeta{}
	for _, m := range te.DescribeAll() {
		got[m.ID] = m
	}
	for _, id := range []string{"threat", "crs", "ip2region", "auto-backup"} {
		m, ok := got[id]
		if !ok {
			t.Fatalf("%s 未注册", id)
		}
		if m.Kind != taskengine.KindScheduled {
			t.Errorf("%s Kind=%s, want scheduled（v2.0 排程槽驱动）", id, m.Kind)
		}
	}
	for _, id := range []string{"threat", "crs", "ip2region"} {
		m := got[id]
		if !m.Toggleable {
			t.Errorf("%s 应 Toggleable（U1-P4-2 调度开关元数据化）", id)
		}
		if m.ToggleName == "" {
			t.Errorf("%s ToggleName 不应为空", id)
		}
	}
}

// Given 证书族四循环已注册并启用。
// When 引擎切到从节点角色。
// Then 循环 IsRunning=false（U7-P3-2：RunsOn=RoleMasterOnly 显式角色门——
// cert-reconcile 曾在从节点真实执行）。
func TestTaskEngineWire_CertFamilyMasterOnly(t *testing.T) {
	te := newWireTestEngine(t)
	te.SetRole(true)
	for _, id := range []string{"cert-renewal-scan", "cert-reconcile", "cert-manual-poll", "cert-waiting-ca"} {
		te.StartLoop(id)
	}
	te.SetRole(false)
	for _, id := range []string{"cert-renewal-scan", "cert-reconcile", "cert-manual-poll", "cert-waiting-ca"} {
		if te.IsRunning(id) {
			t.Errorf("从节点角色下 %s 不应运行（证书族应显式 master-only）", id)
		}
	}
	te.SetRole(true)
}

// Given 四个业务开关（threat/crs/ip2region 自动更新 + 自动备份启用）全部关闭。
// When DescribeAll + collectEngineFamilies 聚合视图。
// Then 四任务 Enabled=false 且 status=disabled（业务开关联动展示——2026-10-01
// 用户裁定：业务关≠空闲，须呈现「已暂停」）；恢复开关后回到 idle。
func TestTaskEngineWire_BusinessToggleLinksDisabledStatus(t *testing.T) {
	te := newWireTestEngine(t)
	// 三规则集自动更新关（threat=global_config 列；crs/ip2region=各自版本表）+ 备份停用
	if _, err := db.DB.Exec(`UPDATE global_config SET threat_auto_update=0, auto_backup_enabled=0 WHERE id=1`); err != nil {
		t.Fatal(err)
	}
	// crs 版本表由 manager 初始化种子（测试环境无 manager——显式补行）
	if _, err := db.DB.Exec(`INSERT OR IGNORE INTO security_crs_version (id, version, auto_update) VALUES (1, 'v-test', 1)`); err != nil {
		t.Fatal(err)
	}
	if _, err := db.DB.Exec(`UPDATE security_crs_version SET auto_update=0 WHERE id=1`); err != nil {
		t.Fatal(err)
	}
	if _, err := db.DB.Exec(`UPDATE security_ip2region_version SET auto_update=0 WHERE id=1`); err != nil {
		t.Fatal(err)
	}
	meta := map[string]taskengine.TaskMeta{}
	for _, m := range te.DescribeAll() {
		meta[m.ID] = m
	}
	for _, id := range []string{"threat", "crs", "ip2region", "auto-backup"} {
		if meta[id].Enabled {
			t.Errorf("%s 业务开关关闭时 Enabled 应 false", id)
		}
		if meta[id].NextSlot != "" {
			t.Errorf("%s 业务开关关闭时 NextSlot 应空（零调度）", id)
		}
	}
	view := map[string]TaskInfo{}
	for _, ti := range collectEngineFamilies(te) {
		view[ti.ID] = ti
	}
	for _, id := range []string{"threat", "crs", "ip2region", "auto-backup"} {
		if view[id].Status != TaskStatusDisabled {
			t.Errorf("%s 联动展示应为 disabled（已暂停）, got %s", id, view[id].Status)
		}
	}
	// 恢复 threat 开关——回到非 disabled
	if _, err := db.DB.Exec(`UPDATE global_config SET threat_auto_update=1 WHERE id=1`); err != nil {
		t.Fatal(err)
	}
	for _, m := range te.DescribeAll() {
		if m.ID == "threat" && !m.Enabled {
			t.Fatal("threat 开关恢复后 Enabled 应回 true")
		}
	}
}
