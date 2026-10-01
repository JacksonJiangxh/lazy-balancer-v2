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

// Given 从节点 DB 角色（is_master=0）下 InitTaskEngine。
// When 初始化完成。
// Then 仅创建一个引擎（无泄漏实例）且角色种子作用于生效引擎——master-only
// daemon（cert-issuance）零 boot 行（U1-P2-2 钉：曾双 NewEngine 种子落在
// 被弃引擎上，从节点瞬启一轮幻影行）。
func TestTaskEngineWire_SingleEngineWithRoleSeedOnSlave(t *testing.T) {
	oldDB, oldM, oldA := db.DB, db.MetricsDB, db.AuditDB
	if err := db.Initialize(t.TempDir()); err != nil {
		t.Fatalf("initialize: %v", err)
	}
	t.Cleanup(func() {
		StopTaskEngine()
		_ = db.Close()
		db.DB, db.MetricsDB, db.AuditDB = oldDB, oldM, oldA
	})
	if _, err := db.DB.Exec(`UPDATE global_config SET is_master=0 WHERE id=1`); err != nil {
		t.Fatal(err)
	}
	te2 := InitTaskEngine("", t.TempDir()+"/app.log")
	if te2 == nil || te2 != TaskEngine() {
		t.Fatal("InitTaskEngine 幂等：二次调用应返回同一引擎")
	}
	// 生效引擎角色应为从节点（种子作用于本引擎）
	if te2.DescribeAll() == nil {
		t.Fatal("引擎应已注册任务")
	}
	// 从节点 cert-issuance 不得有 boot 行
	var n int
	if err := db.DB.QueryRow(`SELECT COUNT(*) FROM task_runs WHERE task_id='cert-issuance'`).Scan(&n); err != nil {
		t.Fatal(err)
	}
	if n != 0 {
		t.Fatalf("从节点 cert-issuance 应零 boot 行, got %d（双 NewEngine 角色种子失效回归）", n)
	}
}

// Given crs 版本行 next_update 停在过去（失败后不推进=2026-09-25 裁定行为）
// 且该槽已被一次执行覆盖（task_runs 有 started_at≥槽 的行）。
// When 槽位感知 NextSlot 计算。
// Then 返回排程配置的下一未来槽（引擎不重触发已覆盖槽——U1-P2-2 重试风暴
// 修复：管理器语义与 scheduled_update_retry 三钉不动，感知在引擎侧）。
func TestTaskEngineWire_CoveredPastSlotStepsToNextSchedule(t *testing.T) {
	oldDB, oldM, oldA := db.DB, db.MetricsDB, db.AuditDB
	if err := db.Initialize(t.TempDir()); err != nil {
		t.Fatalf("initialize: %v", err)
	}
	t.Cleanup(func() { _ = db.Close(); db.DB, db.MetricsDB, db.AuditDB = oldDB, oldM, oldA })
	// 排程：每天 04:00
	if _, err := db.DB.Exec(`INSERT OR IGNORE INTO security_crs_version (id, version, auto_update, schedule_days, schedule_time, next_update) VALUES (1,'v',1,'1,2,3,4,5,6,7','04:00',?)`,
		time.Now().UTC().Add(-2*time.Hour).Format("2006-01-02 15:04:05")); err != nil {
		t.Fatal(err)
	}
	// 覆盖证据：一次执行发生在槽之后（失败尝试）
	if _, err := db.DB.Exec(`INSERT INTO task_runs (task_id, family, trigger, status, started_at) VALUES ('crs','security','auto','failed',?)`,
		time.Now().Format("2006-01-02 15:04:05")); err != nil {
		t.Fatal(err)
	}
	got := crsNextSlotAware()
	if !got.After(time.Now()) {
		t.Fatalf("已覆盖的过去槽应步进到下一未来槽, got %v（重试风暴：引擎将秒级重触发）", got)
	}
	// 对照：无覆盖行时 past 槽原样返回（追补语义保留）
	if _, err := db.DB.Exec(`DELETE FROM task_runs WHERE task_id='crs'`); err != nil {
		t.Fatal(err)
	}
	got2 := crsNextSlotAware()
	if got2.After(time.Now()) {
		t.Fatalf("未覆盖的过去槽应原样返回（停机追补）, got %v", got2)
	}
}

// Given 引擎在场且 cert-waiting-ca 调度关闭（默认态）。
// When 手动签发/重试路径入队证书任务（CreateOrRequeueCertJobWithChange）。
// Then cert-waiting-ca 被唤醒（U1-P3-1：SPEC §3 声称的行为——曾仅 renewal-scan
// 一处唤醒，手动路径 30s→最长 6h 延迟）。
func TestTaskEngineWire_ManualCertJobWakesWaitingCA(t *testing.T) {
	te := newWireTestEngine(t)
	if te == nil {
		t.Fatal("engine nil")
	}
	// 前置：默认关闭（不在 StartLoop 清单）
	if te.IsRunning("cert-waiting-ca") {
		t.Fatal("前置失效：cert-waiting-ca 默认应关闭")
	}
	// 手动路径入队（真实队列——InitCAQueueManager 测试目录实例）
	InitCAQueueManager(nil, t.TempDir())
	if _, _, err := CreateOrRequeueCertJobWithChange("lb_wake_test", "wake.example.com", 0, GetCAQueueManager()); err != nil {
		t.Fatalf("enqueue: %v", err)
	}
	if !te.IsRunning("cert-waiting-ca") {
		t.Fatal("手动入队应唤醒 cert-waiting-ca（U1-P3-1）")
	}
	te.StopLoop("cert-waiting-ca")
}

// Given 引擎完成全量注册。
// When DescribeAll。
// Then cert-issuance/cluster-sync 为 status_view_only（L1-1：被动守护退出
// 控制面——真实服务由 lifecycle 管理）；security-events-ingestion 仍可控。
func TestTaskEngineWire_PassiveCarrierStatusViewOnly(t *testing.T) {
	te := newWireTestEngine(t)
	for _, m := range te.DescribeAll() {
		switch m.ID {
		case "cert-issuance", "cluster-sync":
			if !m.StatusViewOnly {
				t.Errorf("%s 应 status_view_only=true（被动守护）", m.ID)
			}
			if m.Controllable {
				t.Errorf("%s 应 Controllable=false（控制面不适用）", m.ID)
			}
		case "security-events-ingestion":
			if m.StatusViewOnly {
				t.Errorf("%s 为真实自管理循环，不应 status_view_only", m.ID)
			}
			if !m.Controllable {
				t.Errorf("%s 应 Controllable=true", m.ID)
			}
		}
	}
}
