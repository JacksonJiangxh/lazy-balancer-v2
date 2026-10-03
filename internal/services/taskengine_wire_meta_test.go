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

// Given 引擎完成全量注册（2026-10-03 裁定后）。
// When DescribeAll + 两角色调度。
// Then cert-issuance/cluster-sync/security-events-ingestion 均为真实可控
// 常驻（Controllable=true）；cluster-sync 为 RoleAny+RestartOnRoleFlip——
// 两角色统一生命周期（真实启停；状态镜像废除），主节点角色下真实运行
// （服务面巡检），不再有「主节点不运行」的角色门形态。
func TestTaskEngineWire_DaemonsFullyControllable(t *testing.T) {
	te := newWireTestEngine(t)
	for _, m := range te.DescribeAll() {
		switch m.ID {
		case "cert-issuance", "cluster-sync", "security-events-ingestion":
			if !m.Controllable {
				t.Errorf("%s 应 Controllable=true（B 完全标准化）", m.ID)
			}
		}
	}
	// cluster-sync RoleAny：主节点角色下真实运行（主分支=服务面巡检）
	te.SetRole(true)
	te.StartLoop("cluster-sync")
	time.Sleep(150 * time.Millisecond)
	if !te.IsRunning("cluster-sync") {
		t.Fatal("主节点 cluster-sync 应真实运行（2026-10-03 裁定：统一生命周期，镜像废除）")
	}
	// 从节点角色下同样真实运行（从分支=同步轮询；Run 体按角色分流）
	te.SetRole(false)
	time.Sleep(150 * time.Millisecond)
	if !te.IsRunning("cluster-sync") {
		t.Fatal("从节点 cluster-sync 应真实运行（同步轮询）")
	}
}

// Given 主节点角色（is_master=1）——cluster-sync 真实启动（主分支巡检）。
// When 状态聚合。
// Then cluster-sync 显示运行中（真实 daemon 实态，非状态镜像——2026-10-03
// 裁定废除 masterSyncServingStatus）。
func TestTaskEngineWire_MasterSyncShowsServing(t *testing.T) {
	te := newWireTestEngine(t)
	if _, err := db.DB.Exec(`UPDATE global_config SET is_master=1 WHERE id=1`); err != nil {
		t.Fatal(err)
	}
	te.SetRole(true)
	waitForCond(t, 2*time.Second, func() bool { return te.IsRunning("cluster-sync") })
	for _, ti := range collectEngineFamilies(te) {
		if ti.ID == "cluster-sync" {
			if ti.Status != TaskStatusRunning {
				t.Fatalf("主节点 cluster-sync 应运行中（真实 daemon 实态）, got %s", ti.Status)
			}
			return
		}
	}
	t.Fatal("cluster-sync 未注册")
}
