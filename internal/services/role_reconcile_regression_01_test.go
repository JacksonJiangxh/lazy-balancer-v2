package services

// 一次，播种失败（DB 瞬时不可读）即永久「DB=主/引擎=从」半主半从——全部
// master-only 任务静默停摆且无法再 Promote 自愈。对账函数由 60s 看门狗
// 驱动，把引擎角色收敛到 DB 单源角色。

import (
	"testing"

	"lazy-balancer-v2/internal/db"
)

// 修复前形状：DB=主、引擎=从 → master-only 探针被角色门拒绝；对账后恢复。
func TestReconcileTaskEngineRole_healsSlaveEngineOnMasterDB(t *testing.T) {
	te := newWireTestEngine(t) // DB 默认 is_master=1
	probe := registerRoleProbeTask(t, te)
	te.SetRole(false) // 播种失败终态
	if err := probe(); err == nil {
		t.Fatal("given：引擎从角色时 master-only 探针必须被拒绝")
	}

	reconcileTaskEngineRole()

	if !te.IsMaster() {
		t.Fatal("对账后引擎角色必须回到 DB 的主节点角色")
	}
	if err := probe(); err != nil {
		t.Fatalf("对账后 master-only 任务应恢复可执行: %v", err)
	}
}

// 反方向：DB=从、引擎=主（如外部把库改成从节点）→ 对账必须降级引擎，
// 不得让 master-only 任务在从节点继续执行。
func TestReconcileTaskEngineRole_demotesEngineOnSlaveDB(t *testing.T) {
	te := newWireTestEngine(t)
	probe := registerRoleProbeTask(t, te)
	if err := probe(); err != nil {
		t.Fatalf("given：主节点态探针应通过: %v", err)
	}
	if _, err := db.DB.Exec(`UPDATE global_config SET is_master=0 WHERE id=1`); err != nil {
		t.Fatalf("seed slave db state: %v", err)
	}

	reconcileTaskEngineRole()

	if te.IsMaster() {
		t.Fatal("DB=从时引擎必须降级")
	}
	if err := probe(); err == nil {
		t.Fatal("降级后 master-only 探针必须被角色门拒绝")
	}
}

// 角色一致时必须无副作用（SetRole 重申不重启 daemon）。
func TestReconcileTaskEngineRole_noopWhenAligned(t *testing.T) {
	te := newWireTestEngine(t)
	if !te.IsMaster() {
		t.Fatal("fixture precondition: DB default is master")
	}
	reconcileTaskEngineRole()
	if !te.IsMaster() {
		t.Fatal("已对齐时对账不得改变引擎角色")
	}
	// 库角色读取失败时保持现状（不 fail-closed 翻转——翻转本身有副作用）。
	if _, err := db.DB.Exec(`DELETE FROM global_config`); err != nil {
		t.Fatalf("delete global_config: %v", err)
	}
	reconcileTaskEngineRole()
	if !te.IsMaster() {
		t.Fatal("读取失败时对账不得翻转引擎角色")
	}
}

// seedDriftAndTopologyState 准备「旧角色时代」的全部数据/状态半边，供
// 对账回归断言：分区上报缓存、快照缓存、看门狗漂移态、旧拓扑节记账/WAF
// 文件态。
func seedDriftAndTopologyState(t *testing.T) {
	t.Helper()
	database := db.DB
	if _, err := database.Exec(`INSERT INTO cluster_applied_sections (section, hash, applied_version) VALUES ('users','deadbeef',3)
		ON CONFLICT(section) DO UPDATE SET hash=excluded.hash, applied_version=excluded.applied_version`); err != nil {
		t.Fatalf("seed applied sections: %v", err)
	}
	if _, err := database.Exec(`UPDATE global_config SET applied_waf_ref_hash='cafebabe', applied_waf_ref_version=9 WHERE id=1`); err != nil {
		t.Fatalf("seed waf ref: %v", err)
	}
	clusterSnapshotCaches.Store(database, &clusterSnapshotCache{})
	t.Cleanup(func() { clusterSnapshotCaches.Delete(database) })
	configDriftMu.Lock()
	configDriftStatus = ConfigDriftStatus{Consistent: false, Missing: []string{"r-stale"}}
	configDriftMu.Unlock()
}

func assertRoleSideEffectsApplied(t *testing.T) {
	t.Helper()
	database := db.DB
	if _, ok := clusterSnapshotCaches.Load(database); ok {
		t.Fatal("角色对账必须失效快照缓存（否则降级期内容会在再次升主时被当作权威下发）")
	}
	if drift := CurrentConfigDrift(); !drift.Consistent || len(drift.Missing) != 0 {
		t.Fatalf("角色对账必须复位看门狗漂移态: %+v", drift)
	}
	var sections int
	if err := database.QueryRow(`SELECT COUNT(*) FROM cluster_applied_sections`).Scan(&sections); err != nil {
		t.Fatalf("read applied sections: %v", err)
	}
	if sections != 0 {
		t.Fatalf("角色对账必须清理旧拓扑节记账, 残留 %d 行", sections)
	}
	var hash string
	var version int
	if err := database.QueryRow(`SELECT applied_waf_ref_hash, applied_waf_ref_version FROM global_config WHERE id=1`).Scan(&hash, &version); err != nil {
		t.Fatalf("read waf ref: %v", err)
	}
	if hash != "" || version != 0 {
		t.Fatalf("角色对账必须复位 WAF 文件态记账, got %q/%d", hash, version)
	}
}

// 降级方向（DB=从、引擎=主）：对账必须做 BecomeSlave 的配套半边，并恢复
// 从端拉取调度（主节点期间曾被用户停掉的 cluster-sync 不得延续到从端）。
func TestReconcileTaskEngineRole_demoteAppliesSideEffects(t *testing.T) {
	te := newWireTestEngine(t)
	if !te.IsMaster() {
		t.Fatal("fixture precondition: DB default is master")
	}
	seedDriftAndTopologyState(t)
	if _, err := db.DB.Exec(`INSERT INTO task_loop_prefs (task_id, enabled) VALUES ('cluster-sync',0)
		ON CONFLICT(task_id) DO UPDATE SET enabled=0`); err != nil {
		t.Fatalf("seed loop pref: %v", err)
	}
	if _, err := db.DB.Exec(`UPDATE global_config SET is_master=0 WHERE id=1`); err != nil {
		t.Fatalf("seed slave db state: %v", err)
	}

	reconcileTaskEngineRole()

	if te.IsMaster() {
		t.Fatal("DB=从时引擎必须降级")
	}
	assertRoleSideEffectsApplied(t)
	var enabled int
	if err := db.DB.QueryRow(`SELECT enabled FROM task_loop_prefs WHERE task_id='cluster-sync'`).Scan(&enabled); err != nil {
		t.Fatalf("read loop pref: %v", err)
	}
	if enabled != 1 {
		t.Fatalf("切从后 cluster-sync 持久偏好必须恢复为启用, got %d", enabled)
	}
	if meta, ok := te.Lookup("cluster-sync"); !ok || !meta.LoopOn {
		t.Fatalf("切从后 cluster-sync 调度必须开启: %+v", meta)
	}
}

// 升主方向（DB=主、引擎=从）：对账必须做 Promote 的配套半边（缓存/漂移/
// 旧拓扑记账复位 + 爬虫运行快照重建），否则半程翻转会把降级期状态带入主节点。
func TestReconcileTaskEngineRole_promoteAppliesSideEffects(t *testing.T) {
	te := newWireTestEngine(t)
	te.SetRole(false) // 播种失败终态
	oldCrawlerFile := crawlerIPListFile
	crawlerIPListFile = t.TempDir() + "/crawler-ip-lists.json"
	t.Cleanup(func() { crawlerIPListFile = oldCrawlerFile })
	seedDriftAndTopologyState(t)

	reconcileTaskEngineRole()

	if !te.IsMaster() {
		t.Fatal("对账后引擎角色必须回到 DB 的主节点角色")
	}
	assertRoleSideEffectsApplied(t)
}
