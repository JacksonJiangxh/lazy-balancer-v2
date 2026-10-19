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
