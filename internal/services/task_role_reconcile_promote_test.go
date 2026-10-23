package services

// 角色对账的升主分支必须完成 Promote 的任务面收尾：业务驱动任务按库实态
// 对齐 + 规则库首槽重装。两条升主路径共用单源——对账升主曾漏掉这两项，
// 半程翻转后业务开但调度关、空槽永不到期。

import (
	"testing"

	"lazy-balancer-v2/internal/db"
)

// Given DB=主/引擎=从（播种失败或外部改库），从节点期间残留
// 「规则库 auto_update 开但 next_update 空」与「威胁库业务开但引擎调度关」。
// When 角色对账升主。
// Then 首槽重装（crs.next_slot 非空）+ 业务驱动任务调度对齐（threat.loop_on=true）。
func TestReconcileTaskEngineRole_promoteCompletesTaskSideEffects(t *testing.T) {
	te := newWireTestEngine(t)
	te.SetRole(false)

	if _, err := db.DB.Exec(`UPDATE security_crs_version SET auto_update=1, next_update='' WHERE id=1`); err != nil {
		t.Fatalf("seed crs schedule row: %v", err)
	}
	if _, err := db.DB.Exec(`UPDATE global_config SET threat_auto_update=1 WHERE id=1`); err != nil {
		t.Fatalf("seed threat business switch: %v", err)
	}
	te.StopLoop("threat")

	reconcileTaskEngineRole()

	if !te.IsMaster() {
		t.Fatal("对账后引擎角色必须回到 DB 的主节点角色")
	}
	if meta, ok := te.Lookup("crs"); !ok || meta.NextSlot == "" {
		t.Fatalf("升主对账必须重装规则库首槽, crs 元数据=%+v", meta)
	}
	if meta, ok := te.Lookup("threat"); !ok || !meta.LoopOn {
		t.Fatalf("升主对账必须按业务实态恢复调度, threat 元数据=%+v", meta)
	}
}
