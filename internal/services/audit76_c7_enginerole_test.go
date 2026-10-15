package services

// C7（第 76 轮集群/任务域）：Promote/BecomeSlave 引擎角色显式直调收口钉。
// 原实现仅经 crsManager/ip2regionMgr/threatMgr 的 SetMasterRole 间接传播
//（三者在场时各自转调 TaskEngine().SetRole 后提前返回），三管理器同时为 nil
// 时引擎角色不翻转——master-only 任务在从节点仍可手动调度/升主后不恢复调度
//（生产 main.go 恒初始化三管理器故不可达，防御性收敛）。
// 钉法：引擎在场+三管理器全 nil（newWireTestEngine 装配不含管理器）+注册
// RoleMasterOnly 探针任务，经角色门 Trigger 判定引擎角色——旧实现降级后
// Trigger 仍成功=红。
// 夹具次序（MEMORY 教训）：newWireTestEngine 会 db.Initialize 换库，Cluster
// Service 直接构造在换库后的 db.DB 上，不再二次 Initialize。

import (
	"context"
	"testing"

	"lazy-balancer-v2/internal/db"
	"lazy-balancer-v2/internal/models"
	"lazy-balancer-v2/internal/taskengine"
)

// registerRoleProbeTask 注册 RoleMasterOnly 触发型探针（Run 空体），返回经
// 角色门探测引擎角色的闭包：nil=引擎视本节点为主节点。
func registerRoleProbeTask(t *testing.T, te *taskengine.Engine) func() error {
	t.Helper()
	if err := te.Register(taskengine.Descriptor{
		ID: "r76-role-probe", Family: "test", Name: "角色探针",
		Category: "系统", Kind: taskengine.KindOneshot,
		RunsOn: taskengine.RoleMasterOnly,
		Run:    func(rc taskengine.RunContext) error { return nil },
	}); err != nil {
		t.Fatalf("register probe: %v", err)
	}
	return func() error { return te.Trigger("r76-role-probe", "manual", "test") }
}

func TestBecomeSlave_flipsEngineRoleWithManagersNil(t *testing.T) {
	te := newWireTestEngine(t)
	probe := registerRoleProbeTask(t, te)
	if err := probe(); err != nil {
		t.Fatalf("given: 主节点态探针触发应通过角色门: %v", err)
	}

	service := NewClusterService(db.DB, nil, "")
	if err := service.BecomeSlave(context.Background(), "https://master.example", models.ClusterRegistration{RegistrationID: 9, RegistrationSecret: "secret"}); err != nil {
		t.Fatalf("become slave: %v", err)
	}

	if err := probe(); err == nil {
		t.Fatal("降级（三管理器全 nil）后 master-only 探针必须被角色门拒绝（旧行为：引擎角色未翻转 → 触发成功 → 必红）")
	}
}

func TestPromote_flipsEngineRoleWithManagersNil(t *testing.T) {
	te := newWireTestEngine(t)
	te.SetRole(false) // 从节点态种子
	probe := registerRoleProbeTask(t, te)
	if err := probe(); err == nil {
		t.Fatal("given: 从节点态探针必须被角色门拒绝")
	}

	service := NewClusterService(db.DB, nil, "")
	// 库态种子与引擎角色一致（IsMaster 读库判重——引擎 SetRole(false) 不落库）。
	if _, err := db.DB.Exec(`UPDATE global_config SET is_master=0 WHERE id=1`); err != nil {
		t.Fatalf("seed slave db state: %v", err)
	}
	if err := service.Promote(context.Background()); err != nil {
		t.Fatalf("promote: %v", err)
	}

	if err := probe(); err != nil {
		t.Fatalf("升主（三管理器全 nil）后 master-only 探针应通过角色门: %v", err)
	}
}
