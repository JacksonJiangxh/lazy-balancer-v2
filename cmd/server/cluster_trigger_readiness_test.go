package main

// 集群版本触发器就绪门的启动序钉测试：触发器安装必须早于任务引擎启动。
//
// HTTP 中间件的 fail-closed 只覆盖请求链；引擎内的周期任务直接经主库句柄写
// 同步表。旧启动序（InitTaskEngine 早于 SetupRouter，安装只在装配中间件时
// 发生）在安装失败时让后台写者照常落库却不 bump cluster_version——从节点
// 304 门恒定命中旧指纹，主端稳态变更永不传播，任务日志全绿。

import (
	"os"
	"strings"
	"testing"

	"lazy-balancer-v2/internal/db"
	"lazy-balancer-v2/internal/middleware"
)

// Given 全新库（等价旧启动序：触发器尚未安装）。
// When 后台任务形态直接经主库句柄写同步表。
// Then cluster_version 不变（「fail-closed 假象」的实质：引擎在写、版本没动）；
// 就绪门安装触发器后，同一写入必须 bump。
func TestClusterVersionTriggerReadinessGateBeforeBackgroundWriters(t *testing.T) {
	oldDB, oldMetricsDB, oldAuditDB := db.DB, db.MetricsDB, db.AuditDB
	if err := db.Initialize(t.TempDir()); err != nil {
		t.Fatalf("initialize database: %v", err)
	}
	t.Cleanup(func() {
		_ = db.Close()
		db.DB, db.MetricsDB, db.AuditDB = oldDB, oldMetricsDB, oldAuditDB
		db.SetDB(oldDB)
	})
	version := func() int64 {
		var v int64
		if err := db.DB.QueryRow(`SELECT COALESCE(cluster_version,0) FROM global_config WHERE id=1`).Scan(&v); err != nil {
			t.Fatalf("read cluster_version: %v", err)
		}
		return v
	}

	before := version()
	if _, err := db.DB.Exec(`INSERT INTO lb_rules (caddy_id,name,protocol,listen_port) VALUES ('gate_rule','gate','http',8080)`); err != nil {
		t.Fatalf("background-style write: %v", err)
	}
	if got := version(); got != before {
		t.Fatalf("无触发器时后台写 bump 了 cluster_version（%d→%d）——夹具前提不成立", before, got)
	}

	// When 启动门（生产路径在 services.InitTaskEngine 之前调用）
	if err := middleware.InstallClusterVersionTriggers(db.DB); err != nil {
		t.Fatalf("install cluster version triggers: %v", err)
	}
	if _, err := db.DB.Exec(`UPDATE lb_rules SET name='gate2' WHERE caddy_id='gate_rule'`); err != nil {
		t.Fatalf("background-style update: %v", err)
	}
	if got := version(); got <= before {
		t.Fatalf("触发器就绪后后台写未 bump cluster_version（%d，仍为 %d），从节点将永久滞留", got, before)
	}
}

// 启动顺序可核验：就绪门必须出现在任务引擎启动之前（引擎启动即可能触发
// 配置载入与周期任务写同步表）。
func TestClusterTriggerReadinessGatePrecedesTaskEngineStart(t *testing.T) {
	src, err := os.ReadFile("main.go")
	if err != nil {
		t.Fatalf("read main.go: %v", err)
	}
	gate := strings.Index(string(src), "middleware.InstallClusterVersionTriggers(db.GetDB())")
	engine := strings.Index(string(src), "services.InitTaskEngine(cfg.CaddyAdminURL")
	if gate < 0 {
		t.Fatal("main.go 缺少触发器就绪门（middleware.InstallClusterVersionTriggers）")
	}
	if engine < 0 {
		t.Fatal("main.go 缺少任务引擎启动点（services.InitTaskEngine）")
	}
	if gate > engine {
		t.Fatal("触发器就绪门必须早于 services.InitTaskEngine——后台周期任务不经 HTTP 链，缺触发器时写不 bump 版本")
	}
}
