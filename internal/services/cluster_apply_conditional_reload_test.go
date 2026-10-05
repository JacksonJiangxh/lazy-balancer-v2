package services

// F-L5-68-01（第 68 轮审计 P4）：从端 applySnapshot 尾段此前无条件
// CaddyOpLock{ApplyConfigForce}——主节点排程列/状态列等纯簿记变更（版本行
// next_update/update_status/last_checked 族，不进节哈希，经
// snapshotSecurityVersionRowsDiffer 差分门控重放） bump 快照版本后，从端渲染
// 输入零变化也整轮 /load（Caddy 全量 provision 重放）。修复=渲染数据未变跳过
// /load：三节哈希跳过 + WAF 数据文件无变化 + 证书轴无变化 + 无重载失败补偿
// 标记（标记在=上轮重载失败，本轮必须强制重载，304 补偿通道的语义终点；
// 标记由事务内「记录同步状态」清空，须在事务前捕获）。last_good 兼容：渲染
// 未变则既有 last_good 仍是当前运行配置的准确快照。

import (
	"context"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"

	"lazy-balancer-v2/internal/config"
	"lazy-balancer-v2/internal/models"
)

func TestSyncService_applySnapshot_skipsReloadWhenOnlyBookkeepingChanges(t *testing.T) {
	service, database := newClusterTestService(t)
	if _, err := database.Exec("UPDATE global_config SET is_master=0 WHERE id=1"); err != nil {
		t.Fatalf("set slave mode: %v", err)
	}
	var mu sync.Mutex
	loads := 0
	caddyServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodPost && r.URL.Path == "/load" {
			mu.Lock()
			loads++
			mu.Unlock()
		}
		w.WriteHeader(http.StatusOK)
	}))
	defer caddyServer.Close()
	syncService := NewSyncService(database, &config.Config{CaddyAdminURL: caddyServer.URL}, NewCaddyService(caddyServer.URL))
	// 种子不含 security 表行——安全节经 JSON 文本列回放存在字节归一差异
	// （applySecurityTables 的 snapshotJSONText 通道），回放后重建哈希与记账
	// 哈希分叉会走漂移重放而非哈希跳过，干扰本测试的「无变化」形态。
	// users/rules 节经显式列回放，往返哈希稳定（生产漂移守卫依赖的同一不变式）。
	for _, stmt := range []string{
		`INSERT INTO lb_rules (caddy_id,name,protocol,domain,listen_port,enabled) VALUES ('lb_dg','dg','http','dg.example',80,1)`,
		`INSERT INTO upstreams (rule_id,host,port,weight,enabled) VALUES ('lb_dg','127.0.0.1',8080,1,1)`,
		`INSERT INTO path_rules (rule_id,sort_order,match_type,path) VALUES ('lb_dg',0,'prefix','/api')`,
		`INSERT INTO users (id,username,password_hash,role,is_enabled,last_login) VALUES (1,'admin','h','admin',1,datetime('now'))`,
		`INSERT INTO api_keys (name,key_hash,key_prefix,created_by,is_enabled,last_used) VALUES ('k','kh','kp',1,1,datetime('now'))`,
		`INSERT INTO security_crs_version (id,version) VALUES (1,'v4.0.0') ON CONFLICT(id) DO UPDATE SET version=excluded.version`,
		`INSERT INTO security_ip2region_version (id,version) VALUES (1,'v3.17.0') ON CONFLICT(id) DO UPDATE SET version=excluded.version`,
	} {
		if _, err := database.Exec(stmt); err != nil {
			t.Fatalf("seed %q: %v", stmt, err)
		}
	}
	loadCount := func() int {
		mu.Lock()
		defer mu.Unlock()
		return loads
	}
	// 基准快照取本地规范构建（与 applySnapshot 的 previous 同源）——载荷即
	// 从端重建口径，二次应用时节判定走「哈希一致」而非漂移重放。
	base, err := service.clusterSnapshotBypassingCache(context.Background())
	if err != nil {
		t.Fatalf("build canonical snapshot: %v", err)
	}
	withVersion := func(v int) models.ClusterSnapshot {
		snap := base
		snap.Version = v
		return snap
	}

	// Given 首轮应用（v7：节哈希记账为空，全节首次应用）——必须 /load。
	if err := syncService.applySnapshot(context.Background(), withVersion(7)); err != nil {
		t.Fatalf("apply v7: %v", err)
	}
	if got := loadCount(); got != 1 {
		t.Fatalf("首轮应用后 /load 次数=%d, want 1（全节首次应用必须重载）", got)
	}

	// When v8 节载荷逐字节相同、仅版本/簿记推进（版本行排程列变化为载体）。
	v8 := withVersion(8)
	v8.SecurityCRSVersion = append([]models.ClusterSecurityCRSVersion{}, base.SecurityCRSVersion...)
	if len(v8.SecurityCRSVersion) > 0 {
		v8.SecurityCRSVersion[0].NextUpdate = "2026-10-06 04:00:00"
		v8.SecurityCRSVersion[0].LastChecked = "2026-10-05 04:00:00"
	}
	if err := syncService.applySnapshot(context.Background(), v8); err != nil {
		t.Fatalf("apply v8: %v", err)
	}
	// Then 不发生 /load（渲染输入零变化）。
	if got := loadCount(); got != 1 {
		t.Fatalf("仅簿记变化的快照应用后 /load 次数=%d, want 1（渲染输入无变化应跳过重载）", got)
	}

	// When v9 载荷不变但重载失败补偿标记在（上轮 apply 后 /load 失败的 304 补偿轮）。
	if _, err := database.Exec("UPDATE global_config SET last_sync_error=? WHERE id=1",
		encodeSyncError("apply_ok_reload_failed: probe", models.SyncErrorCodeApplyFailed)); err != nil {
		t.Fatalf("seed reload failure marker: %v", err)
	}
	if err := syncService.applySnapshot(context.Background(), withVersion(9)); err != nil {
		t.Fatalf("apply v9: %v", err)
	}
	// Then 补偿标记击穿跳过——必须 /load（304 漂移守卫兼容）。
	if got := loadCount(); got != 2 {
		t.Fatalf("补偿标记在时 /load 次数=%d, want 2（标记在必须强制重载）", got)
	}

	// When v10 渲染输入真实变化（新增规则→rules 节哈希变化）。
	v10 := withVersion(10)
	v10.Rules = append(append([]models.LbRule{}, base.Rules...),
		models.LbRule{CaddyID: "lb_reload_pin", Name: "pin", Protocol: "http", Domain: "pin.example.com", ListenPort: 8081, Enabled: true})
	v10.SectionHashes = ComputeSnapshotSectionHashes(&v10)
	if err := syncService.applySnapshot(context.Background(), v10); err != nil {
		t.Fatalf("apply v10: %v", err)
	}
	// Then 规则变化仍重载（回归钉）。
	if got := loadCount(); got != 3 {
		t.Fatalf("规则变化后 /load 次数=%d, want 3（渲染输入变化必须重载）", got)
	}
}
