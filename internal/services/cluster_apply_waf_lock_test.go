package services

// F-68-U2-02（第 68 轮审计 P3）：从端 applySnapshot 的 ApplyWafFileBundle 调用点
// 此前不入 wafFileMu——与 lbbak 导入（caller-side 持锁，config_backup_lbbak.go）、
// 三库更新器（内锁）与 BuildWafFileBundle 读相位（内锁）无互斥，同步落盘与导入/
// 更新交错可打出混合 rules 树/撕裂 xdb，并沿 waf_files 节扩散到集群。修复=调用
// 点持 WafFileLock（与 lbbak 同型 caller-side——ApplyWafFileBundle 本体不可内锁，
// lbbak 已持锁调用，内锁=双锁死锁）。锁序：该点不持 CaddyOpLock（重载段在
// cluster_apply.go:253 才取），wafFileMu 叶操作，无 AB-BA。

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
	"time"

	"lazy-balancer-v2/internal/config"
	"lazy-balancer-v2/internal/models"
)

// Given wafFileMu 被预持（模拟并发的 lbbak 导入文件相位），从节点 SyncService
// 指向就绪的主节点 stub（waf-files 端点返回与 ref 匹配的合法 bundle）。
// When applySnapshot 执行到安全数据落盘（ApplyWafFileBundle）。
// Then 落盘必须阻塞至 WafFileLock 释放（持锁期间不得完成），释放后照常完成。
func TestSyncService_applySnapshot_wafApply_blocks_while_waf_file_lock_held(t *testing.T) {
	_, database := newClusterTestService(t)
	if _, err := database.Exec("UPDATE global_config SET is_master=0 WHERE id=1"); err != nil {
		t.Fatalf("set slave mode: %v", err)
	}

	// 主节点文件树：bundle 与 ref 同源构建（先于预持锁——BuildWafFileBundle 内锁）。
	masterTree := t.TempDir()
	if err := os.MkdirAll(filepath.Join(masterTree, "crs", "rules"), 0755); err != nil {
		t.Fatal(err)
	}
	os.WriteFile(filepath.Join(masterTree, "crs", "rules", "a.conf"), []byte("SecRule X 1"), 0644)
	os.WriteFile(filepath.Join(masterTree, "crs", "VERSION"), []byte("v4.28.0"), 0644)
	restore := OverrideWafLivePathsForTest(filepath.Join(masterTree, "crs"), filepath.Join(masterTree, "ip2region.xdb"))
	bundle := BuildWafFileBundle()
	ref := BuildWafFileRef()
	restore()
	if bundle == nil || ref == nil || ref.CRSSha256 == "" {
		t.Fatalf("master bundle/ref build failed: bundle=%+v ref=%+v", bundle, ref)
	}
	// 从节点活动路径指向空的本地树（与 ref 必不符→触发安全数据同步分支）。
	slaveTree := t.TempDir()
	defer OverrideWafLivePathsForTest(filepath.Join(slaveTree, "crs"), filepath.Join(slaveTree, "ip2region.xdb"))()

	// 主节点 stub：waf-files 端点返回 bundle。
	masterServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/api/v1/cluster/sync/waf-files" {
			w.WriteHeader(http.StatusNotFound)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]interface{}{"data": bundle})
	}))
	defer masterServer.Close()
	if _, err := database.Exec("UPDATE global_config SET master_url=?, cluster_token=? WHERE id=1", masterServer.URL, "probe-token"); err != nil {
		t.Fatalf("seed master endpoint: %v", err)
	}
	// Caddy stub：末段重载就绪。
	caddyServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer caddyServer.Close()
	syncService := NewSyncService(database, &config.Config{CaddyAdminURL: caddyServer.URL}, NewCaddyService(caddyServer.URL))
	snapshot := v3SnapshotWithACMESection(models.ClusterSnapshot{
		Version:       7,
		Users:         []models.ClusterUser{{ID: 7, Username: "waf-lock-admin", PasswordHash: "hash", Role: "admin", IsEnabled: true}},
		BasicSettings: models.ClusterBasicSettings{LogLevel: "info", Timezone: "Asia/Shanghai"},
		WafFiles:      ref,
	})

	WafFileLock().Lock()
	done := make(chan error, 1)
	go func() {
		done <- syncService.applySnapshot(context.Background(), snapshot)
	}()
	select {
	case err := <-done:
		WafFileLock().Unlock()
		t.Fatalf("applySnapshot 安全数据落盘在 wafFileMu 被预持期间完成（调用点未入锁）, err=%v", err)
	case <-time.After(500 * time.Millisecond):
	}
	WafFileLock().Unlock()
	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("锁释放后 applySnapshot 失败: %v", err)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("锁释放后 applySnapshot 10s 内未完成")
	}
	// 落盘真实发生：从节点本地树与主节点一致。
	if got, err := os.ReadFile(filepath.Join(slaveTree, "crs", "rules", "a.conf")); err != nil || string(got) != "SecRule X 1" {
		t.Fatalf("同步落盘内容=%q err=%v, want 主节点 rules 已落盘", string(got), err)
	}
}
