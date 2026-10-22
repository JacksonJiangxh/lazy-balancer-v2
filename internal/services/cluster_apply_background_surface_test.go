package services

// 从节点「快照已提交、Caddy 重载失败」分叉的全局可观测性钉测：
// 重载失败必须登记后台失败面（BackgroundApplyClusterSync 来源——状态接口
// background_apply_error 与全局横幅的消费源）；补偿重拉成功后清除。

import (
	"context"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"

	"lazy-balancer-v2/internal/config"
	"lazy-balancer-v2/internal/models"
)

func TestSyncService_applySnapshot_reloadFailureSurfacesBackgroundBanner(t *testing.T) {
	_, database := newClusterTestService(t)
	if _, err := database.Exec("UPDATE global_config SET is_master=0 WHERE id=1"); err != nil {
		t.Fatalf("set slave mode: %v", err)
	}
	// 失败面进程内存储——用例间隔离（与 applystatus_test 同口径）。
	backgroundApplyStore.mu.Lock()
	backgroundApplyStore.failures = map[string]BackgroundApplyFailure{}
	backgroundApplyStore.mu.Unlock()
	t.Cleanup(func() {
		backgroundApplyStore.mu.Lock()
		backgroundApplyStore.failures = map[string]BackgroundApplyFailure{}
		backgroundApplyStore.mu.Unlock()
	})

	var failLoads atomic.Bool
	failLoads.Store(true)
	caddyServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodPost && r.URL.Path == "/load" && failLoads.Load() {
			w.WriteHeader(http.StatusBadGateway)
			return
		}
		w.WriteHeader(http.StatusOK)
	}))
	defer caddyServer.Close()
	syncService := NewSyncService(database, &config.Config{CaddyAdminURL: caddyServer.URL}, NewCaddyService(caddyServer.URL))
	snapshot := v3SnapshotWithACMESection(models.ClusterSnapshot{
		Version:       7,
		Users:         []models.ClusterUser{{ID: 7, Username: "banner-admin", PasswordHash: "hash", Role: "admin", IsEnabled: true}},
		BasicSettings: models.ClusterBasicSettings{LogLevel: new("info"), Timezone: new("Asia/Shanghai")},
	})

	// 首轮：/load 持续 502——快照提交成功、重载失败。
	if err := syncService.applySnapshot(context.Background(), snapshot); err != nil {
		t.Fatalf("重载失败不应回滚已提交快照（applySnapshot 应返回 nil）: %v", err)
	}
	snap := BackgroundApplyFailureSnapshot()
	if snap == nil || snap.Source != string(BackgroundApplyClusterSync) {
		t.Fatalf("从节点重载失败未登记后台失败面（全局横幅/状态接口不可见）: %+v", snap)
	}

	// 补偿形态：重载失败标记驱动下轮强制重载；Caddy 恢复后成功收敛，
	// 失败面随之清除。
	failLoads.Store(false)
	if err := syncService.applySnapshot(context.Background(), snapshot); err != nil {
		t.Fatalf("补偿重拉 applySnapshot 失败: %v", err)
	}
	if snap := BackgroundApplyFailureSnapshot(); snap != nil {
		t.Fatalf("补偿重载成功后失败面未清除: %+v", snap)
	}
}
