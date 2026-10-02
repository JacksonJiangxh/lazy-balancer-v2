package services

// L5-66-01（第 66 轮审计 P4）：从端 applySnapshot 末段「渲染+强制重载」绕过
// CaddyOpLock——与重启 watcher（渲染 DB→/load，持 CaddyOpLock）交错时，跨同步
// commit 点的旧渲染可后到覆盖新配置，从节点静默回退上一版本（三通道自愈全
// 探不到）。修复=重载段包入 CaddyOpLock（Pull 路径锁不反向嵌套——锁内仅
// ApplyConfigForce 的 s.mu，叶操作）。

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"lazy-balancer-v2/internal/config"
	"lazy-balancer-v2/internal/models"
)

// Given CaddyOpLock 被预持（模拟并发的重启 watcher/规则写临界区），从端
// SyncService 指向就绪的 Caddy stub。
// When applySnapshot 执行到末段「渲染+ApplyConfigForce 强制重载」。
// Then 重载必须阻塞至 CaddyOpLock 释放（持锁期间不得完成），释放后照常完成。
func TestSyncService_applySnapshot_reload_blocks_while_caddy_op_lock_held(t *testing.T) {
	_, database := newClusterTestService(t)
	if _, err := database.Exec("UPDATE global_config SET is_master=0 WHERE id=1"); err != nil {
		t.Fatalf("set slave mode: %v", err)
	}
	caddyServer := httptest.NewServer(http.HandlerFunc(func(response http.ResponseWriter, _ *http.Request) {
		response.WriteHeader(http.StatusOK)
	}))
	defer caddyServer.Close()
	syncService := NewSyncService(database, &config.Config{CaddyAdminURL: caddyServer.URL}, NewCaddyService(caddyServer.URL))
	snapshot := v3SnapshotWithACMESection(models.ClusterSnapshot{
		Version:       7,
		Users:         []models.ClusterUser{{ID: 7, Username: "lock-order-admin", PasswordHash: "hash", Role: "admin", IsEnabled: true}},
		BasicSettings: models.ClusterBasicSettings{LogLevel: "info", Timezone: "Asia/Shanghai"},
	})

	CaddyOpLock.Lock()
	done := make(chan error, 1)
	go func() {
		done <- syncService.applySnapshot(context.Background(), snapshot)
	}()
	select {
	case err := <-done:
		CaddyOpLock.Unlock()
		t.Fatalf("applySnapshot 重载段在 CaddyOpLock 被预持期间完成（从端重载未入锁）, err=%v", err)
	case <-time.After(500 * time.Millisecond):
	}
	CaddyOpLock.Unlock()
	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("锁释放后 applySnapshot 失败: %v", err)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("锁释放后 applySnapshot 10s 内未完成")
	}
}
