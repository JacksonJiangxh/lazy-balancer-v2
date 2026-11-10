package services

import (
	"context"
	"database/sql"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"

	"lazy-balancer-v2/internal/config"
	"lazy-balancer-v2/internal/models"
)

// 从端同步状态（last_sync_error 及其补偿标记）只能在从节点语境落库。
// Promote 提交后 master_url 被清空、last_sync_error 被清空，但升主前已进入
// Report/Pull 的落库回调（persistSyncError 用 WithoutCancel 跨越 Stop 取消）
// 可能晚于提交执行——没有角色谓词就会把「状态上报失败: …」写回新主节点，且
// 全仓没有第二处清空点（只剩降级/导入）。

func readLastSyncError(t *testing.T, database *sql.DB) string {
	t.Helper()
	var stored string
	if err := database.QueryRow("SELECT COALESCE(last_sync_error,'') FROM global_config WHERE id=1").Scan(&stored); err != nil {
		t.Fatalf("read last_sync_error: %v", err)
	}
	return stored
}

func setNodeMasterRole(t *testing.T, database *sql.DB, isMaster bool) {
	t.Helper()
	role := 0
	if isMaster {
		role = 1
	}
	if _, err := database.Exec("UPDATE global_config SET is_master=? WHERE id=1", role); err != nil {
		t.Fatalf("set node role: %v", err)
	}
}

func TestSyncService_persistSyncError_roleGate(t *testing.T) {
	// Given：节点已是主节点（升主刚清空 last_sync_error）
	_, database := newClusterTestService(t)
	service := NewSyncService(database, &config.Config{DataDir: t.TempDir()}, nil)
	setNodeMasterRole(t, database, true)

	// When：在途上报失败的落库回调晚于 Promote 提交执行
	service.persistSyncError(context.Background(), "状态上报失败: probe", models.SyncErrorCodeTransportError)

	// Then：主节点的同步状态列不得被旧从端写回
	if stored := readLastSyncError(t, database); stored != "" {
		t.Fatalf("master last_sync_error=%q, want empty（升主后从端同步错误不得落库）", stored)
	}

	// When：从节点语境下同一写入
	setNodeMasterRole(t, database, false)
	service.persistSyncError(context.Background(), "状态上报失败: probe", models.SyncErrorCodeTransportError)

	// Then：照常落库（从端语义不回归）
	msg, code := decodeSyncError(readLastSyncError(t, database))
	if msg != "状态上报失败: probe" || code != models.SyncErrorCodeTransportError {
		t.Fatalf("slave last_sync_error=(%q,%q), want transport error message", msg, code)
	}

	// When：升主后成功路径的清空回调同样晚到
	setNodeMasterRole(t, database, true)
	service.persistSyncError(context.Background(), "", "")

	// Then：清空同样不生效（主节点的该列已由 Promote 管理）
	if stored := readLastSyncError(t, database); !strings.Contains(stored, "状态上报失败: probe") {
		t.Fatalf("master last_sync_error=%q, want unchanged slave-era value", stored)
	}
}

func TestMarkStartupFallback_roleGate(t *testing.T) {
	_, database := newClusterTestService(t)
	setNodeMasterRole(t, database, true)

	// 主节点启动时的回退标记没有任何消费方（304 补偿只发生在从端 Pull）：
	// 写入必须是 no-op，避免主节点带出「启动时渲染被拒」的从端文案。
	if err := MarkStartupFallbackPending(context.Background(), database); err != nil {
		t.Fatalf("MarkStartupFallbackPending(master): %v", err)
	}
	if stored := readLastSyncError(t, database); stored != "" {
		t.Fatalf("master last_sync_error=%q, want empty after pending marker", stored)
	}
	if err := MarkStartupFallbackFailed(context.Background(), database, errors.New("boom")); err != nil {
		t.Fatalf("MarkStartupFallbackFailed(master): %v", err)
	}
	if stored := readLastSyncError(t, database); stored != "" {
		t.Fatalf("master last_sync_error=%q, want empty after failed marker", stored)
	}

	// 从节点照常写入两种标记
	setNodeMasterRole(t, database, false)
	if err := MarkStartupFallbackPending(context.Background(), database); err != nil {
		t.Fatalf("MarkStartupFallbackPending(slave): %v", err)
	}
	if msg, _ := decodeSyncError(readLastSyncError(t, database)); !strings.HasPrefix(msg, syncReloadFailureMarkerPrefix) {
		t.Fatalf("slave last_sync_error=%q, want reload-failure marker", msg)
	}
	if err := MarkStartupFallbackFailed(context.Background(), database, errors.New("boom")); err != nil {
		t.Fatalf("MarkStartupFallbackFailed(slave): %v", err)
	}
	msg, code := decodeSyncError(readLastSyncError(t, database))
	if !strings.HasPrefix(msg, syncReloadFailureMarkerPrefix) || !strings.Contains(msg, "boom") {
		t.Fatalf("slave last_sync_error=%q, want failed marker with cause", msg)
	}
	if code != models.SyncErrorCodeApplyFailed {
		t.Fatalf("slave sync error code=%q, want apply_failed", code)
	}
}

func TestSyncService_Report_skipsOnMasterNode(t *testing.T) {
	// Given：主节点残留了从端时代的 master_url/令牌（翻转窗口）
	_, database := newClusterTestService(t)
	var hits atomic.Int32
	master := httptest.NewServer(http.HandlerFunc(func(response http.ResponseWriter, _ *http.Request) {
		hits.Add(1)
		response.WriteHeader(http.StatusOK)
	}))
	defer master.Close()
	if _, err := database.Exec("UPDATE global_config SET is_master=1, master_url=?, cluster_token='cluster-token' WHERE id=1", master.URL); err != nil {
		t.Fatal(err)
	}
	service := NewSyncService(database, &config.Config{DataDir: t.TempDir()}, nil)

	// When
	if err := service.Report(context.Background()); err != nil {
		t.Fatalf("Report(master): %v", err)
	}

	// Then：不得发起上报（否则必然失败并污染 last_sync_error/审计）
	if got := hits.Load(); got != 0 {
		t.Fatalf("master report requests=%d, want 0", got)
	}

	// When：同一服务在从节点语境下上报
	setNodeMasterRole(t, database, false)
	if err := service.Report(context.Background()); err != nil {
		t.Fatalf("Report(slave): %v", err)
	}

	// Then：正常上报（从端通道不回归）
	if got := hits.Load(); got != 1 {
		t.Fatalf("slave report requests=%d, want 1", got)
	}
}
