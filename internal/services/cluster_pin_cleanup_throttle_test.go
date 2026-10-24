package services

import (
	"os"
	"path/filepath"
	"testing"

	"lazy-balancer-v2/internal/db"
)

// pin 清理失败会被 Snapshot（每次 Pull）与主节点巡检按周期重试，同一失败
// 稳定复现时只应留一条「清理失败」审计；恢复成功清空状态后再次失败须重记。
func TestCleanupClusterPin_failureAuditThrottledAcrossRetries(t *testing.T) {
	service, _ := newClusterTestService(t)
	auditDB := db.AuditDB
	root := t.TempDir()
	pinPath := filepath.Join(root, "pin")
	obstructPin := func() {
		t.Helper()
		if err := os.MkdirAll(pinPath, 0o755); err != nil {
			t.Fatal(err)
		}
		// 非空目录让 os.Remove 返回 ENOTEMPTY（稳定复现的失败形态，
		// 不会被当作 pin 已不存在而静默跳过）。
		if err := os.WriteFile(filepath.Join(pinPath, "child"), []byte("x"), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	obstructPin()

	// When：失败形态不变，直接调用与重试路径各触发多次
	service.cleanupClusterPin(pinPath, "http://master.example:8000")
	for range 3 {
		service.retryPendingPinCleanup()
	}
	// Then：只留一条失败审计
	if got := countAuditRows(t, auditDB, "清理失败", "证书指纹"); got != 1 {
		t.Fatalf("repeated pin cleanup failures wrote %d audit rows, want 1", got)
	}

	// When：恢复（pin 变为普通文件并清理成功）
	if err := os.RemoveAll(pinPath); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(pinPath, []byte("fingerprint\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	service.retryPendingPinCleanup()
	if got := countAuditRows(t, auditDB, "清理", "证书指纹"); got != 1 {
		t.Fatalf("successful pin cleanup wrote %d audit rows, want 1", got)
	}

	// When：恢复后再次出现同一失败（成功分支已清空去重状态）→ 须重新留痕
	obstructPin()
	service.cleanupClusterPin(pinPath, "http://master.example:8000")
	if got := countAuditRows(t, auditDB, "清理失败", "证书指纹"); got != 2 {
		t.Fatalf("failure after recovery wrote %d audit rows, want 2", got)
	}
}
