package db

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// metrics 库不是纯「可丢弃遥测」：同库承载 security_events（安全事件历史，
// 攻击取证/触发详情）与 threat 大屏预聚合。损坏隔离重建必须明示丢弃范围并
// 落系统审计——否则安全事件历史静默消失，日志只有一行 "metrics history
// reset"。
func TestInitializeMetricsDB_quarantineDisclosesSecurityEventHistoryLoss(t *testing.T) {
	dir := t.TempDir()
	dbPath := filepath.Join(dir, MetricsDBFilename)
	if err := os.WriteFile(dbPath, make([]byte, 8192), 0600); err != nil {
		t.Fatal(err)
	}
	drainSystemAuditBuffer()

	if err := InitializeMetricsDB(dir); err != nil {
		t.Fatalf("InitializeMetricsDB on corrupted file: %v", err)
	}
	defer func() { _ = MetricsDB.Close(); MetricsDB = nil }()

	entries := drainSystemAuditBuffer()
	var disclosed bool
	for _, entry := range entries {
		if !strings.Contains(entry.detail, "隔离") {
			continue
		}
		if !strings.Contains(entry.detail, "安全事件") {
			t.Fatalf("隔离重建留痕未披露安全事件历史丢失: %+v", entry)
		}
		if !strings.Contains(entry.detail, "指标历史") {
			t.Fatalf("隔离重建留痕未披露指标历史丢失: %+v", entry)
		}
		disclosed = true
	}
	if !disclosed {
		t.Fatalf("metrics 库隔离重建缺少系统审计留痕: %+v", entries)
	}
}
