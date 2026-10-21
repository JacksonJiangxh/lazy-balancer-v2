package db

// 启动期重复事务查重的一次性门：唯一部分索引已在位时，第二次启动必须零
// 全表 GROUP BY 查重（事件表百万行时该扫描是纯启动成本）。

import (
	"path/filepath"
	"testing"
)

func TestEnsureSecurityEventsTransactionIndex_skipsDedupeScanWhenIndexExists(t *testing.T) {
	metrics, err := openAndPingMetricsDB(filepath.Join(t.TempDir(), "metrics-index-probe.db"))
	if err != nil {
		t.Fatalf("open metrics database: %v", err)
	}
	t.Cleanup(func() { _ = metrics.Close() })

	scansBefore, skipsBefore := securityEventsTransactionIndexScans.Load(), securityEventsTransactionIndexSkips.Load()

	// Given 首次初始化：索引缺失 → 走查重 + 建索引路径。
	if err := initMetricsSchema(metrics); err != nil {
		t.Fatalf("first init: %v", err)
	}
	if got := securityEventsTransactionIndexScans.Load() - scansBefore; got != 1 {
		t.Fatalf("首次启动查重扫描=%d, want 1", got)
	}
	if got := securityEventsTransactionIndexSkips.Load() - skipsBefore; got != 0 {
		t.Fatalf("首次启动跳过次数=%d, want 0", got)
	}

	// When 二次初始化（等价于重启：索引已在位）。
	if err := initMetricsSchema(metrics); err != nil {
		t.Fatalf("second init: %v", err)
	}

	// Then 零查重扫描（sqlite_master 命中唯一索引直接跳过）。
	if got := securityEventsTransactionIndexScans.Load() - scansBefore; got != 1 {
		t.Fatalf("二次启动累计查重扫描=%d, want 1（重启不得重复全表查重）", got)
	}
	if got := securityEventsTransactionIndexSkips.Load() - skipsBefore; got != 1 {
		t.Fatalf("二次启动跳过次数=%d, want 1", got)
	}

	// And 存量库形态（索引被删）仍会重新查重并补建索引——探测门不吞真实迁移。
	if _, err := metrics.Exec(`DROP INDEX idx_security_events_transaction`); err != nil {
		t.Fatal(err)
	}
	if err := initMetricsSchema(metrics); err != nil {
		t.Fatalf("reinit after index drop: %v", err)
	}
	if got := securityEventsTransactionIndexScans.Load() - scansBefore; got != 2 {
		t.Fatalf("索引缺失后查重扫描累计=%d, want 2", got)
	}
	var indexCount int
	if err := metrics.QueryRow(`SELECT COUNT(*) FROM sqlite_master WHERE type='index' AND name='idx_security_events_transaction'`).Scan(&indexCount); err != nil {
		t.Fatal(err)
	}
	if indexCount != 1 {
		t.Fatalf("索引重建后条数=%d, want 1", indexCount)
	}
}
