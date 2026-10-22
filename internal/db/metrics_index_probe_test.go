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

// 冗余索引回收同理：初始化时先探测 sqlite_master，fresh 库/已回收库零 DDL
// （此前每次启动无条件两条 DROP INDEX），仅存量库索引真实在位时执行一次。
func TestInitMetricsSchema_skipsRedundantIndexDropsWhenAbsent(t *testing.T) {
	metrics, err := openAndPingMetricsDB(filepath.Join(t.TempDir(), "metrics-index-drop-probe.db"))
	if err != nil {
		t.Fatalf("open metrics database: %v", err)
	}
	t.Cleanup(func() { _ = metrics.Close() })

	probesBefore, dropsBefore := metricsRedundantIndexProbes.Load(), metricsRedundantIndexDrops.Load()

	// Given fresh 库：两条冗余索引均不存在。
	if err := initMetricsSchema(metrics); err != nil {
		t.Fatalf("first init: %v", err)
	}
	if got := metricsRedundantIndexProbes.Load() - probesBefore; got != 2 {
		t.Fatalf("首次启动探测次数=%d, want 2", got)
	}
	if got := metricsRedundantIndexDrops.Load() - dropsBefore; got != 0 {
		t.Fatalf("首次启动回收次数=%d, want 0（不存在即跳过 DROP）", got)
	}

	// When 存量库形态：两条冗余索引在位，再次初始化。
	if _, err := metrics.Exec(`CREATE INDEX idx_metrics_rule ON metrics_history(rule_id);
		CREATE INDEX idx_security_event_target_rollup_minute ON security_event_target_rollup(minute)`); err != nil {
		t.Fatalf("seed legacy indexes: %v", err)
	}
	if err := initMetricsSchema(metrics); err != nil {
		t.Fatalf("second init: %v", err)
	}

	// Then 两条索引各回收一次，且已从 schema 消失。
	if got := metricsRedundantIndexDrops.Load() - dropsBefore; got != 2 {
		t.Fatalf("存量库回收次数=%d, want 2", got)
	}
	var remaining int
	if err := metrics.QueryRow(`SELECT COUNT(*) FROM sqlite_master WHERE type='index' AND name IN ('idx_metrics_rule','idx_security_event_target_rollup_minute')`).Scan(&remaining); err != nil {
		t.Fatal(err)
	}
	if remaining != 0 {
		t.Fatalf("冗余索引残留=%d, want 0", remaining)
	}

	// And 再初始化一次：探测仍执行，但零回收。
	if err := initMetricsSchema(metrics); err != nil {
		t.Fatalf("third init: %v", err)
	}
	if got := metricsRedundantIndexDrops.Load() - dropsBefore; got != 2 {
		t.Fatalf("已回收库重复回收=%d, want 2", got)
	}
}
