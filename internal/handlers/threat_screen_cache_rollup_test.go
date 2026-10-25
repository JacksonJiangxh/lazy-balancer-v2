package handlers

import (
	"testing"
	"time"
)

// 同步固化会改写窗口内分钟行——读 rollup 分钟行的两份缓存（维度聚合与
// top_targets）必须一起失效。只清前者会让同一次响应的「被攻击目标 Top3」
// 仍返回固化前的数据，与已重算的总量/国家口径短暂分叉。
func TestInvalidateThreatScreenRollupCaches_clearsTopTargets(t *testing.T) {
	resetThreatScreenCachesForTest()
	t.Cleanup(resetThreatScreenCachesForTest)

	targetKey := topTargetsCacheKey{sinceMinute: "2026-10-25 10:00"}
	topTargetsCacheMu.Lock()
	topTargetsCache[targetKey] = topTargetsCacheEntry{
		targets:   []threatTopTarget{{Name: "site-a", Value: 7}},
		expiresAt: time.Now().Add(time.Minute),
	}
	topTargetsCacheMu.Unlock()

	aggKey := threatRollupDimAggregateKey{sinceMinute: "2026-10-25 10:00"}
	threatRollupDimAggregateCacheMu.Lock()
	threatRollupDimAggregateCache[aggKey] = threatRollupDimAggregateEntry{expiresAt: time.Now().Add(time.Minute)}
	threatRollupDimAggregateCacheMu.Unlock()

	invalidateThreatScreenRollupCaches()

	topTargetsCacheMu.Lock()
	_, targetLeft := topTargetsCache[targetKey]
	topTargetsCacheMu.Unlock()
	if targetLeft {
		t.Fatal("固化后 top_targets 缓存必须一并失效（否则同一次响应返回固化前 Top3）")
	}

	threatRollupDimAggregateCacheMu.Lock()
	_, aggLeft := threatRollupDimAggregateCache[aggKey]
	threatRollupDimAggregateCacheMu.Unlock()
	if aggLeft {
		t.Fatal("固化后维度聚合缓存必须失效")
	}
}

// 活跃攻击源缓存 TTL 必须覆盖大屏 30s 轮询周期：小于轮询周期时每轮必然
// miss，缓存与代码复杂度为零收益，10 分钟窗口全扫照常每轮发生。
func TestThreatActiveSourcesCacheTTL_coversPollingInterval(t *testing.T) {
	const polling = 30 * time.Second
	if threatActiveSourcesCacheTTL < polling {
		t.Fatalf("threatActiveSourcesCacheTTL=%v, want >= %v（与轮询同周期，否则缓存永不命中）", threatActiveSourcesCacheTTL, polling)
	}
}

// 窗口起点锚点：秒级入参截到分钟（缓存键口径），异形短值原样返回而不得
// 直接 [:16]（带外写库/异形导入的 19 字符以下 event_time 会让处理器 panic）。
func TestThreatMinuteAnchor_guardsShortValues(t *testing.T) {
	cases := []struct{ in, want string }{
		{"2026-10-25 10:00:00", "2026-10-25 10:00"},
		{"2026-10-25 10:00", "2026-10-25 10:00"},
		{"2027-01-01", "2027-01-01"},
		{"", ""},
	}
	for _, c := range cases {
		if got := threatMinuteAnchor(c.in); got != c.want {
			t.Errorf("threatMinuteAnchor(%q)=%q, want %q", c.in, got, c.want)
		}
	}
}
