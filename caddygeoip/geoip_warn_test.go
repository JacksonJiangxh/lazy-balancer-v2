package caddygeoip

import (
	"testing"
	"time"
)

// geoip fail-stale/重建失败告警必须按（路径+原因）节流：一次 reload 会为
// 每条地域规则各调一次 sharedGeoIPSearcher，不节流则 50 条规则 = 50 行相同
// WARN/次 reload；恢复成功后清除记录（再次故障即时上报）。
func TestGeoIPWarnThrottled_dedupesPerPathAndClears(t *testing.T) {
	oldInterval := geoipWarnLogInterval
	geoipWarnLogInterval = time.Minute
	t.Cleanup(func() {
		geoipWarnLogInterval = oldInterval
		geoipWarnSeen.Lock()
		geoipWarnSeen.last = map[string]time.Time{}
		geoipWarnSeen.Unlock()
		geoipWarnCallsForTest.Store(0)
	})
	geoipWarnSeen.Lock()
	geoipWarnSeen.last = map[string]time.Time{}
	geoipWarnSeen.Unlock()
	geoipWarnCallsForTest.Store(0)

	geoipWarnThrottled("stat", "/data/ip2region.xdb", "m")
	geoipWarnThrottled("stat", "/data/ip2region.xdb", "m")
	if got := geoipWarnCallsForTest.Load(); got != 1 {
		t.Fatalf("同路径同原因告警次数=%d, want 1（按窗口节流）", got)
	}
	// 不同原因独立节流（stat 失败与重建失败不是同一事件）
	geoipWarnThrottled("rebuild", "/data/ip2region.xdb", "m")
	if got := geoipWarnCallsForTest.Load(); got != 2 {
		t.Fatalf("不同原因告警次数=%d, want 2", got)
	}
	// 恢复后清除：再次故障必须立即上报
	clearGeoIPWarnLogs("/data/ip2region.xdb")
	geoipWarnThrottled("stat", "/data/ip2region.xdb", "m")
	if got := geoipWarnCallsForTest.Load(); got != 3 {
		t.Fatalf("恢复后再次故障告警次数=%d, want 3（清除节流记录）", got)
	}
}
