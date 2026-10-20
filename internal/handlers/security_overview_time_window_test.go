package handlers

import (
	"testing"
	"time"

	"lazy-balancer-v2/internal/db"
)

// 历史修复0：7 天趋势日桶必须按配置时区的**逐日边界**分桶，不得把单一当前
// 偏移套到整周 SQL date() 上——DST 周界会让切换前一日的边界错 1h，事件跨到
// 相邻日桶（默认 Asia/Shanghai 无 DST，故长期未暴露）。
//
// Given 配置 America/New_York、今日 2026-03-09（已进入夏令时 -4）；
// When 事件发生在 2026-03-04 04:30 UTC（= 03-03 23:30 EST，切换前一日）；
// Then 必须计入 03-03 桶，03-04 桶为零（单偏移 -4 会误记到 03-04）。
func TestLoadSecurityOverviewAggregates_trendUsesPerDayDSTBoundaries(t *testing.T) {
	setupSecurityPolicyTestDB(t)
	resetSecurityOverviewAggCacheForTest()
	t.Cleanup(resetSecurityOverviewAggCacheForTest)

	loc, err := time.LoadLocation("America/New_York")
	if err != nil {
		t.Fatalf("load IANA zoneinfo America/New_York: %v", err)
	}
	today := time.Date(2026, 3, 9, 12, 0, 0, 0, loc)
	todayStart := time.Date(2026, 3, 9, 0, 0, 0, 0, loc).UTC().Format("2006-01-02 15:04:05")

	insertOverviewAggregateEvent(t, db.MetricsDB, "2026-03-04 04:30:00")

	data, err := loadSecurityOverviewAggregates(db.MetricsDB, today, todayStart, "-240 minutes")
	if err != nil {
		t.Fatalf("aggregate: %v", err)
	}
	if len(data.trend) != 7 {
		t.Fatalf("trend len=%d, want 7", len(data.trend))
	}
	blockedByDate := make(map[string]int, len(data.trend))
	for _, point := range data.trend {
		blockedByDate[point.Date] = point.Blocked
	}
	if blockedByDate["2026-03-03"] != 1 {
		t.Fatalf("2026-03-03 blocked=%d, want 1（DST 前一日边界必须按当日偏移）: %+v",
			blockedByDate["2026-03-03"], blockedByDate)
	}
	if blockedByDate["2026-03-04"] != 0 {
		t.Fatalf("2026-03-04 blocked=%d, want 0（单偏移分桶会把事件错记到本日）: %+v",
			blockedByDate["2026-03-04"], blockedByDate)
	}
}

// 历史修复7：requestedHours 需求必须有界衰减——一次 30d 请求不得永久把后台
// 回填窗口顶到上限；同时窗口只升不降、上限钳制、≤24h 不产生宽窗需求。
func TestThreatRollupRequestedHours_boundedDecay(t *testing.T) {
	reset := func() {
		threatRollupRequestedHours.Store(0)
		threatRollupRequestedHoursAt.Store(0)
	}
	reset()
	t.Cleanup(reset)

	// 过期需求：读取即复位（后台回填回落 7d 预热窗口）。
	threatRollupRequestedHours.Store(threatScreenMaxHours)
	threatRollupRequestedHoursAt.Store(time.Now().Add(-2 * threatRollupRequestedHoursTTL).UnixNano())
	if got := threatRollupRequestedHoursLimit(); got != 0 {
		t.Fatalf("stale demand limit=%d, want 0（过期必须衰减）", got)
	}
	if got := threatRollupRequestedHours.Load(); got != 0 {
		t.Fatalf("stale demand 未复位: %d", got)
	}

	// 新鲜需求生效。
	recordThreatRollupRequestedHours(48)
	if got := threatRollupRequestedHoursLimit(); got != 48 {
		t.Fatalf("fresh demand limit=%d, want 48", got)
	}

	// 只升不降：较窄的宽窗请求不得降低已有需求。
	recordThreatRollupRequestedHours(30)
	if got := threatRollupRequestedHoursLimit(); got != 48 {
		t.Fatalf("narrower request lowered demand to %d, want 48", got)
	}

	// 上限钳制。
	recordThreatRollupRequestedHours(threatScreenMaxHours + 24*30)
	if got := threatRollupRequestedHoursLimit(); got != threatScreenMaxHours {
		t.Fatalf("demand limit=%d, want clamp %d", got, threatScreenMaxHours)
	}

	// ≤24h（大屏固定消费窗口）不登记宽窗需求。
	reset()
	recordThreatRollupRequestedHours(24)
	if got := threatRollupRequestedHoursLimit(); got != 0 {
		t.Fatalf("24h request demand=%d, want 0（非宽窗）", got)
	}
}

// 历史修复7：回退窗口钳制同样只看有效需求——过期需求不得继续扩大回退范围。
func TestThreatRollupRewindMinute_staleDemandFallsBackToSevenDays(t *testing.T) {
	reset := func() {
		threatRollupRequestedHours.Store(0)
		threatRollupRequestedHoursAt.Store(0)
	}
	reset()
	t.Cleanup(reset)

	base := time.Date(2026, 10, 18, 12, 0, 30, 0, time.UTC)
	installThreatClock(t, base)
	sevenDayHorizon := base.Add(-time.Minute).Truncate(time.Minute).
		Add(-time.Duration(threatRollupRewindWindowHours) * time.Hour)

	threatRollupRequestedHours.Store(threatScreenMaxHours)
	threatRollupRequestedHoursAt.Store(time.Now().Add(-2 * threatRollupRequestedHoursTTL).UnixNano())
	if got := threatRollupRewindMinute(base.Add(-200 * time.Hour)); !got.Equal(sevenDayHorizon) {
		t.Fatalf("stale demand rewind=%s, want 7d clamp %s", got, sevenDayHorizon)
	}

	// 新鲜 30d 需求才允许更深回退。
	recordThreatRollupRequestedHours(threatScreenMaxHours)
	if got := threatRollupRewindMinute(base.Add(-200 * time.Hour)); !got.Equal(base.Add(-200 * time.Hour).Truncate(time.Minute)) {
		t.Fatalf("fresh demand rewind=%s, want unclamped target", got)
	}
}
