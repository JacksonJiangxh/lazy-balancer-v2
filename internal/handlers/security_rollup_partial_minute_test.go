package handlers

import (
	"encoding/json"
	"net/http"
	"testing"
	"time"

	"lazy-balancer-v2/internal/db"
)

// rollup 时间口径（有意设计，勿按「部分分钟」重报）：
//   - warmer 每轮恒固化 currentMinute 的部分分钟；今日计数与大屏总量/分桶/
//     目标维度都包含「当前分钟截至最近一次固化」的事件（滞后 ≤60s）；
//   - recent_rate 例外：固定 5 分钟除数，必须只取完整分钟（见
//     TestGetSecurityThreatScreen_recentRateUsesCompleteMinutesOnly）。
//
// 本用例钉住前一半事实：若将来把三面查询改成「只取完整分钟」，UI 文案
// （含当前分钟，滞后约 1 分钟）必须同步改回——否则文案与数字再次失配。
func TestRollupQueries_includeCurrentPartialMinute(t *testing.T) {
	setupSecurityPolicyTestDB(t)
	t.Cleanup(resetThreatScreenCachesForTest)
	now := time.Date(2026, 10, 19, 12, 0, 30, 0, time.UTC)
	installThreatClock(t, now)
	lastComplete := now.Add(-time.Minute).Truncate(time.Minute)
	currentMinute := now.Truncate(time.Minute)
	lastStr := lastComplete.Format("2006-01-02 15:04")
	currentStr := currentMinute.Format("2006-01-02 15:04")
	dayStart := time.Date(now.Year(), now.Month(), now.Day(), 0, 0, 0, 0, time.UTC)

	seedThreatLBRule(t, "lb_partial", "API 服务", "api.example.com")
	if _, err := db.MetricsDB.Exec(`INSERT INTO security_event_rollup (minute, country, province, family, rule, action, count) VALUES
		(?, '美国', '', 'SQL注入', '942100', 'blocked', 2),
		(?, '美国', '', 'SQL注入', '942100', 'logged', 1),
		(?, '日本', '', 'XSS', '941100', 'blocked', 5)`,
		lastStr, lastStr, currentStr); err != nil {
		t.Fatalf("seed rollup: %v", err)
	}
	if _, err := db.MetricsDB.Exec(`INSERT INTO security_event_target_rollup (minute, rule_caddy_id, count) VALUES (?, 'lb_partial', 4), (?, 'lb_partial', 9)`,
		lastStr, currentStr); err != nil {
		t.Fatalf("seed target rollup: %v", err)
	}
	if _, err := db.MetricsDB.Exec(`INSERT INTO metrics_state (key, value) VALUES (?, ?), (?, ?)
		ON CONFLICT(key) DO UPDATE SET value=excluded.value`,
		threatRollupCoveredFromKey, dayStart.Format("2006-01-02 15:04"),
		threatRollupWatermarkKey, lastStr); err != nil {
		t.Fatalf("seed rollup state: %v", err)
	}

	// 今日计数：完整分钟 + 当前部分分钟都计入（口径文案已按此陈述）。
	blocked, detected, fromRollup, err := securityOverviewTodayCounts(db.MetricsDB, dayStart, now)
	if err != nil {
		t.Fatalf("today counts: %v", err)
	}
	if !fromRollup {
		t.Fatal("覆盖新鲜时必须走 rollup 口径")
	}
	if blocked != 7 || detected != 1 {
		t.Fatalf("今日计数含当前分钟: blocked=%d detected=%d, want 7/1", blocked, detected)
	}

	// 大屏总量/分桶/目标维度与今日计数同口径（含部分分钟）。
	since := now.Add(-24 * time.Hour).Truncate(time.Minute)
	bucketStarts := []time.Time{since}
	agg, err := threatRollupDimAggregateQuery(db.MetricsDB, since.Format("2006-01-02 15:04"), bucketStarts, dayStart.Format("2006-01-02 15:04"), true)
	if err != nil {
		t.Fatalf("aggregate: %v", err)
	}
	if agg.total != 8 || agg.blocked != 7 {
		t.Fatalf("大屏总量含当前分钟: total=%d blocked=%d, want 8/7", agg.total, agg.blocked)
	}
	if len(agg.bucketTotals) != 1 || agg.bucketTotals[0] != 8 {
		t.Fatalf("分桶总量必须与总量同口径: %+v", agg.bucketTotals)
	}

	targets, err := threatTopTargets(since.Format("2006-01-02 15:04"))
	if err != nil {
		t.Fatalf("top targets: %v", err)
	}
	if len(targets) != 1 || targets[0].Value != 13 {
		t.Fatalf("top_targets 必须与总量同口径: %+v", targets)
	}
}

// 端点级接线：大屏 handler 的总量与 recent_rate 刻意使用不同时间上界，
// 两者都不许被单方面改动（改动必须成对更新文案与本用例）。
func TestGetSecurityThreatScreen_partialMinuteScopeIsExplicit(t *testing.T) {
	setupSecurityPolicyTestDB(t)
	t.Cleanup(resetThreatScreenCachesForTest)
	base := time.Date(2026, 10, 18, 12, 30, 0, 0, time.UTC)
	installThreatClock(t, base)
	lastComplete := base.Add(-time.Minute).Truncate(time.Minute)
	currentMinute := base.Truncate(time.Minute)
	seedThreatScreenEvent(t, lastComplete.Format("2006-01-02 15:04:05"), "93.184.216.7", "942100", "SQL Injection", "blocked")
	seedThreatScreenEvent(t, currentMinute.Add(5*time.Second).Format("2006-01-02 15:04:05"), "93.184.216.8", "942100", "SQL Injection", "blocked")
	router := newThreatScreenRouter(t, newThreatMetricsServer(t).URL)

	var payload threatScreenPayload
	for range 4 {
		recorder := getRequest(t, router, "/security/overview/threat-screen")
		if recorder.Code != http.StatusOK {
			t.Fatalf("status=%d body=%s", recorder.Code, recorder.Body.String())
		}
		if err := json.Unmarshal(recorder.Body.Bytes(), &payload); err != nil {
			t.Fatalf("decode: %v", err)
		}
		if payload.Data.TotalEvents == 2 {
			break
		}
	}
	if payload.Data.TotalEvents != 2 || payload.Data.BlockedEvents != 2 {
		t.Fatalf("大屏总量含当前部分分钟: total=%d blocked=%d, want 2/2（滞后 ≤60s，与 UI 文案一致）",
			payload.Data.TotalEvents, payload.Data.BlockedEvents)
	}
}
