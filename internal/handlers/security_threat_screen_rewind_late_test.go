package handlers

// 回退后迟到插入必须仍能进入聚合（两种形态）：
//   - 原始行被保留期/行帽裁剪：全量重算只看得到剩余行，newTotal<oldTotal；
//   - 含旧口径固化行：按当前攻击口径过滤后 kept<oldTotal。
// 两种形态都只能靠「已计入行的最大 id」区分迟到行——普通插入来源的回退保留
// 分钟高水位（增量重固即可合并），原地改判来源的回退把高水位搬进迟到基线
// 后再删键（全量重算仍能按基线合并）。缺任一环，迟到行会在高水位被抹掉后
// 永久既不在 rollup、也不再进入后续增量重扫（大屏与事件列表口径分裂）。

import (
	"fmt"
	"testing"
	"time"

	"lazy-balancer-v2/internal/db"
	"lazy-balancer-v2/internal/services"
)

const threatRewindMinuteLayout = "2006-01-02 15:04"

// fixThreatRewindMinute 单分钟固化（全量/增量由高水位决定）。
func fixThreatRewindMinute(t *testing.T, m time.Time) {
	t.Helper()
	tx, err := db.MetricsDB.Begin()
	if err != nil {
		t.Fatal(err)
	}
	if err := threatFixMinuteWithMode(tx, m, false); err != nil {
		_ = tx.Rollback()
		t.Fatalf("fix minute: %v", err)
	}
	if err := tx.Commit(); err != nil {
		t.Fatal(err)
	}
}

func seedThreatRewindWatermark(t *testing.T, minute string) {
	t.Helper()
	if _, err := db.MetricsDB.Exec(`INSERT INTO metrics_state (key, value) VALUES (?, ?)
		ON CONFLICT(key) DO UPDATE SET value=excluded.value`, threatRollupWatermarkKey, minute); err != nil {
		t.Fatal(err)
	}
}

func threatRewindRollupTotals(t *testing.T, minute string) (total int, byAction map[string]int) {
	t.Helper()
	rows, err := db.MetricsDB.Query(`SELECT action, SUM(count) FROM security_event_rollup WHERE minute=? GROUP BY action`, minute)
	if err != nil {
		t.Fatal(err)
	}
	defer rows.Close()
	byAction = map[string]int{}
	for rows.Next() {
		var action string
		var count int
		if err := rows.Scan(&action, &count); err != nil {
			t.Fatal(err)
		}
		byAction[action] += count
		total += count
	}
	if err := rows.Err(); err != nil {
		t.Fatal(err)
	}
	return total, byAction
}

func threatRewindStateRows(t *testing.T, key string) int {
	t.Helper()
	var count int
	if err := db.MetricsDB.QueryRow(`SELECT COUNT(*) FROM metrics_state WHERE key=?`, key).Scan(&count); err != nil {
		t.Fatal(err)
	}
	return count
}

// 普通插入来源的回退只回退覆盖水位：分钟高水位必须保留，裁剪分钟上的迟到行
// 由增量重固并入（删除高水位会让 newTotal<oldTotal 分支再也找不到迟到行）。
func TestThreatRollupRewind_insertSourceKeepsLateInsertsOnTrimmedMinute(t *testing.T) {
	setupSecurityPolicyTestDB(t)
	m := time.Date(2026, 10, 18, 12, 0, 0, 0, time.UTC)
	minute := m.Format(threatRewindMinuteLayout)
	eventTime := m.Add(5 * time.Second).Format("2006-01-02 15:04:05")

	// Given 该分钟已固化 3 条拦截事件（首固=全量重建，写入事件高水位）。
	for i := range 3 {
		seedThreatScreenEvent(t, eventTime, fmt.Sprintf("93.184.216.%d", i+1), "942100", "SQL Injection", "blocked")
	}
	fixThreatRewindMinute(t, m)
	if got, _ := threatRewindRollupTotals(t, minute); got != 3 {
		t.Fatalf("首固 rollup 总量=%d, want 3", got)
	}
	if threatRewindStateRows(t, services.ThreatRollupEventHighwaterPrefix+minute) != 1 {
		t.Fatal("首固必须先落分钟事件高水位（增量重固的前提）")
	}
	// 行帽/保留期裁掉两条最旧原始行（已固化历史不可再生）。
	if _, err := db.MetricsDB.Exec(`DELETE FROM security_events WHERE id IN (SELECT id FROM security_events ORDER BY id ASC LIMIT 2)`); err != nil {
		t.Fatal(err)
	}
	// 一条迟到事件（轮转补采）落在已覆盖分钟。
	seedThreatScreenEvent(t, eventTime, "93.184.216.99", "949110", "Inbound Anomaly Score Exceeded", "blocked")
	seedThreatRewindWatermark(t, minute)

	// When 普通插入来源回退（无原地改判分钟）。
	ThreatRollupRewindTo(m, nil)

	// Then 高水位保留 → 下一次固化增量合并迟到行，已裁剪历史不丢。
	if threatRewindStateRows(t, services.ThreatRollupEventHighwaterPrefix+minute) != 1 {
		t.Fatal("普通插入来源的回退不得删除分钟高水位（迟到行 id 单调更大，增量即可覆盖）")
	}
	fixThreatRewindMinute(t, m)
	total, byAction := threatRewindRollupTotals(t, minute)
	if total != 4 {
		t.Fatalf("裁剪+迟到后 rollup 总量=%d, want 4（3 已固化历史 + 1 迟到，%v）", total, byAction)
	}
	if byAction["blocked"] != 4 {
		t.Fatalf("blocked=%d, want 4（迟到行漏计 → 大屏与事件列表口径分裂）", byAction["blocked"])
	}
	// 幂等：再固化一次不重复叠加。
	fixThreatRewindMinute(t, m)
	if got, _ := threatRewindRollupTotals(t, minute); got != 4 {
		t.Fatalf("重复固化后总量=%d, want 4", got)
	}
}

// 原地改判来源的回退删除分钟高水位（改判行 id 不变，增量扫不到）——必须同时
// 留底迟到基线，否则裁剪分钟上的迟到行在全量重算里被 newTotal<oldTotal 分支
// 丢弃，且新落的高水位让后续增量也再扫不到（永久丢失）。
func TestThreatRollupRewind_reclassifySourceKeepsLateInsertsOnTrimmedMinute(t *testing.T) {
	setupSecurityPolicyTestDB(t)
	m := time.Date(2026, 10, 18, 12, 0, 0, 0, time.UTC)
	minute := m.Format(threatRewindMinuteLayout)
	eventTime := m.Add(5 * time.Second).Format("2006-01-02 15:04:05")

	// Given 该分钟已固化 3 条拦截 + 1 条检测（旧口径总量 4），高水位=4。
	for i := range 3 {
		seedThreatScreenEvent(t, eventTime, fmt.Sprintf("93.184.216.%d", i+1), "942100", "SQL Injection", "blocked")
	}
	seedThreatScreenEvent(t, eventTime, "93.184.216.9", "942100", "SQL Injection", "logged")
	fixThreatRewindMinute(t, m)
	if total, _ := threatRewindRollupTotals(t, minute); total != 4 {
		t.Fatalf("首固 rollup 总量=%d, want 4", total)
	}
	// 裁掉两条最旧原始行（保留期/行帽），再插入一条迟到拦截。
	if _, err := db.MetricsDB.Exec(`DELETE FROM security_events WHERE id IN (SELECT id FROM security_events ORDER BY id ASC LIMIT 2)`); err != nil {
		t.Fatal(err)
	}
	seedThreatScreenEvent(t, eventTime, "93.184.216.99", "949110", "Inbound Anomaly Score Exceeded", "blocked")
	seedThreatRewindWatermark(t, minute)

	// When 原地改判来源回退（该分钟需全量重算）。
	ThreatRollupRewindTo(m, []time.Time{m})

	// Then 高水位删除、值搬进迟到基线（=4）；迟到行 id=5 > 基线 → 可合并。
	if threatRewindStateRows(t, services.ThreatRollupEventHighwaterPrefix+minute) != 0 {
		t.Fatal("原地改判来源的回退必须删除该分钟高水位（否则改判结果不会进入 rollup）")
	}
	var baseline string
	if err := db.MetricsDB.QueryRow(`SELECT value FROM metrics_state WHERE key=?`,
		services.ThreatRollupLateBaselinePrefix+minute).Scan(&baseline); err != nil {
		t.Fatalf("迟到基线未留底: %v", err)
	}
	if baseline != "4" {
		t.Fatalf("迟到基线=%q, want 4（被删除的高水位值）", baseline)
	}
	fixThreatRewindMinute(t, m)
	total, byAction := threatRewindRollupTotals(t, minute)
	if total != 5 {
		t.Fatalf("裁剪+迟到后 rollup 总量=%d, want 5（4 已固化历史 + 1 迟到，%v）", total, byAction)
	}
	// 迟到基线已消费：后续回退/固化不得再次叠加同一批迟到行。
	if threatRewindStateRows(t, services.ThreatRollupLateBaselinePrefix+minute) != 0 {
		t.Fatal("迟到基线必须在重固事务内消费（残留会让下一次回退重复合并）")
	}
	fixThreatRewindMinute(t, m)
	if got, _ := threatRewindRollupTotals(t, minute); got != 5 {
		t.Fatalf("重复固化后总量=%d, want 5（基线不得重复消费）", got)
	}
}

// 含旧口径固化行（爬虫放行的 logged 仍在 rollup）的分钟：按当前口径过滤后
// kept<oldTotal，同样落到「保留旧行」分支——两种回退来源都必须把迟到行并入，
// 且旧口径行必须被清掉。
func TestThreatRollupRewind_legacyPredicateRowsKeepLateInserts(t *testing.T) {
	for _, tc := range []struct {
		name       string
		reclassify func(m time.Time) []time.Time
	}{
		{name: "insert-source", reclassify: func(time.Time) []time.Time { return nil }},
		{name: "reclassify-source", reclassify: func(m time.Time) []time.Time { return []time.Time{m} }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			setupSecurityPolicyTestDB(t)
			m := time.Date(2026, 10, 19, 11, 59, 0, 0, time.UTC)
			minute := m.Format(threatRewindMinuteLayout)

			// Given 先烧两条事件 id（已计入的历史行，原始行已裁剪）。
			seedThreatScreenEvent(t, m.Add(-2*time.Minute).Format("2006-01-02 15:04:05"),
				"93.184.216.1", "942100", "SQL Injection", "blocked")
			seedThreatScreenEvent(t, m.Add(-2*time.Minute).Format("2006-01-02 15:04:05"),
				"93.184.216.2", "942100", "SQL Injection", "blocked")
			// 旧口径固化行：放行族 logged 1 条 + 正常 blocked 2 条。
			if _, err := db.MetricsDB.Exec(`INSERT INTO security_event_rollup (minute, country, province, family, rule, action, count) VALUES
				(?, '', '', '其他', ?, 'logged', 1),
				(?, '', '', 'SQL注入', '942100', 'blocked', 2)`,
				minute, crawlerExemptRulePass, minute); err != nil {
				t.Fatal(err)
			}
			if _, err := db.MetricsDB.Exec(`INSERT INTO metrics_state (key, value) VALUES (?, '2')
				ON CONFLICT(key) DO UPDATE SET value=excluded.value`,
				services.ThreatRollupEventHighwaterPrefix+minute); err != nil {
				t.Fatal(err)
			}
			// 一条迟到拦截事件（id=3 > 高水位 2）。
			seedThreatScreenEvent(t, m.Add(10*time.Second).Format("2006-01-02 15:04:05"),
				"93.184.216.99", "949110", "Inbound Anomaly Score Exceeded", "blocked")
			seedThreatRewindWatermark(t, minute)

			// When 回退（来源按子用例）。
			ThreatRollupRewindTo(m, tc.reclassify(m))

			// Then 全量/增量重固都按当前口径清掉放行行，并保留迟到行。
			fixThreatRewindMinute(t, m)
			total, byAction := threatRewindRollupTotals(t, minute)
			if total != 3 || byAction["blocked"] != 3 {
				t.Fatalf("rollup=(total %d, %v), want total=3 全 blocked（迟到行不得丢、旧口径放行行不得留）", total, byAction)
			}
			fixThreatRewindMinute(t, m)
			if got, _ := threatRewindRollupTotals(t, minute); got != 3 {
				t.Fatalf("重复固化后总量=%d, want 3", got)
			}
		})
	}
}
