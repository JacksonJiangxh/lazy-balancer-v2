package services

import (
	"context"
	"fmt"
	"strings"
	"testing"
	"time"

	"lazy-balancer-v2/internal/db"
)

func setupSecurityEventsRetentionTestDB(t *testing.T) {
	t.Helper()
	oldDB, oldMetricsDB, oldAuditDB := db.DB, db.MetricsDB, db.AuditDB
	dataDir := t.TempDir()
	if err := db.Initialize(dataDir); err != nil {
		t.Fatalf("initialize database: %v", err)
	}
	if err := db.InitializeMetricsDB(dataDir); err != nil {
		t.Fatalf("initialize metrics database: %v", err)
	}
	t.Cleanup(func() {
		_ = db.Close()
		db.DB, db.MetricsDB, db.AuditDB = oldDB, oldMetricsDB, oldAuditDB
	})
}

func countSecurityEventsByType(t *testing.T, eventType string) int {
	t.Helper()
	var count int
	if err := db.MetricsDB.QueryRow(`SELECT COUNT(*) FROM security_events WHERE event_type=?`, eventType).Scan(&count); err != nil {
		t.Fatal(err)
	}
	return count
}

func TestSecurityEventsRetentionCleanup_deletesEventsOlderThanConfiguredDays(t *testing.T) {
	// Given: a 30-day retention window and events older and newer than the cutoff
	setupSecurityEventsRetentionTestDB(t)
	if _, err := db.DB.Exec(`UPDATE global_config SET security_events_retention_days=30 WHERE id=1`); err != nil {
		t.Fatal(err)
	}
	if _, err := db.MetricsDB.Exec(`INSERT INTO security_events (event_time, client_ip, event_type) VALUES
		(datetime('now', '-40 days'), '198.51.100.1', 'expired'),
		(datetime('now', '-1 day'), '198.51.100.2', 'recent')`); err != nil {
		t.Fatal(err)
	}

	// When
	securityEventsRetentionCleanup(context.Background())

	// Then: the expired event is gone, the recent one survives
	if got := countSecurityEventsByType(t, "expired"); got != 0 {
		t.Fatalf("expired events after cleanup = %d, want 0", got)
	}
	if got := countSecurityEventsByType(t, "recent"); got != 1 {
		t.Fatalf("recent events after cleanup = %d, want 1", got)
	}
}

func TestSecurityEventsRetentionCleanup_keepsAllBelowSafetyMax(t *testing.T) {
	// 原名 trimsOldestRowsWhenCountExceedsMax 与断言
	// 语义相反（行为变更后复用旧名）——本用例实际钉「宽年龄窗+远低于安全上限
	// 时全存活」。count-trim 分支的独立钉测见
	// TestSecurityEventsRetentionCleanup_trimsOldestWhenRowCapExceeded（历史
	// v2.3.8 起 security_events_row_cap 可配置，cap=小值即可经济构造
	// 该分支——原「不可构造」豁免理由已失效）。
	setupSecurityEventsRetentionTestDB(t)
	if _, err := db.DB.Exec(`UPDATE global_config SET security_events_retention_days=3650 WHERE id=1`); err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 5; i++ {
		if _, err := db.MetricsDB.Exec(`INSERT INTO security_events (event_time, client_ip) VALUES (datetime('now'), ?)`,
			fmt.Sprintf("198.51.100.%d", i)); err != nil {
			t.Fatal(err)
		}
	}

	// When
	securityEventsRetentionCleanup(context.Background())

	// Then: all 5 events survive (safety max not reached)
	var count int
	if err := db.MetricsDB.QueryRow(`SELECT COUNT(*) FROM security_events`).Scan(&count); err != nil {
		t.Fatal(err)
	}
	if count != 5 {
		t.Fatalf("events after cleanup = %d, want 5 (safety max not reached)", count)
	}
}

func TestSecurityEventsRetentionSettings_appliesDefaultsWhenZero(t *testing.T) {
	// Given: non-positive retention values stored in global_config
	setupSecurityEventsRetentionTestDB(t)
	if _, err := db.DB.Exec(`UPDATE global_config SET security_events_retention_days=0 WHERE id=1`); err != nil {
		t.Fatal(err)
	}

	// When
	days, max := securityEventsRetentionSettings()

	// Then: the documented defaults apply
	if days != 90 || max != 1000000 {
		t.Fatalf("settings = (%d, %d), want (90, 1000000)", days, max)
	}
}

func TestSecurityEventsRetentionCleanup_usesDefaultDaysWhenConfigZero(t *testing.T) {
	// Given: zeroed retention config and events straddling the default 90-day window
	// （默认从 30 天提升到与操作日志同口径的 90 天/3 个月)
	setupSecurityEventsRetentionTestDB(t)
	if _, err := db.DB.Exec(`UPDATE global_config SET security_events_retention_days=0 WHERE id=1`); err != nil {
		t.Fatal(err)
	}
	if _, err := db.MetricsDB.Exec(`INSERT INTO security_events (event_time, client_ip, event_type) VALUES
		(datetime('now', '-91 days'), '198.51.100.1', 'expired'),
		(datetime('now', '-89 days'), '198.51.100.2', 'recent')`); err != nil {
		t.Fatal(err)
	}

	// When
	securityEventsRetentionCleanup(context.Background())

	// Then: the default 90-day window deleted the 91-day-old event only
	if got := countSecurityEventsByType(t, "expired"); got != 0 {
		t.Fatalf("expired events after cleanup = %d, want 0", got)
	}
	if got := countSecurityEventsByType(t, "recent"); got != 1 {
		t.Fatalf("recent events after cleanup = %d, want 1", got)
	}
}

func TestSecurityEventsRetention_engineTriggerDeletesExpired(t *testing.T) {
	// Given：引擎驱动路径 + 过期与保留事件。
	setupSecurityEventsRetentionTestDB(t)
	if _, err := db.DB.Exec(`UPDATE global_config SET security_events_retention_days=30 WHERE id=1`); err != nil {
		t.Fatal(err)
	}
	if _, err := db.MetricsDB.Exec(`INSERT INTO security_events (event_time, client_ip, event_type) VALUES
		(datetime('now', '-40 days'), '198.51.100.1', 'expired'),
		(datetime('now', '-1 day'), '198.51.100.2', 'recent')`); err != nil {
		t.Fatal(err)
	}
	SetConfigLoadRerun(func(string) error { return nil })
	t.Cleanup(func() { SetConfigLoadRerun(nil) })
	te := InitTaskEngine("", t.TempDir()+"/app.log")
	t.Cleanup(StopTaskEngine)

	// When：经引擎手动触发（与 24h Periodic 同一 Run 体）。
	if err := te.Trigger("security-events-retention", "manual", ""); err != nil {
		t.Fatal(err)
	}

	// Then：过期事件删除，近期事件保留。
	if got := countSecurityEventsByType(t, "expired"); got != 0 {
		t.Fatalf("expired events after engine cleanup = %d, want 0", got)
	}
	if got := countSecurityEventsByType(t, "recent"); got != 1 {
		t.Fatalf("recent events after engine cleanup = %d, want 1", got)
	}
}

func TestSecurityEventsRetentionCleanup_stopsPromptlyWhenContextCanceled(t *testing.T) {
	// 批间让出同时检查 ctx——已取消的 ctx 保证第一批次删除后立即返回
	// （确定性：循环首批次恒执行，其后的批间 select 立即命中 ctx.Done），
	// 大批量首遍不再阻塞 Stop 的等待。
	// Given: 3 倍单批的过期事件（完整 pass 需 3 批；v2.3.8 单批上调 20000 后
	// 种子随批次缩放，保证「首批后立即取消」语义不依赖具体批大小）+ 已取消的 ctx
	seedTotal := 3 * securityEventsRetentionDeleteBatch
	setupSecurityEventsRetentionTestDB(t)
	if _, err := db.DB.Exec(`UPDATE global_config SET security_events_retention_days=30 WHERE id=1`); err != nil {
		t.Fatal(err)
	}
	var sb strings.Builder
	for start := 0; start < seedTotal; start += 1000 {
		sb.Reset()
		sb.WriteString("INSERT INTO security_events (event_time, client_ip, event_type) VALUES ")
		for i := 0; i < 1000; i++ {
			if i > 0 {
				sb.WriteString(", ")
			}
			fmt.Fprintf(&sb, "(datetime('now', '-40 days'), '198.51.100.%d', 'expired')", (start+i)%250)
		}
		if _, err := db.MetricsDB.Exec(sb.String()); err != nil {
			t.Fatalf("seed expired batch: %v", err)
		}
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	// When
	done := make(chan struct{})
	deleted := -1
	go func() {
		defer close(done)
		deleted, _ = SecurityEventsRetentionCleanupCtxErr(ctx)
	}()

	// Then: 清理迅速返回且仅完成一个批次（未删净），证明中途被取消而非跑完
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("cleanup did not stop promptly on a canceled context")
	}
	if got := countSecurityEventsByType(t, "expired"); got != seedTotal-securityEventsRetentionDeleteBatch {
		t.Fatalf("expired events after canceled cleanup = %d, want %d (exactly one batch deleted)", got, seedTotal-securityEventsRetentionDeleteBatch)
	}
	// 取消路径的返回契约与其余早退同口径——已提交删
	// 除的批次数必须如实上报（§6.5 摘要行数据源），不得归 0 丢弃。
	if deleted != securityEventsRetentionDeleteBatch {
		t.Fatalf("canceled cleanup returned %d, want %d（恰好一批已删计数）", deleted, securityEventsRetentionDeleteBatch)
	}
}

func TestSecurityEventsRetentionCleanup_batchesAgeDelete(t *testing.T) {
	// Given: securityEventsRetentionDeleteBatch+1000 expired events（超过单批
	// 20000，必须分批循环）+ 1 条近期事件。原种子 12000
	// 小于单批上限，实际只走一次 DELETE，「分批」断言恒成立却从未覆盖批循环。
	seedTotal := securityEventsRetentionDeleteBatch + 1000
	setupSecurityEventsRetentionTestDB(t)
	if _, err := db.DB.Exec(`UPDATE global_config SET security_events_retention_days=30 WHERE id=1`); err != nil {
		t.Fatal(err)
	}
	var sb strings.Builder
	for start := 0; start < seedTotal; start += 1000 {
		sb.Reset()
		sb.WriteString("INSERT INTO security_events (event_time, client_ip, event_type) VALUES ")
		for i := 0; i < 1000; i++ {
			if i > 0 {
				sb.WriteString(", ")
			}
			fmt.Fprintf(&sb, "(datetime('now', '-40 days'), '198.51.100.%d', 'expired')", (start+i)%250)
		}
		if _, err := db.MetricsDB.Exec(sb.String()); err != nil {
			t.Fatalf("seed expired batch: %v", err)
		}
	}
	if _, err := db.MetricsDB.Exec(`INSERT INTO security_events (event_time, client_ip, event_type) VALUES (datetime('now'), '198.51.100.250', 'recent')`); err != nil {
		t.Fatal(err)
	}

	// When
	deleted, _ := SecurityEventsRetentionCleanupCtxErr(context.Background())

	// Then：全部过期事件被分批删除，近期事件保留
	if got := countSecurityEventsByType(t, "expired"); got != 0 {
		t.Fatalf("expired events after cleanup = %d, want 0", got)
	}
	if got := countSecurityEventsByType(t, "recent"); got != 1 {
		t.Fatalf("recent events after cleanup = %d, want 1", got)
	}
	// And：删除行数超过单批上限——证明批循环真的跑了（不是一次 DELETE）
	if deleted <= securityEventsRetentionDeleteBatch {
		t.Fatalf("deleted=%d, want > single batch %d", deleted, securityEventsRetentionDeleteBatch)
	}
}

// ---- 保留策略辅助：按分钟截断统计 ----

func countRollupRowsBefore(t *testing.T, cutoff string) int {
	t.Helper()
	var count int
	if err := db.MetricsDB.QueryRow(`SELECT COUNT(*) FROM security_event_rollup WHERE minute < ?`, cutoff).Scan(&count); err != nil {
		t.Fatal(err)
	}
	return count
}

func TestSecurityEventRollupRetention_batches(t *testing.T) {
	// Given：40 天前的 150 个分钟组（每行 1 条）+ 昨天的分钟组 + 当前分钟
	setupSecurityEventsRetentionTestDB(t)
	if _, err := db.DB.Exec(`UPDATE global_config SET security_events_retention_days=30 WHERE id=1`); err != nil {
		t.Fatal(err)
	}
	old := time.Now().UTC().AddDate(0, 0, -40).Truncate(time.Minute)
	for i := 0; i < 150; i++ {
		minute := old.Add(time.Duration(i) * time.Minute).Format("2006-01-02 15:04")
		if _, err := db.MetricsDB.Exec(`INSERT INTO security_event_rollup (minute, country, province, family, rule, action, count) VALUES (?, '美国', '', 'SQL注入', 'r', 'blocked', 1)`, minute); err != nil {
			t.Fatalf("seed old rollup %d: %v", i, err)
		}
	}
	recentMinute := time.Now().UTC().Add(-24 * time.Hour).Truncate(time.Minute).Format("2006-01-02 15:04")
	currentMinute := time.Now().UTC().Truncate(time.Minute).Format("2006-01-02 15:04")
	if _, err := db.MetricsDB.Exec(`INSERT INTO security_event_rollup (minute, country, province, family, rule, action, count) VALUES (?, '中国', '广东省', 'XSS', 'r', 'blocked', 2), (?, '', '', '', '', 'blocked', 1)`, recentMinute, currentMinute); err != nil {
		t.Fatal(err)
	}

	// When
	securityEventsRetentionCleanup(context.Background())

	// Then：40 天前全部清掉，24h 内与当前分钟保留
	cutoff := time.Now().UTC().AddDate(0, 0, -31).Format("2006-01-02 15:04")
	if got := countRollupRowsBefore(t, cutoff); got != 0 {
		t.Fatalf("rollup rows older than 31d=%d, want 0", got)
	}
	var kept int
	if err := db.MetricsDB.QueryRow(`SELECT COUNT(*) FROM security_event_rollup WHERE minute IN (?, ?)`, recentMinute, currentMinute).Scan(&kept); err != nil {
		t.Fatal(err)
	}
	if kept != 2 {
		t.Fatalf("recent rollup rows=%d, want 2", kept)
	}

	// 空表形状：再跑一次无错误（幂等）
	securityEventsRetentionCleanup(context.Background())
}

// security_events_row_cap 可配置后，count 超限批删分支可
// 经济构造——钉住「按最旧优先裁剪到上限 + 返回已删计数」。
func TestSecurityEventsRetentionCleanup_trimsOldestWhenRowCapExceeded(t *testing.T) {
	// Given cap=3、宽年龄窗、5 条近期事件（id 升序=时间序）
	setupSecurityEventsRetentionTestDB(t)
	if _, err := db.DB.Exec(`UPDATE global_config SET security_events_retention_days=3650, security_events_row_cap=3 WHERE id=1`); err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 5; i++ {
		if _, err := db.MetricsDB.Exec(`INSERT INTO security_events (event_time, client_ip, event_type) VALUES (datetime('now'), ?, ?)`,
			fmt.Sprintf("198.51.100.%d", i), fmt.Sprintf("evt-%d", i)); err != nil {
			t.Fatal(err)
		}
	}
	var oldestIDs []int64
	rows, err := db.MetricsDB.Query(`SELECT id FROM security_events ORDER BY id ASC LIMIT 2`)
	if err != nil {
		t.Fatal(err)
	}
	for rows.Next() {
		var id int64
		if err := rows.Scan(&id); err != nil {
			rows.Close()
			t.Fatal(err)
		}
		oldestIDs = append(oldestIDs, id)
	}
	rows.Close()
	if len(oldestIDs) != 2 {
		t.Fatalf("seed 失败：oldestIDs=%v", oldestIDs)
	}

	// When
	deleted, _ := SecurityEventsRetentionCleanupCtxErr(context.Background())

	// Then 行数收敛到 cap，且删的是最旧两行（不是随机/最新）
	var count int
	if err := db.MetricsDB.QueryRow(`SELECT COUNT(*) FROM security_events`).Scan(&count); err != nil {
		t.Fatal(err)
	}
	if count != 3 {
		t.Fatalf("cleanup 后行数=%d，want 3（cap=3）", count)
	}
	for _, id := range oldestIDs {
		var exists int
		if err := db.MetricsDB.QueryRow(`SELECT COUNT(*) FROM security_events WHERE id=?`, id).Scan(&exists); err != nil {
			t.Fatal(err)
		}
		if exists != 0 {
			t.Fatalf("最旧事件 id=%d 未被裁剪（count-trim 应按 id ASC）", id)
		}
	}
	// 返回计数 = 实际删除数（§6.5 摘要行真实性）
	if deleted != 2 {
		t.Fatalf("cleanup 返回已删=%d，want 2", deleted)
	}
}

// 分钟事件高水位键与 rollup 同生命周期清理——
// 写入侧每分钟一行 metrics_state，旧实现无任何删除点（1440 键/天常驻）。
func TestSecurityEventsRetentionCleanup_prunesRollupHighwaterKeys(t *testing.T) {
	setupSecurityEventsRetentionTestDB(t)
	if _, err := db.DB.Exec(`UPDATE global_config SET security_events_retention_days=30 WHERE id=1`); err != nil {
		t.Fatal(err)
	}
	oldMinute := time.Now().UTC().AddDate(0, 0, -40).Format("2006-01-02 15:04")
	recentMinute := time.Now().UTC().Add(-time.Minute).Format("2006-01-02 15:04")
	if _, err := db.MetricsDB.Exec(`INSERT INTO metrics_state (key, value) VALUES (?, '5'), (?, '7')`,
		ThreatRollupEventHighwaterPrefix+oldMinute, ThreatRollupEventHighwaterPrefix+recentMinute); err != nil {
		t.Fatal(err)
	}

	securityEventsRetentionCleanup(context.Background())

	var oldCount, recentCount int
	if err := db.MetricsDB.QueryRow(`SELECT COUNT(*) FROM metrics_state WHERE key=?`, ThreatRollupEventHighwaterPrefix+oldMinute).Scan(&oldCount); err != nil {
		t.Fatal(err)
	}
	if err := db.MetricsDB.QueryRow(`SELECT COUNT(*) FROM metrics_state WHERE key=?`, ThreatRollupEventHighwaterPrefix+recentMinute).Scan(&recentCount); err != nil {
		t.Fatal(err)
	}
	if oldCount != 0 {
		t.Fatalf("超过 rollup 保留期的高水位键未清理（count=%d）", oldCount)
	}
	if recentCount != 1 {
		t.Fatalf("近期高水位键被误删（count=%d）", recentCount)
	}
}

// 任务日志必须能看到聚合/高水位删除量：停摆后首次清理可能只删旧 rollup 与
// 高水位键（事件表无过期行），旧返回口径只报事件数 → 任务监控显示「删除 0 条」，
// 运维误判保留策略未生效。
func TestSecurityEventsRetentionCleanupDetail_reportsAggregateDeletions(t *testing.T) {
	setupSecurityEventsRetentionTestDB(t)
	if _, err := db.DB.Exec(`UPDATE global_config SET security_events_retention_days=30 WHERE id=1`); err != nil {
		t.Fatal(err)
	}
	oldMinute := time.Now().UTC().AddDate(0, 0, -40).Format("2006-01-02 15:04")
	if _, err := db.MetricsDB.Exec(`INSERT INTO security_event_rollup (minute, country, family, rule, action, count) VALUES (?, '中国', 'waf', 'r', 'blocked', 3)`, oldMinute); err != nil {
		t.Fatal(err)
	}
	if _, err := db.MetricsDB.Exec(`INSERT INTO security_event_target_rollup (minute, rule_caddy_id, count) VALUES (?, 'lb_example', 2)`, oldMinute); err != nil {
		t.Fatal(err)
	}
	if _, err := db.MetricsDB.Exec(`INSERT INTO metrics_state (key, value) VALUES (?, '5')`, ThreatRollupEventHighwaterPrefix+oldMinute); err != nil {
		t.Fatal(err)
	}

	res, err := SecurityEventsRetentionCleanupDetail(context.Background())
	if err != nil {
		t.Fatalf("cleanup: %v", err)
	}
	if res.Events != 0 {
		t.Fatalf("events deleted = %d, want 0（事件表无过期行）", res.Events)
	}
	if res.Rollup == 0 || res.TargetRollup == 0 || res.Highwater == 0 {
		t.Fatalf("detail = %+v, want non-zero rollup/target/highwater deletions", res)
	}
	if res.Aggregates() != res.Rollup+res.TargetRollup+res.Highwater {
		t.Fatalf("Aggregates()=%d, want sum of the three buckets", res.Aggregates())
	}
	// 兼容入口仍按事件数返回
	events, err := SecurityEventsRetentionCleanupCtxErr(context.Background())
	if err != nil || events != 0 {
		t.Fatalf("compat wrapper events=%d err=%v, want 0/nil", events, err)
	}
}

// 行帽裁剪必须按「最旧事件」而非「最早插入」——
// 摄取停摆后的补采/归档重放会以新 id 插入旧 event_time 的行，按 id 删会先丢
// 新事件、留住补采的旧事件。
func TestSecurityEventsRetentionCleanup_rowCapTrimsByEventTime(t *testing.T) {
	setupSecurityEventsRetentionTestDB(t)
	if _, err := db.DB.Exec(`UPDATE global_config SET security_events_retention_days=3650, security_events_row_cap=3 WHERE id=1`); err != nil {
		t.Fatal(err)
	}
	// 插入顺序（id）与事件时间顺序刻意错乱：
	//   id1 now-1h（新） / id2 now-10d（最旧） / id3 now-2d / id4 now-5d / id5 now-30m（最新）
	if _, err := db.MetricsDB.Exec(`INSERT INTO security_events (event_time, client_ip, event_type) VALUES
		(datetime('now','-1 hour'), '198.51.100.1', 'evt-1'),
		(datetime('now','-10 days'), '198.51.100.2', 'evt-2'),
		(datetime('now','-2 days'), '198.51.100.3', 'evt-3'),
		(datetime('now','-5 days'), '198.51.100.4', 'evt-4'),
		(datetime('now','-30 minutes'), '198.51.100.5', 'evt-5')`); err != nil {
		t.Fatal(err)
	}

	if _, err := securityEventsRetentionCleanup(context.Background()); err != nil {
		t.Fatalf("cleanup: %v", err)
	}

	// cap=3 → 删最旧两事件（evt-2 10d、evt-4 5d），保留 1h/2d/30m。
	for _, evt := range []string{"evt-1", "evt-3", "evt-5"} {
		if got := countSecurityEventsByType(t, evt); got != 1 {
			t.Fatalf("%s 应保留，got=%d（按 id 裁剪会误删新事件）", evt, got)
		}
	}
	for _, evt := range []string{"evt-2", "evt-4"} {
		if got := countSecurityEventsByType(t, evt); got != 0 {
			t.Fatalf("%s 应被裁剪（最旧事件），got=%d", evt, got)
		}
	}
}

// 保留摘要漏行帽 ——

// 摘要必须同时表达天数与行帽：cleanup 按 count-max 裁剪，只写「保留 N 天」
// 会让行帽提前裁剪时的用户可见文案与实际行为漂移。
func TestSecurityEventsRetention_summaryIncludesRowCap(t *testing.T) {
	setupSecurityEventsRetentionTestDB(t)
	if _, err := db.DB.Exec(`UPDATE global_config SET security_events_retention_days=30, security_events_row_cap=5000 WHERE id=1`); err != nil {
		t.Fatal(err)
	}
	summary, rowCap := SecurityEventsRetentionSnapshot()
	if rowCap != 5000 {
		t.Fatalf("rowCap=%d, want 5000", rowCap)
	}
	// 双口径 + 行帽按字节披露：行帽按行不按字节，理论体积上限必须随文案
	// 可见（5000 行 ×128KiB = 625 MiB）。
	if summary != "每日清理 · 保留 30 天 / 上限 5000 行（按行计，单行最大约 128KiB，理论体积上限约 625 MiB）" {
		t.Fatalf("summary=%q, want 天数+行帽+字节预算三口径", summary)
	}
	// 缺省形态（0=内置默认）同样表达双口径与字节预算（100 万行 ≈ 122 GiB）。
	if _, err := db.DB.Exec(`UPDATE global_config SET security_events_retention_days=0, security_events_row_cap=0 WHERE id=1`); err != nil {
		t.Fatal(err)
	}
	summary, _ = SecurityEventsRetentionSnapshot()
	if !strings.Contains(summary, "90 天") || !strings.Contains(summary, "1000000 行") || !strings.Contains(summary, "122 GiB") {
		t.Fatalf("默认 summary=%q, want 含 90 天、1000000 行与 122 GiB 字节预算", summary)
	}
}

// WAL TRUNCATE 检查点低频门控：本轮有删除时不再每次清理批尾都执行
// （与活跃写者 busy_timeout 叠加放大 tick 延迟），间隔内重复触发被跳过，
// 过窗后恢复执行。
func TestSecurityEventsCheckpointWAL_lowFrequencyGate(t *testing.T) {
	setupSecurityEventsRetentionTestDB(t)
	oldInterval := securityEventsWalCheckpointMinInterval
	securityEventsWalCheckpointMinInterval = 10 * time.Minute
	securityEventsWalCheckpointState.mu.Lock()
	securityEventsWalCheckpointState.lastRun = time.Time{}
	securityEventsWalCheckpointState.runCount = 0
	securityEventsWalCheckpointState.busyCount = 0
	securityEventsWalCheckpointState.mu.Unlock()
	t.Cleanup(func() {
		securityEventsWalCheckpointMinInterval = oldInterval
		securityEventsWalCheckpointState.mu.Lock()
		securityEventsWalCheckpointState.lastRun = time.Time{}
		securityEventsWalCheckpointState.mu.Unlock()
	})

	now := time.Now()
	securityEventsCheckpointWALIfDue(db.MetricsDB, now)
	securityEventsCheckpointWALIfDue(db.MetricsDB, now.Add(time.Minute))
	securityEventsCheckpointWALIfDue(db.MetricsDB, now.Add(11*time.Minute))

	securityEventsWalCheckpointState.mu.Lock()
	runs := securityEventsWalCheckpointState.runCount
	securityEventsWalCheckpointState.mu.Unlock()
	if runs != 2 {
		t.Fatalf("checkpoint 执行次数=%d, want 2（间隔内触发被门控跳过）", runs)
	}
}

// 检查点 BUSY 让出（活跃写者下的正常形态）显式计数——观测而非吞掉。
func TestSecurityEventsCheckpointWAL_busyCounted(t *testing.T) {
	setupSecurityEventsRetentionTestDB(t)
	securityEventsWalCheckpointState.mu.Lock()
	securityEventsWalCheckpointState.lastRun = time.Time{}
	securityEventsWalCheckpointState.busyCount = 0
	securityEventsWalCheckpointState.mu.Unlock()

	// 持写锁事务制造 BUSY：检查点在写者活跃时让出（busy=1）。
	tx, err := db.MetricsDB.Begin()
	if err != nil {
		t.Fatal(err)
	}
	if _, err := tx.Exec(`INSERT INTO security_events (event_time, client_ip, event_type) VALUES (datetime('now'), '198.51.100.9', 'lock-holder')`); err != nil {
		t.Fatal(err)
	}
	securityEventsCheckpointWALIfDue(db.MetricsDB, time.Now())
	_ = tx.Rollback()

	securityEventsWalCheckpointState.mu.Lock()
	busy := securityEventsWalCheckpointState.busyCount
	securityEventsWalCheckpointState.mu.Unlock()
	if busy != 1 {
		t.Fatalf("busyCount=%d, want 1（写者活跃时检查点让出必须计数）", busy)
	}
}
