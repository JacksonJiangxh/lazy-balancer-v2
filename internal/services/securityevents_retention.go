package services

import (
	"context"
	"fmt"
	"time"

	"lazy-balancer-v2/internal/db"
)

const (
	// GEO25-2(历史):默认保留与操作日志同口径 90 天(3 个月)——
	// 原 30 天静默分裂(读 DB 失败/0 值时静默降级 30 天,兄弟组件 90 天)。
	securityEventsRetentionDefaultDays = 90
	securityEventsRetentionDefaultMax  = 1000000 // 2026-09-14 用户裁定:10 万→100 万(索引全覆盖,无查询性能影响)
	// securityEventsRetentionDeleteBatch 是年龄裁剪与 count 超限裁剪共用的单批
	// 删除行数（历史问题 E 起年龄裁剪亦按此批次执行，同口径）：大批量单语句 DELETE
	// 会长时间持指标库写锁，阻塞摄取 tick（历史问题 F9）。
	// v2.3.8 批次上调（100/s 压力设计：摊销删除吞吐翻四倍，批间让写锁）
	securityEventsRetentionDeleteBatch = 20000
)

// SecurityEventsRetentionMax 返回安全事件行数上限（v2.3.8 起可经
// security_events_row_cap 显式设置，0=内置默认）。
func SecurityEventsRetentionMax() int {
	return securityEventsRetentionPolicyFromDB().Max
}

// securityEventsRetentionPolicy 是安全事件保留策略的解析结果（单源——清理体、
// 行帽展示与面板摘要共用同一次读逻辑，避免多处口径分裂）。
type securityEventsRetentionPolicy struct {
	Days int // 生效保留天数
	Max  int // 生效行数上限
}

// SecurityEventsRetentionSummary 返回安全事件保留口径的可读摘要（日志统计面板
// security_events 行展示）。安全事件保留完全由本表两个配置项决定，不再读取
// audit_retention_months（审计表独立口径）。
func SecurityEventsRetentionSummary() string {
	policy := securityEventsRetentionPolicyFromDB()
	return fmt.Sprintf("每日清理 · 保留 %d 天", policy.Days)
}

// securityEventsRetentionPolicyFromDB 读取安全事件保留策略（独立配置项）：
// security_events_retention_days / security_events_row_cap；0/缺省使用内置
// 默认 90 天 / 100 万行。审计日志保留月数只作用于 audit_logs，不参与本表。
func securityEventsRetentionPolicyFromDB() securityEventsRetentionPolicy {
	policy := securityEventsRetentionPolicy{Days: securityEventsRetentionDefaultDays, Max: securityEventsRetentionDefaultMax}
	database := db.DB
	if database == nil {
		return policy
	}
	var explicitDays, explicitCap int
	if err := database.QueryRow(`SELECT COALESCE(security_events_retention_days,0), COALESCE(security_events_row_cap,0) FROM global_config WHERE id=1`).Scan(&explicitDays, &explicitCap); err != nil {
		Logf("warn", "security events retention: read retention settings failed, falling back to %d days: %v", policy.Days, err)
		return policy
	}
	if explicitDays > 0 {
		policy.Days = explicitDays
	}
	if explicitCap > 0 {
		policy.Max = explicitCap
	}
	return policy
}

// securityEventsRetentionSettings 读取保留策略（天数, 行帽）——清理体消费。
func securityEventsRetentionSettings() (days, max int) {
	policy := securityEventsRetentionPolicyFromDB()
	return policy.Days, policy.Max
}

// securityEventsRetentionCleanup deletes events older than the configured
// retention window, then trims the oldest rows while the table still holds
// more rows than the configured maximum. The DB handle is captured locally so
// a concurrent test teardown (db.DB = nil) cannot nil-deref mid-pass.
// 历史问题：批间让出写锁的等待同时检查 ctx——Stop（cancel 后等待 worker 退出）
// 得以在大批量首遍（如数据恢复后的百万行）中及时中止，不再被拖到 docker
// SIGKILL 跳过 db.Close。
// SecurityEventsRetentionCleanupOnce 单轮过期事件清理（引擎每日节拍），按保留期
// 清理安全事件并返回删除条数（§6.5 摘要行数据源）。
func SecurityEventsRetentionCleanupOnce() int {
	return securityEventsRetentionCleanup(context.Background())
}

func securityEventsRetentionCleanup(ctx context.Context) int {
	database := db.MetricsDB
	if database == nil {
		return 0
	}
	days, max := securityEventsRetentionSettings()
	total := 0
	// 年龄裁剪同样分批执行（与 count 裁剪同口径）：大表单条 DELETE 长时间持
	// 指标库写锁，阻塞摄取 tick（历史问题 E）。
	for {
		res, err := database.Exec(`DELETE FROM security_events WHERE id IN (SELECT id FROM security_events WHERE event_time < datetime('now', printf('-%d days', ?)) ORDER BY id ASC LIMIT ?)`, days, securityEventsRetentionDeleteBatch)
		if err != nil {
			Logf("warn", "security events retention: age-based cleanup failed: %v", err)
			break
		}
		affected, _ := res.RowsAffected()
		total += int(affected)
		if affected == 0 {
			break
		}
		// 批间短暂让出写锁，避免长时间阻塞摄取 INSERT；同时响应 ctx 取消（历史问题）
		select {
		case <-ctx.Done():
			Logf("info", "security events retention: age-based cleanup canceled mid-pass")
			// SEC-L1（历史）：返回契约统一为「已删多少报多少」——取消
			// 路径此前 return 0 丢弃已提交批次，§6.5 摘要行少报。下同三处。
			return total
		case <-time.After(10 * time.Millisecond):
		}
	}
	if err := ctx.Err(); err != nil {
		return total
	}
	var count int
	if err := database.QueryRow(`SELECT COUNT(*) FROM security_events`).Scan(&count); err != nil {
		Logf("warn", "security events retention: row count failed: %v", err)
		return total // SEC-L1：age 阶段已删计数不丢弃
	}
	if overflow := count - max; overflow > 0 {
		remaining := overflow
		for remaining > 0 {
			batch := remaining
			if batch > securityEventsRetentionDeleteBatch {
				batch = securityEventsRetentionDeleteBatch
			}
			res, err := database.Exec(`DELETE FROM security_events WHERE id IN (SELECT id FROM security_events ORDER BY id ASC LIMIT ?)`, batch)
			if err != nil {
				Logf("warn", "security events retention: count-based cleanup failed: %v", err)
				break
			}
			affected, _ := res.RowsAffected()
			if affected == 0 {
				break
			}
			remaining -= int(affected)
			// SEC-L1：count 阶段删除同样计入返回（此前只减 remaining 从不累加
			// total——审计建议遗漏点：仅改 return 不补累计，count 阶段删除在
			// 正常终点同样少报）。
			total += int(affected)
			// 批间短暂让出写锁，避免长时间阻塞摄取 INSERT；同时响应 ctx 取消（历史问题）
			select {
			case <-ctx.Done():
				Logf("info", "security events retention: count-based cleanup canceled mid-pass")
				return total
			case <-time.After(10 * time.Millisecond):
			}
		}
	}
	// 历史问题（历史）：security_event_rollup 保留清理——全仓此前无任何
	// 删除点，分钟聚合行无限增长。保留天数取 max(31, 事件保留天数)：31 天
	// 下界保证「当前与上一完整分钟」恒在（大屏 recent_rate/小时直方最小窗口
	// 只有 24h）。按分钟分批（每批 60 个分钟组）删除，批间让写锁并响应 ctx。
	rollupDays := days
	if rollupDays < 31 {
		rollupDays = 31
	}
	rollupCutoff := time.Now().UTC().AddDate(0, 0, -rollupDays).Format("2006-01-02 15:04")
	rollupDeleted := 0
	for {
		res, err := database.Exec(`DELETE FROM security_event_rollup WHERE minute < ? AND minute IN (
			SELECT minute FROM security_event_rollup WHERE minute < ? GROUP BY minute ORDER BY minute LIMIT 60)`, rollupCutoff, rollupCutoff)
		if err != nil {
			Logf("warn", "security events retention: rollup cleanup failed: %v", err)
			break
		}
		affected, _ := res.RowsAffected()
		rollupDeleted += int(affected)
		if affected == 0 {
			break
		}
		select {
		case <-ctx.Done():
			Logf("info", "security events retention: rollup cleanup canceled mid-pass (deleted %d)", rollupDeleted)
			return total
		case <-time.After(10 * time.Millisecond):
		}
	}
	if rollupDeleted > 0 {
		Logf("info", "security events retention: rollup cleanup removed %d rows older than %s", rollupDeleted, rollupCutoff)
	}
	// 历史问题（历史）：目标维度 rollup 与主 rollup 同生命周期——同批次/
	// 同保留下界清理，否则 top_targets 投影无限增长。
	targetDeleted := 0
	for {
		res, err := database.Exec(`DELETE FROM security_event_target_rollup WHERE minute < ? AND minute IN (
			SELECT minute FROM security_event_target_rollup WHERE minute < ? GROUP BY minute ORDER BY minute LIMIT 60)`, rollupCutoff, rollupCutoff)
		if err != nil {
			Logf("warn", "security events retention: target rollup cleanup failed: %v", err)
			break
		}
		affected, _ := res.RowsAffected()
		targetDeleted += int(affected)
		if affected == 0 {
			break
		}
		select {
		case <-ctx.Done():
			Logf("info", "security events retention: target rollup cleanup canceled mid-pass (deleted %d)", targetDeleted)
			return total
		case <-time.After(10 * time.Millisecond):
		}
	}
	if targetDeleted > 0 {
		Logf("info", "security events retention: target rollup cleanup removed %d rows older than %s", targetDeleted, rollupCutoff)
	}
	// v2.3.8：本轮有删除时截断 WAL（含仅 rollup 清理；100/s 持续写入+滚动删除下防 WAL 无界）
	if total > 0 || rollupDeleted > 0 || targetDeleted > 0 {
		if _, err := database.Exec(`PRAGMA wal_checkpoint(TRUNCATE)`); err != nil {
			Logf("warn", "security events retention: wal checkpoint failed: %v", err)
		}
	}
	return total
}
