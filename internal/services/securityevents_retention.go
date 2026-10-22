package services

import (
	"context"
	"database/sql"
	"fmt"
	"sync"
	"time"

	"lazy-balancer-v2/internal/db"
)

const (
	// 默认保留与操作日志同口径 90 天(3 个月)——
	// 原 30 天静默分裂(读 DB 失败/0 值时静默降级 30 天,兄弟组件 90 天)。
	// 默认值单源=db.Default*（DDL/启动迁移/读侧
	// COALESCE/导入归一同一常量族），本包别名仅供包内可读性。
	securityEventsRetentionDefaultDays = db.DefaultSecurityEventsRetentionDays
	securityEventsRetentionDefaultMax  = db.DefaultSecurityEventsRowCap // 2026-09-14 用户裁定:10 万→100 万(索引全覆盖,无查询性能影响)
	// securityEventsRetentionDeleteBatch 是年龄裁剪与 count 超限裁剪共用的单批
	// 删除行数（E 起年龄裁剪亦按此批次执行，同口径）：大批量单语句 DELETE
	// 会长时间持指标库写锁，阻塞摄取 tick。
	// v2.3.8 批次上调（100/s 压力设计：摊销删除吞吐翻四倍，批间让写锁）
	securityEventsRetentionDeleteBatch = 20000
)

// ThreatRollupEventHighwaterPrefix 分钟事件高水位键前缀（单源）：写入侧=大屏
// rollup 固化（handlers 包引用本常量），清理侧=保留任务按同一 rollupCutoff
// 删除——两处不得各自硬编码。
const ThreatRollupEventHighwaterPrefix = "threat_rollup_max_event_id:"

// SecurityEventsRetentionSnapshot 一次读取策略并返回（面板摘要, 行数上限）：
// 日志统计面板同一响应内需同时展示两项，收敛为单次
// global_config 点查（此前 Summary 与 Max 各读一遍同一条 SQL）。
// 摘要必须同时表达 Days 与 Max 双口径——cleanup
// 按 count-max 裁剪，只写「保留 N 天」会让行帽提前裁剪的用户可见文案与实际
// 行为漂移（securityEventsRetentionPolicy 本就 Days+Max 双口径）。
func SecurityEventsRetentionSnapshot() (string, int) {
	policy := securityEventsRetentionPolicyFromDB()
	return fmt.Sprintf("每日清理 · 保留 %d 天 / 上限 %d 行", policy.Days, policy.Max), policy.Max
}

// securityEventsRetentionPolicy 是安全事件保留策略的解析结果（单源——清理体、
// 行帽展示与面板摘要共用同一次读逻辑，避免多处口径分裂）。
type securityEventsRetentionPolicy struct {
	Days int // 生效保留天数
	Max  int // 生效行数上限
}

// securityEventsRetentionPolicyFromDB 读取安全事件保留策略（独立配置项）：
// security_events_retention_days / security_events_row_cap；0/缺省使用内置
// 默认 90 天 / 100 万行。审计日志保留月数只作用于 audit_logs，不参与本表。
//
// 写侧拒绝 0（retention 1..3650、row_cap 1..1e8），
// 导入把 0 归一为默认值，SVC 以一次性 marker 迁移存量 0/NULL。读侧保留本
// 0/NULL → 内置默认的 legacy 防御（带外写库/旧库），行为不变——不回写、不
// 改写库值。
func securityEventsRetentionPolicyFromDB() securityEventsRetentionPolicy {
	policy := securityEventsRetentionPolicy{Days: securityEventsRetentionDefaultDays, Max: securityEventsRetentionDefaultMax}
	database := db.DB
	if database == nil {
		return policy
	}
	var explicitDays, explicitCap int
	if err := database.QueryRow(`SELECT COALESCE(security_events_retention_days,0), COALESCE(security_events_row_cap,0) FROM global_config WHERE id=1`).Scan(&explicitDays, &explicitCap); err != nil {
		// 读失败回退内置默认且留痕；本函数同时被每日清理与面板轮询消费，
		// 裸 warn 会在库故障窗口按请求刷屏——接状态转换去重（首报 warn、
		// 恢复 info），与同族配置读取单源口径一致。
		if lvl := logStateTransition("security-events-retention-read", true); lvl != "" {
			Logf(lvl, "security events retention: read retention settings failed, falling back to %d days: %v", policy.Days, err)
		}
		return policy
	}
	if lvl := logStateTransition("security-events-retention-read", false); lvl != "" {
		Logf(lvl, "security events retention: retention settings read recovered")
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
// 批间让出写锁的等待同时检查 ctx——Stop（cancel 后等待 worker 退出）
// 得以在大批量首遍（如数据恢复后的百万行）中及时中止，不再被拖到 docker
// SIGKILL 跳过 db.Close。
// SecurityEventsRetentionCleanupCtxErr 单轮清理入口（导出面唯一形态）：任务体
// 传 rc.Ctx（批间 ctx.Done() 分支才在生产可达，停机时百万行清理可及时中止，
// 不拖过宽限期被 SIGKILL 跳过 db.Close/WAL 落盘），并返回本轮首个清理错误，
// 供任务引擎把失败写进 task_runs。
// Once（无 ctx 包装）与 Ctx（吞错误的 int 包装）全仓
// 零调用，已删除——注释曾称「保留给测试/兼容调用」与事实不符。
func SecurityEventsRetentionCleanupCtxErr(ctx context.Context) (int, error) {
	return securityEventsRetentionCleanup(ctx)
}

func securityEventsRetentionCleanup(ctx context.Context) (int, error) {
	database := db.MetricsDB
	if database == nil {
		return 0, nil
	}
	days, max := securityEventsRetentionSettings()
	total := 0
	// 年龄裁剪同样分批执行（与 count 裁剪同口径）：大表单条 DELETE 长时间持
	// 指标库写锁，阻塞摄取 tick。
	for {
		res, err := database.Exec(`DELETE FROM security_events WHERE id IN (SELECT id FROM security_events WHERE event_time < datetime('now', printf('-%d days', ?)) ORDER BY id ASC LIMIT ?)`, days, securityEventsRetentionDeleteBatch)
		if err != nil {
			Logf("warn", "security events retention: age-based cleanup failed: %v", err)
			return total, err
		}
		affected, _ := res.RowsAffected()
		total += int(affected)
		if affected == 0 {
			break
		}
		// 批间短暂让出写锁，避免长时间阻塞摄取 INSERT；同时响应 ctx 取消
		select {
		case <-ctx.Done():
			Logf("info", "security events retention: age-based cleanup canceled mid-pass")
			// 返回契约统一为「已删多少报多少」——取消
			// 路径此前 return 0 丢弃已提交批次，§6.5 摘要行少报。下同三处。
			return total, nil
		case <-time.After(10 * time.Millisecond):
		}
	}
	if err := ctx.Err(); err != nil {
		return total, nil
	}
	var count int
	if err := database.QueryRow(`SELECT COUNT(*) FROM security_events`).Scan(&count); err != nil {
		Logf("warn", "security events retention: row count failed: %v", err)
		return total, err // SEC-L1：age 阶段已删计数不丢弃
	}
	if overflow := count - max; overflow > 0 {
		remaining := overflow
		for remaining > 0 {
			batch := remaining
			if batch > securityEventsRetentionDeleteBatch {
				batch = securityEventsRetentionDeleteBatch
			}
			// 按事件时间（event_time ASC, id ASC）
			// 裁剪而非自增 id——摄取停摆后的补采/归档重放会以新 id 插入旧
			// event_time 的行，按 id 删会先删「最早插入」而非「最旧事件」，
			// 即先丢新事件、留住补采的旧事件。与上方年龄裁剪同一时间口径
			// （idx_security_events_time 支撑排序）。
			res, err := database.Exec(`DELETE FROM security_events WHERE id IN (SELECT id FROM security_events ORDER BY event_time ASC, id ASC LIMIT ?)`, batch)
			if err != nil {
				Logf("warn", "security events retention: count-based cleanup failed: %v", err)
				return total, err
			}
			affected, _ := res.RowsAffected()
			if affected == 0 {
				break
			}
			remaining -= int(affected)
			// count 阶段删除同样计入返回（此前只减 remaining 从不累加
			// total——审计建议遗漏点：仅改 return 不补累计，count 阶段删除在
			// 正常终点同样少报）。
			total += int(affected)
			// 批间短暂让出写锁，避免长时间阻塞摄取 INSERT；同时响应 ctx 取消
			select {
			case <-ctx.Done():
				Logf("info", "security events retention: count-based cleanup canceled mid-pass")
				return total, nil
			case <-time.After(10 * time.Millisecond):
			}
		}
	}
	// security_event_rollup 保留清理——全仓此前无任何
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
			return total, err
		}
		affected, _ := res.RowsAffected()
		rollupDeleted += int(affected)
		if affected == 0 {
			break
		}
		select {
		case <-ctx.Done():
			Logf("info", "security events retention: rollup cleanup canceled mid-pass (deleted %d)", rollupDeleted)
			return total, nil
		case <-time.After(10 * time.Millisecond):
		}
	}
	if rollupDeleted > 0 {
		Logf("info", "security events retention: rollup cleanup removed %d rows older than %s", rollupDeleted, rollupCutoff)
	}
	// 目标维度 rollup 与主 rollup 同生命周期——同批次/
	// 同保留下界清理，否则 top_targets 投影无限增长。
	targetDeleted := 0
	for {
		res, err := database.Exec(`DELETE FROM security_event_target_rollup WHERE minute < ? AND minute IN (
			SELECT minute FROM security_event_target_rollup WHERE minute < ? GROUP BY minute ORDER BY minute LIMIT 60)`, rollupCutoff, rollupCutoff)
		if err != nil {
			Logf("warn", "security events retention: target rollup cleanup failed: %v", err)
			return total, err
		}
		affected, _ := res.RowsAffected()
		targetDeleted += int(affected)
		if affected == 0 {
			break
		}
		select {
		case <-ctx.Done():
			Logf("info", "security events retention: target rollup cleanup canceled mid-pass (deleted %d)", targetDeleted)
			return total, nil
		case <-time.After(10 * time.Millisecond):
		}
	}
	if targetDeleted > 0 {
		Logf("info", "security events retention: target rollup cleanup removed %d rows older than %s", targetDeleted, rollupCutoff)
	}
	// 分钟事件高水位键 threat_rollup_max_event_id:<minute>
	// 与 rollup 同生命周期——此前每分钟一行常驻 metrics_state（约 1440 行/天、
	// 52.5 万行/年），全仓无删除点。按同一 rollupCutoff 清理（键后缀为
	// 'YYYY-MM-DD HH:MM' 同形态，字符串比较即时间序）。
	highwaterDeleted := 0
	for {
		res, err := database.Exec(`DELETE FROM metrics_state WHERE key IN (
			SELECT key FROM metrics_state WHERE key LIKE ? AND substr(key, ?) < ? LIMIT 500)`,
			ThreatRollupEventHighwaterPrefix+"%", len(ThreatRollupEventHighwaterPrefix)+1, rollupCutoff)
		if err != nil {
			Logf("warn", "security events retention: rollup highwater cleanup failed: %v", err)
			return total, err
		}
		affected, _ := res.RowsAffected()
		highwaterDeleted += int(affected)
		if affected == 0 {
			break
		}
		select {
		case <-ctx.Done():
			Logf("info", "security events retention: rollup highwater cleanup canceled mid-pass (deleted %d)", highwaterDeleted)
			return total, nil
		case <-time.After(10 * time.Millisecond):
		}
	}
	if highwaterDeleted > 0 {
		Logf("info", "security events retention: rollup highwater cleanup removed %d keys older than %s", highwaterDeleted, rollupCutoff)
	}
	// 本轮有删除时考虑截断 WAL（含仅 rollup 清理；100/s 持续写入+滚动删除
	// 下防 WAL 无界）。TRUNCATE 检查点在活跃写者（摄取 tick/rollup warmer）
	// 下易遇 BUSY 且与 30s busy_timeout 叠加放大 tick 延迟——不再每轮清理
	// 批尾执行，收敛为低频门控 + BUSY 显式计数观测（语义不变，频次解耦）。
	if total > 0 || rollupDeleted > 0 || targetDeleted > 0 || highwaterDeleted > 0 {
		securityEventsCheckpointWALIfDue(database, time.Now())
	}
	return total, nil
}

// securityEventsWalCheckpointMinInterval 是 WAL TRUNCATE 检查点的最小间隔
// （var 供测试收窄）。
var securityEventsWalCheckpointMinInterval = 10 * time.Minute

// securityEventsWalCheckpointState 低频门控与 BUSY 观测状态（测试可重置）。
var securityEventsWalCheckpointState struct {
	mu        sync.Mutex
	lastRun   time.Time
	runCount  int
	busyCount int
}

// securityEventsCheckpointWALIfDue 距上次检查点超过最小间隔才执行
// wal_checkpoint(TRUNCATE)。BUSY（结果行 busy=1，活跃写者下的正常让出）
// 显式计数并留痕——观测而非改语义；错误告警同旧口径。
func securityEventsCheckpointWALIfDue(database *sql.DB, now time.Time) {
	securityEventsWalCheckpointState.mu.Lock()
	if now.Sub(securityEventsWalCheckpointState.lastRun) < securityEventsWalCheckpointMinInterval {
		securityEventsWalCheckpointState.mu.Unlock()
		return
	}
	securityEventsWalCheckpointState.lastRun = now
	securityEventsWalCheckpointState.mu.Unlock()

	var busy, logFrames, checkpointed int
	err := database.QueryRow(`PRAGMA wal_checkpoint(TRUNCATE)`).Scan(&busy, &logFrames, &checkpointed)
	securityEventsWalCheckpointState.mu.Lock()
	securityEventsWalCheckpointState.runCount++
	if busy != 0 {
		securityEventsWalCheckpointState.busyCount++
	}
	busyTotal := securityEventsWalCheckpointState.busyCount
	securityEventsWalCheckpointState.mu.Unlock()
	if err != nil {
		Logf("warn", "security events retention: wal checkpoint failed: %v", err)
		return
	}
	if busy != 0 {
		Logf("info", "security events retention: wal checkpoint busy（活跃写者让出，累计 %d 次）", busyTotal)
	}
}
