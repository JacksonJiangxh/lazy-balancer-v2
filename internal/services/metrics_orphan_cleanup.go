package services

// A86 D-4（历史，用户裁定）：删除规则后的 metrics_history 清理失败
// 此前仅 Logf（无审计、无重试）。裁定=失败落操作审计 + taskengine 有界重试
// ——本轮由周期任务 metrics-orphan-cleanup 承担：按「已删除规则」谓词收敛
// 清理残留历史指标（每轮限量分批，天然有界；收敛后每轮零工作）。
//
// 口径：
//   - 仅动 rule_id 非 NULL 的行（全局指标行 rule_id=NULL，不得误删）。
//   - 存活规则清单来自主库 lb_rules（caddy_id 不复用——残留行无功能影响，
//     仅占盘；7 天保留期（CleanupMetricsHistory）另有兜底，本任务只是把
//     「删除时清理失败」的余量提前收敛）。

import (
	"context"
	"fmt"
	"sort"
	"strings"

	"lazy-balancer-v2/internal/db"
)

// metricsOrphanPurgeRulesPerRun 单轮最多清理的孤儿规则数（有界重试的
// 「有界」落点：积压超限时下一轮继续，不在一轮内无限放大删除事务）。
// 变量形态便于测试收窄。
var metricsOrphanPurgeRulesPerRun = 500

// PurgeOrphanMetricsHistory 清理 metrics 库中已删除规则的残留历史指标，
// 返回本轮删除的规则数。调用方（taskengine metrics-orphan-cleanup）按错误
// 落 task_runs failed——不得静默成功。
func PurgeOrphanMetricsHistory(ctx context.Context) (int, error) {
	if db.DB == nil || db.MetricsDB == nil {
		return 0, nil // 无 metrics 库/无主库：无可清理对象（启动早期）
	}
	liveIDs, err := liveRuleIDs(ctx)
	if err != nil {
		return 0, fmt.Errorf("读取存活规则清单: %w", err)
	}
	if err := ctx.Err(); err != nil {
		return 0, err
	}
	orphans, err := orphanMetricsRuleIDs(ctx)
	if err != nil {
		return 0, fmt.Errorf("读取指标库规则清单: %w", err)
	}
	pending := make([]string, 0, len(orphans))
	for _, ruleID := range orphans {
		if !liveIDs[ruleID] {
			pending = append(pending, ruleID)
		}
	}
	if len(pending) == 0 {
		return 0, nil
	}
	sort.Strings(pending) // 确定性：同一积压跨轮次优先清理同一前缀
	if limit := metricsOrphanPurgeRulesPerRun; limit > 0 && len(pending) > limit {
		pending = pending[:limit]
	}
	if err := ctx.Err(); err != nil {
		return 0, err
	}
	placeholders := strings.TrimSuffix(strings.Repeat("?, ", len(pending)), ", ")
	args := make([]any, len(pending))
	for i, ruleID := range pending {
		args[i] = ruleID
	}
	if _, err := db.MetricsDB.ExecContext(ctx, `DELETE FROM metrics_history WHERE rule_id IN (`+placeholders+`)`, args...); err != nil {
		return 0, fmt.Errorf("删除孤儿规则指标: %w", err)
	}
	return len(pending), nil
}

// liveRuleIDs 读取主库存活规则 caddy_id 集合。
func liveRuleIDs(ctx context.Context) (map[string]bool, error) {
	rows, err := db.DB.QueryContext(ctx, `SELECT caddy_id FROM lb_rules`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	live := map[string]bool{}
	for rows.Next() {
		var ruleID string
		if err := rows.Scan(&ruleID); err != nil {
			return nil, err
		}
		live[ruleID] = true
	}
	return live, rows.Err()
}

// orphanMetricsRuleIDs 读取 metrics 库出现过的非 NULL rule_id（去重排序）。
func orphanMetricsRuleIDs(ctx context.Context) ([]string, error) {
	rows, err := db.MetricsDB.QueryContext(ctx, `SELECT DISTINCT rule_id FROM metrics_history WHERE rule_id IS NOT NULL`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	ruleIDs := make([]string, 0)
	for rows.Next() {
		var ruleID string
		if err := rows.Scan(&ruleID); err != nil {
			return nil, err
		}
		ruleIDs = append(ruleIDs, ruleID)
	}
	return ruleIDs, rows.Err()
}
