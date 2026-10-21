package services

import (
	"context"
	"time"

	"lazy-balancer-v2/internal/db"
	"lazy-balancer-v2/internal/taskengine"
)

const (
	// updateMaxAttempts 任务内重试：同一任务内对失败步骤最多尝试 3 次
	// （1 初始 + 2 重试），重试等待见 updateAttemptWaits。
	updateMaxAttempts = 3
)

// updateAttemptWaits 第 N 次失败后的重试等待（30s/60s）。
var updateAttemptWaits = []time.Duration{30 * time.Second, 60 * time.Second}

// updateRetrySleep 重试等待（测试可替换为即时返回）。父 ctx 取消会立即
// 中断等待；返回 nil 表示等待完整结束，可进入下一次尝试。
var updateRetrySleep = func(ctx context.Context, d time.Duration) error {
	timer := time.NewTimer(d)
	defer timer.Stop()
	select {
	case <-timer.C:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}

// runWithInTaskRetry 在同一任务内重试失败步骤：第 N 次失败后经 onWait 回调
// （调用方落「等待 Ns 重试，第 x 次，共 x 次」日志），等待后重试；耗尽返回最后错误。
// 父 runCtx 取消在每次操作后、等待前与等待中均优先返回，不得把手动取消
// 当成瞬断再尝试。这里只检查父 ctx，不把源级 DeadlineExceeded 错当取消。
func runWithInTaskRetry(ctx context.Context, op func() error, onWait func(nextAttempt int, wait time.Duration, err error)) error {
	var err error
	for attempt := 1; ; attempt++ {
		if ctxErr := ctx.Err(); ctxErr != nil {
			return ctxErr
		}
		err = op()
		if ctxErr := ctx.Err(); ctxErr != nil {
			return ctxErr
		}
		if err == nil || attempt >= updateMaxAttempts {
			return err
		}
		wait := updateAttemptWaits[attempt-1]
		onWait(attempt+1, wait, err)
		if err := updateRetrySleep(ctx, wait); err != nil {
			return err
		}
	}
}

// updateRunRole 运行期角色三态：(是否主节点, 角色是否已判定)——起点角色门、
// demote 在途中止复核、取消归因共用同一 SQL 口径（COALESCE(is_master,1)）。
// 角色读故障必须是「不可判定」而非并入「非主节点」——否则 DB 瞬断会被误报成
// 「节点已降级」（源行终态与审计失真），或被当作从节点静默跳过本轮（任务监控
// 恒 success 掩盖 DB 异常）。消费口径：!known → 返回错误/记 failed（任务
// 可见）+ warn 留痕；known && !master → 从节点跳过语义（宁停勿写不变）。
func updateRunRole() (bool, bool) {
	if db.DB == nil {
		return false, false
	}
	isMaster, err := RoleOf(context.Background(), db.DB)
	if err != nil {
		return false, false
	}
	return isMaster, true
}

// taskRunStartedAt 取任务引擎预插行的 started_at（配置时区墙钟）并归一
// 为 UTC 存储；前端 formatDate 再按配置时区显示，与任务监控展示同一时刻。
// 直接调用（rc=nil/RunID=0）或行不可读时回退当前 UTC。
func taskRunStartedAt(rc *taskengine.RunContext) string {
	// 历史问题：与同族 历史修复 口径一致——nil 库直接回退当前 UTC（不 panic）。
	if db.DB == nil {
		return time.Now().UTC().Format(crsTimeLayout)
	}
	if rc != nil && rc.RunID > 0 {
		var started string
		if err := db.DB.QueryRow(`SELECT started_at FROM task_runs WHERE id=?`, rc.RunID).Scan(&started); err == nil && started != "" {
			if instant, err := time.ParseInLocation(crsTimeLayout, started, CurrentLocation()); err == nil {
				return instant.UTC().Format(crsTimeLayout)
			}
		}
	}
	return time.Now().UTC().Format(crsTimeLayout)
}
