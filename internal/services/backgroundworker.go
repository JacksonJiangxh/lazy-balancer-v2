package services

import (
	"context"
	"sync"
	"time"
)

// backgroundWorker 是包级后台 worker 的生命周期槽（cancel + done + 互斥）。
// 「取消旧实例 → 有界等待 done → 超时 warn → 字段清零」此前在时区刷新与
// 运行日志尺寸刷新两处逐行同构，且已出现行为分叉（重启路径一份有界、一份
// 无界）——统一到此实现，各 worker 只提供自己的 loop 与日志标签。
type backgroundWorker struct {
	sync.Mutex
	cancel context.CancelFunc
	done   chan struct{}
}

// replace 取消并（有界）等待旧实例，随后安装新实例的生命周期；返回新实例的
// ctx 与 done（调用方在自己的 goroutine 返回前 close(done)）。旧实例卡在
// DB busy_timeout 时不得无界挂起启动链——超时放弃等待并 warn，残留 goroutine
// 由下一次 Stop/进程退出收尾。
func (w *backgroundWorker) replace(ctx context.Context, restartBudget time.Duration, label string) (context.Context, chan struct{}) {
	w.Lock()
	defer w.Unlock()
	if w.cancel != nil {
		w.cancel()
		select {
		case <-w.done:
		case <-time.After(restartBudget):
			Logf("warn", "%s worker 未在重启预算 %s 内退出，放弃等待旧实例（启动新实例继续）", label, restartBudget)
		}
	}
	workerCtx, cancel := context.WithCancel(ctx)
	done := make(chan struct{})
	w.cancel, w.done = cancel, done
	return workerCtx, done
}

// stop 无界停止（进程退出/无预算调用方）。
func (w *backgroundWorker) stop(label string) {
	w.Lock()
	defer w.Unlock()
	w.stopLocked(0, label)
}

// stopWithin 有界停止：cancel 后最多等待 within（within<=0=无界）。超时放弃
// 等待并 warn 且不清零字段（worker 最终退出后可再次调用完成清零，可重启语义
// 不变）。返回 true=worker 已退出且状态清零。
func (w *backgroundWorker) stopWithin(within time.Duration, label string) bool {
	w.Lock()
	defer w.Unlock()
	return w.stopLocked(within, label)
}

func (w *backgroundWorker) stopLocked(within time.Duration, label string) bool {
	if w.cancel == nil {
		return true
	}
	w.cancel()
	if within <= 0 {
		<-w.done
	} else {
		select {
		case <-w.done:
		case <-time.After(within):
			Logf("warn", "%s worker 未在关停预算 %s 内退出，放弃等待（进程继续退出）", label, within)
			return false
		}
	}
	w.cancel = nil
	w.done = nil
	return true
}
