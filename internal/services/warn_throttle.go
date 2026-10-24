package services

import "time"

// throttleWarnAllowed 判定同一 key 在 window 内是否应放行一次告警：放行时
// 记录时间，并顺带回收超过 retention 的键，避免 key 空间在进程生命周期内
// 单调增长。调用方持有 seen 对应的锁并保证 seen 非 nil——各告警族的锁与
// 状态仍归各调用方/测试持有，本函数只收敛「窗口判定 + 插入 + 回收」三段
// 逻辑。
//
// 节点健康解析失败、快照坏行隔离、证书候选告警与审计轮转失败日志此前各写
// 一份同形实现（窗口 60s / 10min / 5min / 60s，GC 与窗口或长于窗口），
// 调窗口或 GC 需要逐处修改且容易漏掉某条新告警。retention 短于 window 时
// 按 window 处理（否则刚放行的键会被立即回收，限频退化为不限频）。
func throttleWarnAllowed[K comparable](seen map[K]time.Time, key K, now time.Time, window, retention time.Duration) bool {
	if retention < window {
		retention = window
	}
	if last, ok := seen[key]; ok && now.Sub(last) < window {
		return false
	}
	throttleWarnEvict(seen, now, retention)
	seen[key] = now
	return true
}

// throttleWarnEvict 回收早于 retention 的键。调用方持锁。
func throttleWarnEvict[K comparable](seen map[K]time.Time, now time.Time, retention time.Duration) {
	for seenKey, seenAt := range seen {
		if now.Sub(seenAt) >= retention {
			delete(seen, seenKey)
		}
	}
}
