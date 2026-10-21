package services

import (
	"sync"
	"time"
)

// dbValueCache 单个 DB 数值配置的缓存槽（历史修复，历史单源收敛）。
//
// 背景：任务日志大小阈值（task_log_size_mb）与审计日志大小阈值
// （audit_log_size_mb）此前各有一套「TTL + 原子量/互斥量」实现——审计侧
// 「读库失败不缓存」（历史修复），任务侧却把瞬时故障的 10MB 回退值写进
// 5 分钟缓存：DB 抖动一次即让任务日志按偏小阈值被提前滚动，且两套实现易
// 单侧漏改。
//
// 本类型只承载缓存机制（TTL + 同槽单飞 + 显式失效）；读库语句与回退值仍由
// 调用方决定。统一口径：**load 失败不写入缓存**，回退值只对本轮生效，下一轮
// 重试——不把瞬时故障钉死整个窗口。
type dbValueCache struct {
	ttl   time.Duration
	mu    sync.Mutex
	value int64
	at    time.Time
}

// get 返回有效期内缓存值；未命中时持锁调用 load（同槽单飞——审计轮转 2s
// tick 只会产生一次查询，并发读不到部分初始化的值）。load 失败返回 fallback
// 且不缓存。
func (c *dbValueCache) get(load func() (int64, error), fallback int64) int64 {
	if v, ok := c.fresh(); ok {
		return v
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	if v, ok := c.freshLocked(); ok {
		return v
	}
	v, err := load()
	if err != nil {
		return fallback
	}
	c.value, c.at = v, time.Now()
	return v
}

// invalidate 清空缓存（设置保存/导入后必须调用，否则最长 TTL 内仍按旧阈值）。
func (c *dbValueCache) invalidate() {
	c.mu.Lock()
	c.at = time.Time{}
	c.mu.Unlock()
}

func (c *dbValueCache) fresh() (int64, bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.freshLocked()
}

func (c *dbValueCache) freshLocked() (int64, bool) {
	if c.at.IsZero() || time.Since(c.at) >= c.ttl {
		return 0, false
	}
	return c.value, true
}
