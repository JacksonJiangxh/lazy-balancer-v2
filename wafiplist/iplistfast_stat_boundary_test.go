package wafiplist

// 节流窗口边界的单飞：StatCheckInterval 到期瞬间的 N 个并发读请求只允许
// 一个进入 stat/重建（CAS 抢占本窗检查权），其余直接返回缓存——此前每个
// 请求各自 os.Stat，形成窗口边界的 stat 风暴。

import (
	"fmt"
	"sync"
	"testing"
	"time"
)

func TestResolvePrefixesNormalized_windowBoundarySingleStat(t *testing.T) {
	dir := useAllowedDir(t)
	path := writeListFile(t, dir, "boundary.txt", []string{"10.0.0.0/8", "2001:db8::/48"})
	oldInterval := StatCheckInterval
	StatCheckInterval = time.Minute
	t.Cleanup(func() { StatCheckInterval = oldInterval })

	// 基线加载（首次读盘，产生 1 次 stat）。
	state, err := loadIPListFile(path, false)
	if err != nil {
		t.Fatal(err)
	}

	// 把节流窗口人为拨到「刚过期」：下一次并发请求全部落在窗口边界上。
	baselineStat := ipListStatCalls.Load()
	state.lastCheckTick.Store(monotonicNowNano() - int64(2*time.Minute))

	const concurrency = 32
	var wg sync.WaitGroup
	errs := make([]error, concurrency)
	wg.Add(concurrency)
	for i := range concurrency {
		go func() {
			defer wg.Done()
			prefixes, err := ResolvePrefixesNormalized(path)
			errs[i] = err
			if err == nil && len(prefixes) != 2 {
				errs[i] = fmt.Errorf("前缀数=%d, want 2", len(prefixes))
			}
		}()
	}
	wg.Wait()
	for _, err := range errs {
		if err != nil {
			t.Fatalf("并发解析失败: %v", err)
		}
	}

	// Then：窗口边界只发生一次 stat 检查（旧实现为 N 次）。
	if got := ipListStatCalls.Load() - baselineStat; got != 1 {
		t.Fatalf("窗口边界 stat 次数=%d, want 1（每窗单飞）", got)
	}
}
