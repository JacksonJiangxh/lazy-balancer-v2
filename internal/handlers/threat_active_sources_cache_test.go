package handlers

// 威胁大屏「活跃攻击源」计数的短 TTL 缓存：同窗口锚点内不重复扫描原始
// 事件表；窗口前移/缓存过期后重查；失败不缓存。

import (
	"testing"
	"time"

	"lazy-balancer-v2/internal/db"
)

func TestThreatActiveSourcesCount_cachedWithinWindow(t *testing.T) {
	newBackupTestHandlers(t)
	resetThreatActiveSourcesCacheForTest()
	oldTTL := threatActiveSourcesCacheTTL
	threatActiveSourcesCacheTTL = 10 * time.Second
	t.Cleanup(func() { threatActiveSourcesCacheTTL = oldTTL; resetThreatActiveSourcesCacheForTest() })

	now := time.Now().UTC()
	since := now.Add(-10 * time.Minute).Truncate(time.Minute).Format("2006-01-02 15:04:05")
	insert := func(ip string) {
		t.Helper()
		if _, err := db.MetricsDB.Exec(`INSERT INTO security_events (client_ip, action) VALUES (?, 'blocked')`, ip); err != nil {
			t.Fatal(err)
		}
	}
	insert("93.184.216.10")
	insert("93.184.216.11")
	insert("10.0.0.5")     // 私网/保留：不计入
	insert("203.0.113.13") // RFC 5737 文档段：同保留地址排除

	got, err := threatActiveSourcesCount(db.MetricsDB, since, now)
	if err != nil {
		t.Fatalf("first count: %v", err)
	}
	if got != 2 {
		t.Fatalf("首次活跃源=%d, want 2（保留地址排除）", got)
	}

	// 同窗口内新增源 IP：TTL 内必须命中缓存、不重查。
	insert("93.184.216.12")
	got, err = threatActiveSourcesCount(db.MetricsDB, since, now.Add(3*time.Second))
	if err != nil {
		t.Fatalf("cached count: %v", err)
	}
	if got != 2 {
		t.Fatalf("TTL 内活跃源=%d, want 2（缓存命中不得重查）", got)
	}

	// 过期后必须重查。
	got, err = threatActiveSourcesCount(db.MetricsDB, since, now.Add(11*time.Second))
	if err != nil {
		t.Fatalf("expired count: %v", err)
	}
	if got != 3 {
		t.Fatalf("过期后活跃源=%d, want 3（必须重查）", got)
	}

	// 窗口前移（新锚点）→ 新键，独立计数（此处窗口起点晚于全部事件之外时
	// 查询为空属预期，仅断言不返回旧窗口缓存值）。
	laterSince := now.Add(10 * time.Minute).Truncate(time.Minute).Format("2006-01-02 15:04:05")
	got, err = threatActiveSourcesCount(db.MetricsDB, laterSince, now.Add(12*time.Second))
	if err != nil {
		t.Fatalf("shifted window count: %v", err)
	}
	if got != 0 {
		t.Fatalf("窗口前移后活跃源=%d, want 0（不得复用旧窗口缓存）", got)
	}
}

// 失败不缓存：指标库不可用时错误必须上抛且不落缓存（下一轮重试自愈）。
func TestThreatActiveSourcesCount_failureNotCached(t *testing.T) {
	newBackupTestHandlers(t)
	resetThreatActiveSourcesCacheForTest()
	t.Cleanup(resetThreatActiveSourcesCacheForTest)

	closed := db.MetricsDB
	if err := closed.Close(); err != nil {
		t.Fatal(err)
	}
	if _, err := threatActiveSourcesCount(closed, "2026-10-22 00:00:00", time.Now()); err == nil {
		t.Fatal("关闭的指标库必须显式报错")
	}
	threatActiveSourcesMu.Lock()
	cached := len(threatActiveSourcesCache)
	threatActiveSourcesMu.Unlock()
	if cached != 0 {
		t.Fatalf("失败结果被缓存（%d 条）", cached)
	}
}
