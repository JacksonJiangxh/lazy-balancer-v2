package middleware

import "testing"

// withIsolatedRateLimitBuckets 保存-清空-恢复全局限流桶表。
//
// 限流桶是进程级全局状态：用例「直接替换 entries」会让计数跨用例继承
// （-count=2 时第二轮因首轮残留计数假红），替换后不恢复又会污染后续用例。
// 本 helper 统一三种语义：用例开始前空表（确定性计数）、结束时恢复调用前
// 的表（不外泄、不吞别人状态）。
func withIsolatedRateLimitBuckets(t *testing.T) {
	t.Helper()
	loginRateBuckets.Lock()
	saved := loginRateBuckets.entries
	loginRateBuckets.entries = make(map[string]*loginRateBucket)
	loginRateBuckets.Unlock()
	t.Cleanup(func() {
		loginRateBuckets.Lock()
		loginRateBuckets.entries = saved
		loginRateBuckets.Unlock()
	})
}
