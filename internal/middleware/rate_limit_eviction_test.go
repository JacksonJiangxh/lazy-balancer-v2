package middleware

import (
	"testing"
	"time"
)

// 未认证机器端点会用任意 X-Cluster-Token 建 credential 桶；容量满时
// LRU 若把 login 桶淘汰，攻击者即可重置登录/MFA 暴力破解限流。
// 淘汰必须优先选择机器凭证桶，认证作用域桶不得被凭证泛洪冲掉。
func TestRateLimitBucketEviction_protectsLoginScope(t *testing.T) {
	loginRateBuckets.Lock()
	loginRateBuckets.entries = map[string]*loginRateBucket{}
	now := time.Now()
	login := &loginRateBucket{until: now.Add(time.Minute)}
	login.lastUsed.Store(now.Add(-2 * time.Hour).UnixNano()) // 最久未命中，旧实现必淘汰
	loginRateBuckets.entries["203.0.113.9|login"] = login
	for i := 0; i < rateLimitBucketCapacity; i++ {
		key := "203.0.113.9|sync-snapshot|credential:" + string(rune('a'+i%26)) + string(rune('a'+i/26))
		b := &loginRateBucket{until: now.Add(time.Minute)}
		b.lastUsed.Store(now.Add(-time.Hour).UnixNano() + int64(i))
		loginRateBuckets.entries[key] = b
	}
	loginRateBuckets.Unlock()

	acquireRateLimitBucket("203.0.113.9", "sync-snapshot|credential:new", now)

	loginRateBuckets.Lock()
	_, kept := loginRateBuckets.entries["203.0.113.9|login"]
	loginRateBuckets.Unlock()
	if !kept {
		t.Fatal("login bucket evicted by machine credential flood")
	}
}
