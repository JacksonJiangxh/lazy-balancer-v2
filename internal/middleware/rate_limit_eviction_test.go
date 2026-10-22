package middleware

import (
	"fmt"
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

// 匿名端点（oidc-callback / service-control / 机器 scope 的 |ip 桶）
// 每个源 IP 仅凭公开请求即可建桶，攻击者可把 1024 容量填成「全非凭证桶」。
// 此时旧实现回退全表 LRU，最旧的 login/register 桶（10/min 与 30/min 的
// 爆破/审计放大窗口）被淘汰 → 限流窗口被重置且可循环推满。淘汰次序必须
// 为 credential → 非受保护匿名桶 → 受保护桶（仅在别无选择时）。
func TestRateLimitBucketEviction_protectsLoginAndRegisterAmongAnonymousBuckets(t *testing.T) {
	loginRateBuckets.Lock()
	loginRateBuckets.entries = map[string]*loginRateBucket{}
	now := time.Now()
	add := func(key string, age time.Duration) {
		bucket := &loginRateBucket{until: now.Add(time.Minute)}
		bucket.lastUsed.Store(now.Add(-age).UnixNano())
		loginRateBuckets.entries[key] = bucket
	}
	add("198.51.100.1|login", 2*time.Hour) // 最久未命中——旧实现必淘汰
	add("198.51.100.1|register", 110*time.Minute)
	for i := range rateLimitBucketCapacity - 2 {
		add(fmt.Sprintf("198.51.100.%d|oidc-callback", i), time.Hour)
	}
	loginRateBuckets.Unlock()

	acquireRateLimitBucket("203.0.113.9", "service-control", now)

	loginRateBuckets.Lock()
	_, loginKept := loginRateBuckets.entries["198.51.100.1|login"]
	_, registerKept := loginRateBuckets.entries["198.51.100.1|register"]
	_, newKept := loginRateBuckets.entries["203.0.113.9|service-control"]
	size := len(loginRateBuckets.entries)
	loginRateBuckets.Unlock()
	if !loginKept || !registerKept {
		t.Fatalf("login/register 桶被匿名桶洪泛淘汰: login=%v register=%v", loginKept, registerKept)
	}
	if !newKept || size != rateLimitBucketCapacity {
		t.Fatalf("新键必须照常建桶且容量有界: new=%v size=%d want %d", newKept, size, rateLimitBucketCapacity)
	}
}
