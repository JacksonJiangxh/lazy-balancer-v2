package dnsprovider

import (
	"testing"
	"time"
)

// 同域名并发签发（CA 复用 pending 授权 → 同一 token → 同一 keyAuth）时，按值
// 清理必须由最后结束的一方执行：先结束的一方若照旧清理，会把对方仍在等待验证
// 的 TXT 删掉。
func TestChallengeClaim_sameValueConcurrentIssuanceDefersCleanup(t *testing.T) {
	ResetChallengeClaimsForTest()
	t.Cleanup(ResetChallengeClaimsForTest)

	zone, fqdn, value := "example.com", "_acme-challenge.example.com.", "same-key-auth"
	claimA, firstA := ClaimChallengeValue(zone, fqdn, value)
	if !firstA {
		t.Fatal("首笔登记必须返回 first=true（无并发时允许预清理）")
	}
	claimB, firstB := ClaimChallengeValue(zone, fqdn, value)
	if firstB {
		t.Fatal("第二笔同值登记必须返回 first=false（对方仍在途，禁止预清理）")
	}

	if claimA.Release() {
		t.Fatal("先结束的签发不得拿到清理判定权（对方仍在途）")
	}
	if !claimB.Release() {
		t.Fatal("最后结束的签发必须拿到清理判定权")
	}
	if claimA.Release() {
		t.Fatal("重复注销不得二次扣减（会误判为最后一方并删掉在途记录）")
	}
}

func TestChallengeClaim_isolatedByZoneAndValue(t *testing.T) {
	ResetChallengeClaimsForTest()
	t.Cleanup(ResetChallengeClaimsForTest)

	if _, first := ClaimChallengeValue("example.com", "_acme-challenge.example.com.", "v1"); !first {
		t.Fatal("首次登记必须 first=true")
	}
	if _, first := ClaimChallengeValue("example.com", "_acme-challenge.example.com.", "v2"); !first {
		t.Fatal("不同挑战值互不影响")
	}
	if _, first := ClaimChallengeValue("example.net", "_acme-challenge.example.com.", "v1"); !first {
		t.Fatal("不同 zone 互不影响")
	}
	// 大小写/尾点书写差异必须命中同一条登记。
	if _, first := ClaimChallengeValue("Example.COM.", "_ACME-Challenge.Example.com", "v1"); first {
		t.Fatal("DNS 名大小写/尾点差异不得绕开在途登记")
	}
}

func TestChallengeClaim_expiredClaimDoesNotBlockForever(t *testing.T) {
	ResetChallengeClaimsForTest()
	t.Cleanup(ResetChallengeClaimsForTest)

	claim, _ := ClaimChallengeValue("example.com", "_acme-challenge.example.com.", "v1")
	// 模拟「异常退出未注销」：把登记时间推到 TTL 之外，登记不得永久压制清理。
	challengeClaims.mu.Lock()
	for key, owners := range challengeClaims.owners {
		for owner := range owners {
			owners[owner] = challengeClaimRecord{claimedAt: time.Now().Add(-2 * challengeClaimTTL)}
		}
		challengeClaims.owners[key] = owners
	}
	challengeClaims.mu.Unlock()
	if _, first := ClaimChallengeValue("example.com", "_acme-challenge.example.com.", "v1"); !first {
		t.Fatal("过期登记必须被清理，不得永久压制同值清理")
	}
	if claim.Release() {
		t.Fatal("过期登记已被剔除，旧句柄注销不得再拿到判定权")
	}
}
