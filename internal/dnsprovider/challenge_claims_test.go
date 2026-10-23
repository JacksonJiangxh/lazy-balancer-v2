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
	// 另一条不同挑战值的在途登记：只应影响 v1 的过期判定，不得被一并改写。
	if _, first := ClaimChallengeValue("example.com", "_acme-challenge.example.com.", "v2"); !first {
		t.Fatal("不同挑战值的首次登记必须 first=true")
	}
	// 模拟「异常退出未注销」：只把 v1 的登记时间推到 TTL 之外（此前用例把全部
	// key 的所有 owner 都改成过期，误伤范围无法被发现），登记不得永久压制清理。
	targetKey := challengeClaimKeyOf("example.com", "_acme-challenge.example.com.", "v1")
	challengeClaims.mu.Lock()
	owners := challengeClaims.owners[targetKey]
	for owner := range owners {
		owners[owner] = challengeClaimRecord{claimedAt: time.Now().Add(-2 * challengeClaimTTL)}
	}
	challengeClaims.mu.Unlock()
	if _, first := ClaimChallengeValue("example.com", "_acme-challenge.example.com.", "v1"); !first {
		t.Fatal("过期登记必须被清理，不得永久压制同值清理")
	}
	if _, first := ClaimChallengeValue("example.com", "_acme-challenge.example.com.", "v2"); first {
		t.Fatal("v2 的在途登记未过期，必须继续压制其同值清理")
	}
	if claim.Release() {
		t.Fatal("过期登记已被剔除，旧句柄注销不得再拿到判定权")
	}
}

// nil 接收者必须返回 true（=调用方可以清理）：deferred 清理在未登记/降级路径
// 上会拿到 nil 句柄，返回 false 会让清理被永久跳过。
func TestChallengeClaim_nilReceiverAllowsCleanup(t *testing.T) {
	var claim *ChallengeClaim
	if !claim.Release() {
		t.Fatal("nil 句柄的 Release 必须返回 true（无在途登记 → 允许清理）")
	}
}
