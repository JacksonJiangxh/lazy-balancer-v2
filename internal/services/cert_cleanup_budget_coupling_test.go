package services

import (
	"testing"

	"lazy-balancer-v2/internal/acme"
	"lazy-balancer-v2/internal/dnsprovider"
	"lazy-balancer-v2/internal/dnsprovider/ownership"
)

// 跨层耦合断言：CA 队列执行预算**上限** + ACME DNS 清理上限必须仍小于
// ownership 的陈旧判定阈值。否则在途签发的挑战记录/账本条目会在清理进行中
// 被他方判为陈旧而并发删除（重复清理 + 误删他人记录）。
//
// 断言必须落在 services 侧：`caExecutionTimeoutMax` 是 services 私有常量，
// acme 作为被依赖层无法导入 services，历史实现因此在 acme 侧镜像一个字面量
// （且注释指向错误的常量），常量上调时测试仍绿。清理上限经
// acme.DNSCleanupBudgetMax() 取值，两侧无字面量镜像。
func TestCleanupBudget_staysBelowStaleOwnershipAge(t *testing.T) {
	cleanupBudget := acme.DNSCleanupBudgetMax()
	total := caExecutionTimeoutMax + cleanupBudget
	if total >= ownership.StaleOwnershipAge {
		t.Fatalf("执行预算上限 %v + 清理上限 %v = %v，必须 < staleOwnershipAge %v",
			caExecutionTimeoutMax, cleanupBudget, total, ownership.StaleOwnershipAge)
	}
}

// 跨层耦合断言：签发分段预算之和必须严格小于 CA 队列外层执行预算。否则最坏
// 路径被外层 ctx 抢先取消，错误从阶段错误（「wait authorization 超时」等）退化
// 为泛化「证书签发执行超时」，并多烧一次 renewal_attempts。
//
// 1 域与 2 域两形态都钉住：2 域是 ACME 域名集的实际上限
// （normalizeAndValidateDomains 拒绝 >2），且余量最小；3 域封顶分支属防御性。
// 分段预算经 acme.IssuanceSegmentBudgetFor 取值，services 侧不镜像任何字面量。
func TestIssuanceSegmentBudget_staysBelowExecutionTimeout(t *testing.T) {
	cases := []struct {
		domains string
		count   int
	}{
		{domains: "example.com", count: 1},
		{domains: "example.com,www.example.com", count: 2},
	}
	for _, tc := range cases {
		segments := acme.IssuanceSegmentBudgetFor(tc.count)
		budget := caExecutionTimeoutFor(tc.domains)
		if segments >= budget {
			t.Fatalf("%d 域分段预算之和 %v 必须 < 外层执行预算 %v", tc.count, segments, budget)
		}
	}
}

// 跨层耦合断言：挑战值登记兜底有效期必须大于「CA 队列执行上限 + DNS 清理
// 上限」。否则同域名同值的第二条签发会在第一条仍在验证时把对方登记判为过期，
// 双方随后都自认最后一方，其中一方会删掉对方仍在等待验证的 TXT（表现为
// 「DNS 传播超时」并白烧 CA 配额）。dnsprovider 不能反向导入 services，
// 故断言落在此侧、由 getter 取值。
func TestChallengeClaimTTL_coversExecutionAndCleanup(t *testing.T) {
	required := caExecutionTimeoutMax + acme.DNSCleanupBudgetMax()
	if ttl := dnsprovider.ChallengeClaimTTL(); ttl <= required {
		t.Fatalf("challengeClaimTTL %v 必须 > 执行上限 %v + 清理上限 %v = %v",
			ttl, caExecutionTimeoutMax, acme.DNSCleanupBudgetMax(), required)
	}
}
