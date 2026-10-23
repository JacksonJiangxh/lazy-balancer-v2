package services

import (
	"testing"

	"lazy-balancer-v2/internal/acme"
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
