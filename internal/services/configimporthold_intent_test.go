package services

// 导入屏障的「延迟启动意图」契约：判定屏障活跃 → 登记意图 → 屏障退出时兑现。
// 判定与登记是两次独立操作，EndConfigImportHold 可能在两者之间跑完（读完意图
// 并退出）——此时意图若无人复核就会永久悬挂，本代进程内没有第二条恢复通道
// （角色一致时不会重启 loop）：CA 队列保持 inactive、证书签发/续签/部署重试
// 整代不启动，直到进程重启。
//
// 这些用例把屏障退出精准插进那个窗口（configImportHoldDeferHook），断言意图
// 仍被兑现（或由本代自愈取走）。

import (
	"testing"
)

// resetConfigImportHoldForTest 归零屏障状态（用例前置与收尾共用；失败提前返回
// 时不得把深度/意图泄漏给同包其他用例）。
func resetConfigImportHoldForTest(t *testing.T) {
	t.Helper()
	configImportHold.Lock()
	configImportHold.depth = 0
	configImportHold.pendingStart = false
	configImportHold.Unlock()
	certIssuanceStartDeferred.Store(false)
	configImportHoldDeferHook = nil
}

// withCertIssuanceLifecycleCounter 注入可计数的证书生命周期启停挂钩，返回
// 启动次数读取器；收尾恢复全局挂钩与屏障状态。
func withCertIssuanceLifecycleCounter(t *testing.T) (func() int, func(int)) {
	t.Helper()
	oldStart, oldStop := certIssuanceLifecycleStart, certIssuanceLifecycleStop
	oldManager := caQueueManager
	starts := 0
	SetCertIssuanceLifecycleHooks(func() { starts++ }, func() {})
	caQueueManager = nil
	resetConfigImportHoldForTest(t)
	t.Cleanup(func() {
		resetConfigImportHoldForTest(t)
		SetCertIssuanceLifecycleHooks(oldStart, oldStop)
		caQueueManager = oldManager
	})
	return func() int { return starts }, func(v int) { starts = v }
}

// 窗口内退出：屏障在「判定活跃」与「登记意图」之间退出时，意图必须仍被兑现。
// 旧实现在这里直接返回（End 已读完意图），启动次数 = 0。
func TestCertIssuanceLifecycle_deferredIntentSurvivesBarrierExitInWindow(t *testing.T) {
	starts, _ := withCertIssuanceLifecycleCounter(t)

	BeginConfigImportHold()
	configImportHoldDeferHook = func() { EndConfigImportHold() }
	startCertIssuanceLifecycle()

	if got := starts(); got != 1 {
		t.Fatalf("屏障在窗口内退出后证书生命周期启动 %d 次, want 1（延迟意图被丢弃=证书链整代停摆）", got)
	}
	if configImportHoldActive() {
		t.Fatal("屏障深度未归零")
	}
	if certIssuanceStartDeferred.Load() {
		t.Fatal("意图已兑现却仍留位（下一次 End 会重复启动）")
	}
}

// 正常形态：屏障活跃期间只登记意图，屏障退出时兑现一次。
func TestCertIssuanceLifecycle_defersIntentWhileBarrierActive(t *testing.T) {
	starts, _ := withCertIssuanceLifecycleCounter(t)

	BeginConfigImportHold()
	startCertIssuanceLifecycle()
	if got := starts(); got != 0 {
		t.Fatalf("屏障期启动了证书生命周期 %d 次, want 0（导入事务会与部署重试并发写库）", got)
	}
	if !certIssuanceStartDeferred.Load() {
		t.Fatal("屏障期未登记延迟启动意图")
	}
	EndConfigImportHold()
	if got := starts(); got != 1 {
		t.Fatalf("屏障退出后启动 %d 次, want 1（延迟意图未兑现）", got)
	}
	EndConfigImportHold() // 幂等：无意图时不得再启动
	if got := starts(); got != 1 {
		t.Fatalf("重复退出屏障又启动了一次：总 %d 次", got)
	}
}

// 屏障不在场：直接启动，不留意图（否则下一次 End 会重复启动）。
func TestCertIssuanceLifecycle_startsDirectlyWithoutBarrier(t *testing.T) {
	starts, _ := withCertIssuanceLifecycleCounter(t)

	BeginConfigImportHold()
	EndConfigImportHold()
	startCertIssuanceLifecycle()
	if got := starts(); got != 1 {
		t.Fatalf("屏障不在场时启动 %d 次, want 1", got)
	}
	if certIssuanceStartDeferred.Load() {
		t.Fatal("直接启动路径不得留下延迟意图")
	}
}

// 队列侧同形：startUnlessConfigImportHold 在窗口内退出时必须返回「可启动」。
func TestCertQueueStartIntent_survivesBarrierExitInWindow(t *testing.T) {
	_, _ = withCertIssuanceLifecycleCounter(t)

	BeginConfigImportHold()
	configImportHoldDeferHook = func() { EndConfigImportHold() }
	if !startUnlessConfigImportHold() {
		t.Fatal("屏障在窗口内退出后仍判「已延迟」：CA 队列将永久 inactive")
	}
	configImportHold.Lock()
	pending := configImportHold.pendingStart
	configImportHold.Unlock()
	if pending {
		t.Fatal("已由本代兑现的启动意图仍留在 pendingStart")
	}
}

// 队列侧正常形态：屏障活跃只登记，退出时由 EndConfigImportHold 消费。
func TestCertQueueStartIntent_defersUntilBarrierEnd(t *testing.T) {
	_, _ = withCertIssuanceLifecycleCounter(t)

	BeginConfigImportHold()
	if startUnlessConfigImportHold() {
		t.Fatal("屏障活跃时不得立即启动队列")
	}
	configImportHold.Lock()
	pending := configImportHold.pendingStart
	configImportHold.Unlock()
	if !pending {
		t.Fatal("屏障活跃时未登记延迟启动意图")
	}
	EndConfigImportHold()
	configImportHold.Lock()
	pending = configImportHold.pendingStart
	configImportHold.Unlock()
	if pending {
		t.Fatal("屏障退出后延迟意图未被消费")
	}
}
