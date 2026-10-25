package services

import (
	"context"
	"testing"

	"lazy-balancer-v2/internal/models"
)

// 临界区 panic 后锁必须释放：同步/应用路径可从 gin 路由进入，gin.Recovery 只恢复
// HTTP 栈、不清理互斥状态——裸 Lock/Unlock 一旦在临界区内 panic，包级/实例级锁
// 永久泄漏，后续重载/导入/规则库更新/同步全部阻塞且无持有者诊断信息。
func TestLockHelpers_releaseOnPanic(t *testing.T) {
	t.Run("waf file lock", func(t *testing.T) {
		func() {
			defer func() {
				if recovered := recover(); recovered == nil {
					t.Fatal("预期注入的 panic 被恢复")
				}
			}()
			withWafFileLock(func() { panic("injected waf lock panic") })
		}()
		if !wafFileMu.TryLock() {
			t.Fatal("WAF 文件锁未释放（临界区 panic 后永久泄漏）")
		}
		wafFileMu.Unlock()
	})

	t.Run("caddy op lock", func(t *testing.T) {
		func() {
			defer func() {
				if recovered := recover(); recovered == nil {
					t.Fatal("预期注入的 panic 被恢复")
				}
			}()
			withCaddyOpLock(func() { panic("injected caddy lock panic") })
		}()
		if !CaddyOpLock.TryLock() {
			t.Fatal("Caddy 写锁未释放（临界区 panic 后永久泄漏）")
		}
		CaddyOpLock.Unlock()
	})
}

// pullApplyMu 为服务实例级锁：手动同步端点在 gin.Recovery 下 panic 后若未释放，
// 该实例的后续同步/提升排干永久阻塞。
func TestPullAndApplyLocked_releasesLockOnPanic(t *testing.T) {
	service := &SyncService{}
	service.beforeApplyWrite = func() { panic("injected pull apply panic") }

	func() {
		defer func() {
			if recovered := recover(); recovered == nil {
				t.Fatal("预期注入的 panic 被恢复")
			}
		}()
		_, _ = service.pullAndApplyLocked(context.Background(), models.ClusterSnapshot{})
	}()

	if !service.pullApplyMu.TryLock() {
		t.Fatal("pullApplyMu 未释放（临界区 panic 后永久泄漏）")
	}
	service.pullApplyMu.Unlock()
}

// 反向形状：正常返回路径同样释放锁（defer 与显式 Unlock 等价性）。
func TestPullAndApplyLocked_releasesLockOnNormalReturn(t *testing.T) {
	service := &SyncService{}
	// 停机哨兵分支不触碰 DB 即返回。
	service.pullsStopped = true

	stopped, err := service.pullAndApplyLocked(context.Background(), models.ClusterSnapshot{})
	if !stopped || err != nil {
		t.Fatalf("stopped=%v err=%v, want true/nil", stopped, err)
	}
	if !service.pullApplyMu.TryLock() {
		t.Fatal("正常返回后 pullApplyMu 未释放")
	}
	service.pullApplyMu.Unlock()
}

// 判别力自证（负向对照）：同一 TryLock 断言在「裸持锁后 panic」形态上必须失败。
// 若此用例变绿，说明上面的释放断言失去判别力（无法捕获裸 Lock/Unlock 回归）。
func TestLockReleaseAssertion_catchesMissingDefer(t *testing.T) {
	wafFileMu.Lock()
	func() {
		defer func() { _ = recover() }()
		panic("injected panic without defer unlock")
	}()
	if wafFileMu.TryLock() {
		wafFileMu.Unlock()
		t.Fatal("断言无判别力：无 defer 的裸持锁形态竟被判为已释放")
	}
	wafFileMu.Unlock() // 清理本用例故意留下的持有
}
