package main

import (
	"sync"
	"time"

	"lazy-balancer-v2/internal/services"
)

// lifecycleWorker 是可被 runtimeLifecycle 启停的后台 worker 契约。证书与
// 集群同步两个领域共用同一方法集——领域差异由字段名表达（certService /
// syncService），不为每个领域各声明一个同构接口（那会催生第三个、第四个，
// 却不提供任何额外约束力）。
type lifecycleWorker interface {
	Start()
	Stop()
}

type runtimeLifecycle struct {
	mu          sync.Mutex
	syncService lifecycleWorker
	certFactory func() lifecycleWorker
	certService lifecycleWorker
	certDone    chan struct{}
	// acmeOps 串行化证书侧启停（StartACME vs stopACMEWithin）：停止在途时
	// 不得拉起新一代，否则在途的 queue.Stop() 会关掉新一代队列。互斥**覆盖**
	// 等待——有界等待就在临界区内执行，因此启动最多被推迟一个停止预算。
	// 超时后等待被放弃但互斥即释放：残留在途的停止仍可能落在新一代队列上，
	// 故 acmeStopDone 记录「停止仍在途」，由 StartACME 在拉起新一代前等待它
	// 收尾（有界，超时则拒绝启动并 error，见 StartACME）。
	// 容量 1 的通道而非 sync.Mutex：互斥获取本身必须能按关停预算有界——
	// Mutex.Lock 没有 deadline，并发的证书 daemon 停止（同样持锁、最长一个
	// 停止预算）会把证书段从 timeout 拖成 2×timeout，正好吃掉 compose grace
	// 的余量，使「最坏 25s」的断言在极端形态下失真。
	acmeOps chan struct{}
	// acmeStopDone 是在途 ACME 停止的完成信号（l.mu 保护）：停止启动时登记，
	// 真正收尾（queue.Stop/worker.Stop/<-done 全部返回）后清空并 close。
	// 关停超时只放弃「等待」，不谎称停止已完成——残留停止仍会 PauseAndDrain
	// 并清空规则屏障租约，若此时拉起新一代，证书签发/部署会静默停摆。
	acmeStopDone chan struct{}
	// stopped 是 Shutdown 后的启动门：进程退出路径与 taskengine daemon
	// 换代（角色翻转/快速重启）并发时，已 teardown 的 worker 不得被重新拉起
	// （生命周期互斥域对称化：启动/停止两侧同门）。
	stopped bool
	// syncStopDone 是同步停止的单飞句柄：首次 StopSync 启动唯一的停止
	// goroutine，后续调用（daemon 收尾与 Shutdown 并发）await 同一个 done——
	// 不再二次进入 syncService.Stop()，也不再持 l.mu 等 `<-done`。停止完成时
	// 清空（与 startSyncStopLocked 配对），使换代后的下一次 StopSync 能停新代。
	syncStopDone chan struct{}
}

// syncStopSegmentMax 同步停止在关停预算内的等待上限。同步段的等待源不可
// 预算（pull 客户端 30s + apply 阶段的 DB 写），必须像 ACME 段一样纳入预算
// 派生；剩余预算留给 ACME 收尾。
const syncStopSegmentMax = 3 * time.Second

func newRuntimeLifecycle(syncService lifecycleWorker, certFactory func() lifecycleWorker) *runtimeLifecycle {
	return &runtimeLifecycle{syncService: syncService, certFactory: certFactory, acmeOps: make(chan struct{}, 1)}
}

// acquireACMEOps 在 budget 内获取证书启停互斥；budget<=0 表示只做非阻塞尝试
// （与同层 awaitChannelWithin/runWithin 的「0=放弃」口径一致）。
func (l *runtimeLifecycle) acquireACMEOps(budget time.Duration) bool {
	if budget <= 0 {
		select {
		case l.acmeOps <- struct{}{}:
			return true
		default:
			return false
		}
	}
	timer := time.NewTimer(budget)
	defer timer.Stop()
	select {
	case l.acmeOps <- struct{}{}:
		return true
	case <-timer.C:
		return false
	}
}

// releaseACMEOps 释放证书启停互斥。
func (l *runtimeLifecycle) releaseACMEOps() { <-l.acmeOps }

func (l *runtimeLifecycle) StartACME() {
	// 与在途停止串行化（见 acmeOps）。互斥只保证「同一时刻一个启停动作」，
	// 不保证上一代停止已经收尾——关停超时后互斥已释放而停止 goroutine 还在跑。
	// 拉起新一代前必须等它收尾：在途 queue.Stop() 会 PauseAndDrain 新一代队列
	// 并清空规则屏障租约（证书签发/部署静默停摆）。等待有界（一个停止预算，
	// 互斥获取与在途停止等待共用该预算），超时则拒绝启动并 error——降级为
	// 「无证书 worker 但可诊断」，好过静默启动一个立刻被上一代停止杀掉的队列。
	started := time.Now()
	if !l.acquireACMEOps(acmeStopSegmentMax) {
		services.Logf("error", "证书服务启停竞态：%s 内未取得启停锁（并发停止在途），本次启动放弃（下次换代重试）", acmeStopSegmentMax)
		return
	}
	defer l.releaseACMEOps()
	l.mu.Lock()
	if l.stopped || l.certService != nil {
		l.mu.Unlock()
		return
	}
	pendingStop := l.acmeStopDone
	l.mu.Unlock()
	if pendingStop != nil {
		remaining := acmeStopSegmentMax - time.Since(started)
		if remaining <= 0 {
			services.Logf("error", "证书服务启停竞态：上一代停止仍在途（启停锁等待已耗尽 %s 预算），本次启动放弃以免在途 Stop 关闭新队列（下次换代重试）", acmeStopSegmentMax)
			return
		}
		select {
		case <-pendingStop:
		case <-time.After(remaining):
			services.Logf("error", "证书服务启停竞态：上一代停止仍在途（超过 %s），本次启动放弃以免在途 Stop 关闭新队列（下次换代重试）", acmeStopSegmentMax)
			return
		}
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.stopped || l.certService != nil {
		return
	}
	if queue := services.GetCAQueueManager(); queue != nil {
		queue.Start()
	}
	worker := l.certFactory()
	done := make(chan struct{})
	l.certService = worker
	if cs, ok := worker.(*services.CertificateService); ok {
		services.SetActiveCertificateService(cs) // 任务引擎证书循环单轮 tick 消费
	}
	l.certDone = done
	go func() {
		defer close(done)
		worker.Start()
	}()
}

func (l *runtimeLifecycle) StopACME() { l.stopACMEWithin(acmeStopSegmentMax) }

// stopACMEWithin 与 StopACME 同语义，但等待有界：
// 生产证书 worker 的 Stop 会阻塞到 Start 返回（services.CertificateService.Stop
// 末尾 <-s.done），而 Start 的退出路径上 recoverJobs 是纯 DB 工作、不消费
// 取消信号；CA 队列的 Stop 同样内含不可预算的补偿/排空等待。这些调用放在
// l.mu 内会让「超时 select」永不可达（先无界阻塞在 Stop），且换代钩子
// （StartSync/StopSync）被一起拖住。
//
// 因此本函数把等待逐层移出锁外：锁内只摘指针/清 active 注入，Stop 与
// Start 退出统一放进一个 goroutine，由调用方预算有界等待——超时记录 error
// 后放弃等待（进程继续退出）。放弃等待**不等于**停止已完成：finished 通道
// 登记为 l.acmeStopDone，StartACME 在拉起新一代前会等它收尾（见该函数）。
func (l *runtimeLifecycle) stopACMEWithin(timeout time.Duration) {
	started := time.Now()
	// 互斥获取本身也计入同一个关停预算：并发停止各持一个停止预算，无界等锁
	// 会把证书段从 timeout 拖成 2×timeout，正好吃掉 compose grace 的余量。
	if !l.acquireACMEOps(timeout) {
		// 互斥被在途启停动作持有：若那是另一个停止，等它的完成信号（同一个
		// 预算），让本次调用仍具备「停止已收尾」语义；没有任何在途停止句柄
		// 可等（对端是启动动作）才只能跳过本段。
		l.mu.Lock()
		pendingStop := l.acmeStopDone
		l.mu.Unlock()
		if pendingStop != nil {
			l.awaitACMEStop(pendingStop, timeout-time.Since(started))
			return
		}
		if timeout <= 0 {
			services.Logf("error", "证书服务停止等待超时（关停预算已耗尽），放弃等待继续退出")
		} else {
			services.Logf("error", "证书服务停止等待超时（%s）：未能在预算内取得启停锁（并发启停动作在途），跳过本段继续退出", timeout)
		}
		return
	}
	defer l.releaseACMEOps()

	l.mu.Lock()
	// 已有停止在途：单飞复用它的完成信号，不登记新一代句柄。若用本次的
	// finished 覆写 acmeStopDone，后一个停止快速完成会让 StartACME 误判
	// 前一个（仍在 PauseAndDrain 旧队列）也已收尾而放行新一代。
	if pendingStop := l.acmeStopDone; pendingStop != nil {
		l.mu.Unlock()
		l.awaitACMEStop(pendingStop, timeout-time.Since(started))
		return
	}
	queue := services.GetCAQueueManager()
	worker := l.certService
	done := l.certDone
	l.certService = nil
	l.certDone = nil
	// 与 StartACME 注入对称——停机必须清除任务引擎证书
	// 单轮体消费的 active 指针，否则 demote/停机后 cert-manual-poll 等循环
	// 继续驱动已停服务（重复到期日志/无角色门补扫）。
	services.SetActiveCertificateService(nil)
	l.mu.Unlock()

	if queue == nil && worker == nil && done == nil {
		return
	}
	finished := make(chan struct{})
	// 在启动停止 goroutine 前登记「停止在途」：关停超时只是放弃等待，停止
	// 仍在执行（queue.Stop 的补偿等待可达分钟级），StartACME 必须能看到它。
	l.mu.Lock()
	l.acmeStopDone = finished
	l.mu.Unlock()
	go func() {
		defer func() {
			l.mu.Lock()
			if l.acmeStopDone == finished {
				l.acmeStopDone = nil
			}
			close(finished)
			l.mu.Unlock()
		}()
		if queue != nil {
			queue.Stop()
		}
		if worker != nil {
			worker.Stop()
		}
		if done != nil {
			<-done
		}
	}()
	l.awaitACMEStop(finished, timeout-time.Since(started))
}

// awaitACMEStop 按剩余预算等待一次证书停止收尾；remaining<=0 表示预算已耗尽
// （只做非阻塞检查，进程必须按时退出）。
func (l *runtimeLifecycle) awaitACMEStop(finished <-chan struct{}, remaining time.Duration) {
	if remaining <= 0 {
		// 预算耗尽：不再等待，但如实报告未收尾（非阻塞检查，进程必须按时退出）。
		select {
		case <-finished:
		default:
			services.Logf("error", "证书服务停止等待超时（关停预算已耗尽），放弃等待继续退出")
		}
		return
	}
	select {
	case <-finished:
	case <-time.After(remaining):
		services.Logf("error", "证书服务停止等待超时（%s），放弃等待继续退出（worker goroutine 随进程回收）", remaining)
	}
}

// StartSync/StopSync 与 StartACME 共用 l.mu：cluster-sync 的
// 启停来自 taskengine daemon 换代，Shutdown 与换代并发时原实现无锁——旧代
// Stop 可能在 Shutdown 已 teardown 之后执行，或新代 Start 越过 Shutdown
// 重新拉起同步循环。stopped 门使退出后的 Start 成为 no-op。
func (l *runtimeLifecycle) StartSync() {
	for {
		l.mu.Lock()
		if l.stopped {
			l.mu.Unlock()
			return
		}
		pending := l.syncStopDone
		if pending == nil {
			l.syncService.Start()
			l.mu.Unlock()
			return
		}
		l.mu.Unlock()
		// 停止在途：等它完成再判（等价旧实现里 StartSync 等 l.mu 的语义）——
		// 在途 Stop 可能正在关旧代，此时拉起新代会让两代互相踩。
		<-pending
	}
}

// startSyncStopLocked 启动（或复用）唯一一次 syncService.Stop()。调用方须持
// l.mu；返回共享 done。停止完成时在锁内清字段并 close(done)：清字段先于
// close，避免等待方醒来后看到「done 已关闭但字段仍在」而空转。
func (l *runtimeLifecycle) startSyncStopLocked() chan struct{} {
	if l.syncStopDone != nil {
		return l.syncStopDone
	}
	done := make(chan struct{})
	l.syncStopDone = done
	svc := l.syncService
	go func() {
		svc.Stop()
		l.mu.Lock()
		if l.syncStopDone == done {
			l.syncStopDone = nil
		}
		close(done)
		l.mu.Unlock()
	}()
	return done
}

// StopSync 无预算等待（engine daemon 收尾钩子语义）：首次调用发起停止，后续
// 调用等待同一次停止完成。等待期间不持 l.mu——换代钩子（StartACME/
// StartSync）不再被同步收尾拖住。
func (l *runtimeLifecycle) StopSync() {
	l.mu.Lock()
	done := l.startSyncStopLocked()
	l.mu.Unlock()
	<-done
}

// stopSyncWithin 有界等待同步停止（关停预算派生）：超时记录 error 后放弃
// 等待——残留 goroutine 随进程消亡，绝不让进程越过容器 stop_grace_period。
// d<=0 表示预算已耗尽：只做非阻塞检查，不再等待。
func (l *runtimeLifecycle) stopSyncWithin(d time.Duration) {
	l.mu.Lock()
	done := l.startSyncStopLocked()
	l.mu.Unlock()
	if d <= 0 {
		select {
		case <-done:
		default:
			services.Logf("error", "集群同步停止等待超时（关停预算已耗尽），放弃等待继续退出")
		}
		return
	}
	select {
	case <-done:
	case <-time.After(d):
		services.Logf("error", "集群同步停止等待超时（%s），放弃等待继续退出（在途拉取 goroutine 随进程回收）", d)
	}
}

// ShutdownWithTimeout 关停证书/同步两域：同步段与 ACME 收尾段的等待都由
// 调用方给的关停预算派生（进程退出路径传剩余预算）。stopped 门与幂等语义不变。
// 生产退出路径一律传预算调用本方法；固定预算的测试辅助在
// runtime_lifecycle_test.go（shutdownForTest），产品文件不承载 test-only 入口。
func (l *runtimeLifecycle) ShutdownWithTimeout(timeout time.Duration) {
	l.mu.Lock()
	if l.stopped {
		l.mu.Unlock()
		return
	}
	l.stopped = true
	l.mu.Unlock()
	// 先置 stopped 再关停：并发的 StartSync/StartACME 已无法再拉起新代。
	// 同步段先行但有界：旧实现的无预算 StopSync 排在 ACME 段之前且持 l.mu，
	// 在途 pull 可把关停拖过 compose grace（并卡住换代钩子）；单飞后即使
	// 引擎排空路径已发起同一个停止，本段也只是 await 同一个 done。
	syncBudget := timeout
	if syncBudget > syncStopSegmentMax {
		syncBudget = syncStopSegmentMax
	}
	started := time.Now()
	l.stopSyncWithin(syncBudget)
	remaining := timeout - time.Since(started)
	if remaining < 0 {
		remaining = 0
	}
	l.stopACMEWithin(remaining)
}
