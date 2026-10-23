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
	// acmeOpsMu 串行化证书侧启停（StartACME vs stopACMEWithin）：停止在途时
	// 不得拉起新一代，否则在途的 queue.Stop() 会关掉新一代队列。它只覆盖
	// 串行化，不覆盖等待——等待一律在锁外按调用方预算有界执行。
	acmeOpsMu sync.Mutex
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
	return &runtimeLifecycle{syncService: syncService, certFactory: certFactory}
}

func (l *runtimeLifecycle) StartACME() {
	// 与在途停止串行化（见 acmeOpsMu）；停止自身的有界等待在这里体现为
	// 「启动最多被推迟一个停止预算」，不会成为无界阻塞点。
	l.acmeOpsMu.Lock()
	defer l.acmeOpsMu.Unlock()
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
// 后放弃（残留 goroutine 随进程回收），绝不让进程越过容器 stop_grace_period。
func (l *runtimeLifecycle) stopACMEWithin(timeout time.Duration) {
	l.acmeOpsMu.Lock()
	defer l.acmeOpsMu.Unlock()

	l.mu.Lock()
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
	go func() {
		defer close(finished)
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
	if timeout <= 0 {
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
	case <-time.After(timeout):
		services.Logf("error", "证书服务停止等待超时（%s），放弃等待继续退出（worker goroutine 随进程回收）", timeout)
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

// Shutdown 是测试缝：用固定预算（acmeStopSegmentMax）调用 ShutdownWithTimeout，
// 让测试不必自行构造关停预算。生产退出路径（main.go 的关停链）一律走
// ShutdownWithTimeout(剩余预算)，本方法在生产代码中无调用点。
func (l *runtimeLifecycle) Shutdown() { l.ShutdownWithTimeout(acmeStopSegmentMax) }

// ShutdownWithTimeout 与 Shutdown 同语义，同步段与 ACME 收尾段的等待都由
// 调用方给的关停预算派生（进程退出路径传剩余预算）。stopped 门与幂等语义不变。
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
