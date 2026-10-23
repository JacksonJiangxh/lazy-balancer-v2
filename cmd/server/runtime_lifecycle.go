package main

import (
	"sync"
	"time"

	"lazy-balancer-v2/internal/services"
)

type certificateWorker interface {
	Start()
	Stop()
}

type syncWorker interface {
	Start()
	Stop()
}

type runtimeLifecycle struct {
	mu          sync.Mutex
	syncService syncWorker
	certFactory func() certificateWorker
	certService certificateWorker
	certDone    chan struct{}
	// acmeOpsMu 串行化证书侧启停（StartACME vs stopACMEWithin）：停止在途时
	// 不得拉起新一代，否则在途的 queue.Stop() 会关掉新一代队列。它只覆盖
	// 串行化，不覆盖等待——等待一律在锁外按调用方预算有界执行。
	acmeOpsMu sync.Mutex
	// stopped 是 Shutdown 后的启动门：进程退出路径与 taskengine daemon
	// 换代（角色翻转/快速重启）并发时，已 teardown 的 worker 不得被重新拉起
	// （生命周期互斥域对称化：启动/停止两侧同门）。
	stopped bool
}

func newRuntimeLifecycle(syncService syncWorker, certFactory func() certificateWorker) *runtimeLifecycle {
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
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.stopped {
		return
	}
	l.syncService.Start()
}

func (l *runtimeLifecycle) StopSync() {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.syncService.Stop()
}

// Shutdown 是测试缝：用固定预算（acmeStopSegmentMax）调用 ShutdownWithTimeout，
// 让测试不必自行构造关停预算。生产退出路径（main.go 的关停链）一律走
// ShutdownWithTimeout(剩余预算)，本方法在生产代码中无调用点。
func (l *runtimeLifecycle) Shutdown() { l.ShutdownWithTimeout(acmeStopSegmentMax) }

// ShutdownWithTimeout 与 Shutdown 同语义，ACME 收尾等待由调用方给的关停预算
// 派生（进程退出路径传剩余预算）。stopped 门与幂等语义不变。
func (l *runtimeLifecycle) ShutdownWithTimeout(timeout time.Duration) {
	l.mu.Lock()
	if l.stopped {
		l.mu.Unlock()
		return
	}
	l.stopped = true
	l.mu.Unlock()
	// 先置 stopped 再关停：并发的 StartSync/StartACME 已无法再拉起新代。
	// StopSync/StopACME 自身幂等（ACME 的 <-done 在锁外等待）。
	l.StopSync()
	l.stopACMEWithin(timeout)
}
