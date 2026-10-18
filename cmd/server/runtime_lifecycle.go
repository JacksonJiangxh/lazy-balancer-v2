package main

import (
	"sync"

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
	// stopped 是 Shutdown 后的启动门：进程退出路径与 taskengine daemon
	// 换代（角色翻转/快速重启）并发时，已 teardown 的 worker 不得被重新拉起
	// （历史问题-2 生命周期互斥域对称化）。
	stopped bool
}

func newRuntimeLifecycle(syncService syncWorker, certFactory func() certificateWorker) *runtimeLifecycle {
	return &runtimeLifecycle{syncService: syncService, certFactory: certFactory}
}

func (l *runtimeLifecycle) StartACME() {
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

func (l *runtimeLifecycle) StopACME() {
	l.mu.Lock()
	if queue := services.GetCAQueueManager(); queue != nil {
		queue.Stop()
	}
	worker := l.certService
	done := l.certDone
	l.certService = nil
	l.certDone = nil
	// 历史问题-9/历史问题-1：与 StartACME 注入对称——停机必须清除任务引擎证书
	// 单轮体消费的 active 指针，否则 demote/停机后 cert-manual-poll 等循环
	// 继续驱动已停服务（重复到期日志/无角色门补扫）。
	services.SetActiveCertificateService(nil)
	if worker != nil {
		worker.Stop()
	}
	l.mu.Unlock()
	if done != nil {
		<-done
	}
}

// StartSync/StopSync 与 StartACME 共用 l.mu（历史问题-2）：cluster-sync 的
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

func (l *runtimeLifecycle) Shutdown() {
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
	l.StopACME()
}
