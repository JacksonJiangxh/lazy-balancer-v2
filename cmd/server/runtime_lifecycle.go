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
}

func newRuntimeLifecycle(syncService syncWorker, certFactory func() certificateWorker) *runtimeLifecycle {
	return &runtimeLifecycle{syncService: syncService, certFactory: certFactory}
}

func (l *runtimeLifecycle) StartACME() {
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.certService != nil {
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
	// U1-P3-9/U7-P3-1：与 StartACME 注入对称——停机必须清除任务引擎证书
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

func (l *runtimeLifecycle) StartSync() { l.syncService.Start() }
func (l *runtimeLifecycle) StopSync()  { l.syncService.Stop() }

func (l *runtimeLifecycle) Shutdown() {
	l.StopSync()
	l.StopACME()
}
