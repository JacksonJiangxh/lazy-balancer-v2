package main

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"log"
	"math/big"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"lazy-balancer-v2/internal/db"
	"lazy-balancer-v2/internal/services"
	"lazy-balancer-v2/internal/taskengine"
)

type blockingCertificateWorker struct {
	stopOnce sync.Once
	stop     chan struct{}
	exited   chan struct{}
}

func (w *blockingCertificateWorker) Start() {
	<-w.stop
	close(w.exited)
}

func (w *blockingCertificateWorker) Stop() {
	w.stopOnce.Do(func() { close(w.stop) })
}

type idleSyncWorker struct{}

func (idleSyncWorker) Start() {}
func (idleSyncWorker) Stop()  {}

type countingSyncWorker struct {
	starts atomic.Int32
	stops  atomic.Int32
}

func (w *countingSyncWorker) Start() { w.starts.Add(1) }
func (w *countingSyncWorker) Stop()  { w.stops.Add(1) }

// Shutdown 后 StartSync 必须成为 no-op——进程退出与 taskengine
// daemon 换代并发时，已 teardown 的同步循环不得被重新拉起。
func TestRuntimeLifecycle_ShutdownGatesLaterStarts(t *testing.T) {
	worker := &countingSyncWorker{}
	lifecycle := newRuntimeLifecycle(worker, func() certificateWorker {
		return &blockingCertificateWorker{stop: make(chan struct{}), exited: make(chan struct{})}
	})
	lifecycle.StartSync()
	lifecycle.StartSync() // 重复启动由 worker 自身幂等，此处只断言生命周期门

	lifecycle.Shutdown()
	if got := worker.stops.Load(); got != 1 {
		t.Fatalf("StopSync invocations=%d, want 1", got)
	}

	lifecycle.StartSync() // Shutdown 后必须被 stopped 门拒绝
	if got := worker.starts.Load(); got != 2 {
		t.Fatalf("StartSync after Shutdown must be a no-op: starts=%d (before shutdown=2)", got)
	}
	lifecycle.Shutdown() // 幂等
	if got := worker.stops.Load(); got != 1 {
		t.Fatalf("second Shutdown must not stop again: stops=%d", got)
	}
}

func TestRuntimeLifecycle_StopACME_waitsForWorkerExit(t *testing.T) {
	// Given
	worker := &blockingCertificateWorker{stop: make(chan struct{}), exited: make(chan struct{})}
	lifecycle := newRuntimeLifecycle(idleSyncWorker{}, func() certificateWorker { return worker })
	lifecycle.StartACME()

	// When
	lifecycle.StopACME()

	// Then
	select {
	case <-worker.exited:
	default:
		t.Fatal("StopACME returned before the certificate worker exited")
	}
}

// StopACME 必须与 StartACME 的注入对称，
// 清除 services 侧 active 指针——否则 demote/停机后任务引擎证书单轮体
// （cert-manual-poll 等）继续驱动已停服务（重复到期日志/无角色门补扫）。
// 可观察口径：注入生效时 CertManualCheckOnce 真实消费服务（到期汇总日志），
// StopACME 后同一入口零行为。
func TestRuntimeLifecycle_StopACME_clearsActiveCertificateService(t *testing.T) {
	// Given：临时库 + 一张已过期手动证书，注入真实证书服务
	oldDB, oldMetricsDB, oldAuditDB := db.DB, db.MetricsDB, db.AuditDB
	t.Cleanup(func() {
		// 仅复位指针会泄漏本测试打开的三个 *sql.DB——
		// 先关闭再恢复外层句柄。
		_ = db.Close()
		db.DB, db.MetricsDB, db.AuditDB = oldDB, oldMetricsDB, oldAuditDB
		db.SetDB(oldDB)
	})
	if err := db.Initialize(t.TempDir()); err != nil {
		t.Fatalf("initialize db: %v", err)
	}
	if _, err := db.DB.Exec(`INSERT INTO lb_rules (caddy_id,name,domain,protocol,listen_port,enabled,enable_tls,tls_source,tls_cert) VALUES ('lb_stopacme','stopacme','stopacme.test','http',8080,1,1,'manual',?)`, expiredManualCertPEM(t)); err != nil {
		t.Fatalf("seed expired manual cert rule: %v", err)
	}
	var buf strings.Builder
	oldWriter := log.Writer()
	log.SetOutput(&buf)
	t.Cleanup(func() { log.SetOutput(oldWriter) })

	lifecycle := newRuntimeLifecycle(idleSyncWorker{}, func() certificateWorker { return services.NewCertificateService() })
	lifecycle.StartACME()

	// 观察口：CertRenewalScanOnce 依赖活动证书服务实例（缺失即返回
	// ErrTaskSkipped 哨兵）。CertManualCheckOnce 已与该指针解耦（停机后仍执行
	// 只读巡检），不再能作为「实例已摘除」的观察口。
	// 正向对照：注入生效——扫描进入真实服务路径（不返回 skipped 哨兵）。
	if err := services.CertRenewalScanOnce(); errors.Is(err, taskengine.ErrTaskSkipped) {
		t.Fatalf("after StartACME the renewal scan should reach the active service, err=%v", err)
	}

	// When
	lifecycle.StopACME()

	// Then ①：active 指针已清除——续期扫描回到 skipped 哨兵
	if err := services.CertRenewalScanOnce(); !errors.Is(err, taskengine.ErrTaskSkipped) {
		t.Fatalf("active certificate service survived StopACME: cert-renewal-scan would keep driving a stopped service, err=%v", err)
	}
	// Then ②（交叉断言）：手动到期巡检不依赖实例，停机后照常执行——停机
	// 不得把「手动证书即将到期」这条唯一信号一起关掉。
	buf.Reset()
	services.CertManualCheckOnce()
	if !strings.Contains(buf.String(), "TLS Certificate Check") {
		t.Fatalf("manual expiry check must keep running after StopACME (independent of service instance), log=%q", buf.String())
	}
}

func expiredManualCertPEM(t *testing.T) string {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "stopacme.test"},
		NotBefore:    time.Now().Add(-48 * time.Hour),
		NotAfter:     time.Now().Add(-24 * time.Hour),
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	return string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}))
}
