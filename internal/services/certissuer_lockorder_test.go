package services

// 第 88 轮审计 P2-01：部署链（certissuer 持 DeployLock → caddyReloader 内取
// CaddyOpLock，services/caddy.go GenerateAndApplyConfigForce）与恢复链
//（handlers UpdateRule/EnableRule 补偿全程持 caddyOpMu=CaddyOpLock →
// RestoreCertJobsForRule 取 DeployLock，certificates.go）锁序相反，双向互等
// 无超时=AB-BA 死锁。修复=全局锁序统一为 CaddyOpLock → DeployLock：部署
// 临界区先取 CaddyOpLock 再取 DeployLock，重载回调以 InLock 语义调用
//（生产注入 GenerateAndApplyConfigForceInLock，自取锁变体会重入死锁）。

import (
	"context"
	"testing"
	"time"
)

// Given 部署链推进到重载点（部署临界区内）。
// Then 全局 CaddyOpLock 与同规则 DeployLock 必须都已被部署链持有——
// 旧形态只持 DeployLock，CaddyOpLock.TryLock() 必成功（红）。
func TestDeployIssuedCertificate_holdsCaddyOpLockBeforeDeployLock(t *testing.T) {
	jobID, ruleID := seedCertificateJob(t, "downloaded")
	useTemporaryCertDir(t)

	reloaderEntered := make(chan struct{})
	releaseReloader := make(chan struct{})
	issuer := NewCertIssuer(func() error {
		close(reloaderEntered)
		<-releaseReloader
		return nil
	})
	material := issuedCertificate{
		ruleID: ruleID, certPEM: "new-cert", keyPEM: "new-key",
		notAfter: time.Now().Add(90 * 24 * time.Hour), providerID: 1,
	}
	deployDone := make(chan error, 1)
	go func() { deployDone <- issuer.deployIssuedCertificate(context.Background(), jobID, material) }()

	select {
	case <-reloaderEntered:
	case <-time.After(5 * time.Second):
		t.Fatal("部署链未到达重载点")
	}

	// 重载在途=部署临界区内：CaddyOpLock 必须已被部署链持有（主 goroutine 抢不到）。
	if CaddyOpLock.TryLock() {
		CaddyOpLock.Unlock()
		close(releaseReloader)
		<-deployDone
		t.Fatal("部署链重载点未持有 CaddyOpLock——锁序为 DeployLock→CaddyOpLock，与恢复链（CaddyOpLock→DeployLock）构成 AB-BA")
	}
	// 同一时点 DeployLock 也必须仍被持有（恢复链同规则恢复须排队）。
	deployLockFree := make(chan struct{})
	go func() {
		unlock := DeployLock(ruleID)
		unlock()
		close(deployLockFree)
	}()
	select {
	case <-deployLockFree:
		close(releaseReloader)
		<-deployDone
		t.Fatal("部署链重载点未持有 DeployLock")
	case <-time.After(150 * time.Millisecond):
	}

	close(releaseReloader)
	select {
	case err := <-deployDone:
		if err != nil {
			t.Fatalf("部署失败: %v", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("部署未在重载释放后完成")
	}
}

// Given 恢复链临界区形态：主 goroutine 全程持 CaddyOpLock（=caddyOpMu）再取
// DeployLock（UpdateRule/EnableRule 补偿 → RestoreCertJobsForRule）。
// When 部署链并发启动。
// Then 恢复必须先完成（部署链先取 CaddyOpLock，被主持有期间进不了临界区），
// 释放 CaddyOpLock 后部署完成——双方都不得超时（旧形态下部署链先持
// DeployLock 再在重载点等 CaddyOpLock，与恢复链互等=AB-BA；即便重载回调
// 不取锁，部署在主持 CaddyOpLock 期间完成本身即违反统一锁序）。
func TestDeployAndRestoreCertJobs_canonicalLockOrderCompletes(t *testing.T) {
	jobID, ruleID := seedCertificateJob(t, "downloaded")
	useTemporaryCertDir(t)
	snapshot, err := SnapshotCertJobsForRule(ruleID)
	if err != nil {
		t.Fatalf("snapshot: %v", err)
	}

	CaddyOpLock.Lock() // 恢复链 handler 临界区（caddyOpMu=CaddyOpLock 全程持锁）
	issuer := NewCertIssuer(func() error { return nil })
	material := issuedCertificate{
		ruleID: ruleID, certPEM: "new-cert", keyPEM: "new-key",
		notAfter: time.Now().Add(90 * 24 * time.Hour), providerID: 1,
	}
	deployDone := make(chan error, 1)
	go func() { deployDone <- issuer.deployIssuedCertificate(context.Background(), jobID, material) }()
	time.Sleep(50 * time.Millisecond) // 给部署链到达 CaddyOpLock 等待点的窗口

	restoreDone := make(chan error, 1)
	go func() { restoreDone <- RestoreCertJobsForRule(snapshot) }()
	select {
	case err := <-restoreDone:
		if err != nil {
			CaddyOpLock.Unlock()
			t.Fatalf("恢复失败: %v", err)
		}
	case <-time.After(5 * time.Second):
		CaddyOpLock.Unlock()
		t.Fatal("恢复链持 CaddyOpLock 时无法取得 DeployLock——AB-BA 互等")
	}
	// 恢复完成时部署必须仍阻塞在 CaddyOpLock（锁序生效）；旧形态部署早已完成。
	time.Sleep(50 * time.Millisecond)
	select {
	case <-deployDone:
		CaddyOpLock.Unlock()
		t.Fatal("部署链在主 goroutine 持 CaddyOpLock 期间完成——部署未先取 CaddyOpLock，锁序未统一")
	default:
	}
	CaddyOpLock.Unlock()

	select {
	case err := <-deployDone:
		if err != nil {
			t.Fatalf("部署失败: %v", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("部署链未在恢复完成并释放 CaddyOpLock 后完成")
	}
}
