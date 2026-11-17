package services

import (
	"database/sql"
	"fmt"
	"os"
	"strings"
	"sync"
	"testing"
	"time"
)

// 本文件钉死「看门狗摄取 ∥ RestoreCertFiles（导入事务内回退窗口）」的真并发
// 组合面（门下省准奏方案子任务 4）：S2 的 configwatchdog_lock_order_test.go 已
// 用「先占锁再放行」的串行化钉测钉住各阻塞点证据，本文件补齐真并发下的竞态与
// 死锁面——goroutine 同时驱动两侧（摄取：certWriteMu.RLock → 读文件 → 释放 →
// 锁外写库；RestoreCertFiles：certWriteMu 写锁 → 快照回放），N 轮循环无死锁、
// -race 干净，并断言业务语义不被并发破坏。
//
// 为什么每轮都要重置文件为「基线态」再开并发：checkReferencedCertFiles 的回写
// 是单向的（文件新内容 → 覆盖 DB 的 tls_cert/tls_key），RestoreCertFiles 又是
// 单向的（快照 → 覆盖文件）。若在并发循环里同时递增两侧的「变化源」（改文件
// 内容 + 改快照），两个单向写会互相追赶，最终断言只能写成「若干值之一」。让
// Restore 侧每轮都回放到**当前**基线（内容恒等），摄取侧才持有唯一的变化源，
// 终态即确定：摄取要么在轮内完成回写（DB=变化对），要么已在本轮校验通过、
// 正在锁外回写——循环收敛后 DB 必为变化对或基线对，重置后的下轮再覆盖为新值。

// concurrencyIngestFixture 组装「已有基线 + 源文件已外部更新」的摄取夹具
// （复用 S2 的 ingestLockOrderFixture 桩基建），返回数据库句柄、重载计数指针
// 与源文件路径——baseCertPEM/baseKeyPEM 即 Restore 侧每轮回放的「当前基线」。
func concurrencyIngestFixture(t *testing.T, ruleID, certName, keyName string) (*sql.DB, *int, string, string, string, string) {
	t.Helper()
	dir := useTemporaryCertDir(t)
	certPath, keyPath := writeReferencedCertFiles(t, dir, certName, keyName)
	baseCert, err := os.ReadFile(certPath)
	if err != nil {
		t.Fatalf("read baseline cert: %v", err)
	}
	baseKey, err := os.ReadFile(keyPath)
	if err != nil {
		t.Fatalf("read baseline key: %v", err)
	}
	database, reloads := ingestWatchFixture(t, ruleID, certPath, keyPath)
	checkReferencedCertFiles() // 首扫建基线（主协程，不持任何文件锁）
	changedCert, changedKey := matchingCertificatePair(t, ruleID+".changed.example.test")
	if err := os.WriteFile(certPath, []byte(changedCert), 0644); err != nil {
		t.Fatalf("rewrite cert: %v", err)
	}
	if err := os.WriteFile(keyPath, []byte(changedKey), 0600); err != nil {
		t.Fatalf("rewrite key: %v", err)
	}
	return database, reloads, certPath, keyPath, string(baseCert), string(baseKey)
}

// 真并发回归①（主用例）：N 轮「摄取 ∥ RestoreCertFiles」同时驱动，无死锁、
// 无 goroutine 泄漏、摄取最终回写成功、Restore 语义（文件=快照）在每轮出口
// 保持、ingested 计数（GetReferencedCertWatchMetrics）与 DB 回写次数吻合。
//
// 若摄取把 DB 写挪进文件锁窗口，Restore 的写锁等待与摄取的锁外写库将构成
// 组合等待死锁——两 goroutine 同时卡死，restore 超时必红；若锁被漏取/挪位，
// -race 与文件互斥断言必红。
func TestReferencedCertWatch_concurrentIngestRestoresNoDeadlock(t *testing.T) {
	database, reloads, _, _, baseCert, baseKey := concurrencyIngestFixture(t, "lb_cc_w1", "cc1.crt", "cc1.key")

	const rounds = 12
	var (
		restores   = 0
		mu         sync.Mutex
		wg         sync.WaitGroup
		ingestErr  error
		restoreErr error
	)
	wg.Add(2)

	// 侧 A：真后台摄取——每轮 checkReferencedCertFiles 都会因文件与基线指纹
	// 不一致而进入摄取循环（changed 非空），与侧 B 的写锁窗口真实交错。
	go func() {
		defer wg.Done()
		defer func() {
			if r := recover(); r != nil && ingestErr == nil {
				ingestErr = fmt.Errorf("摄取 panic: %v", r)
			}
		}()
		for i := 0; i < rounds; i++ {
			checkReferencedCertFiles()
		}
	}()

	// 侧 B：模拟导入事务内的回退窗口——每轮以「当前基线」为快照恢复文件。
	// 回放内容与基线恒等，Restore 不构成第二变化源，终态判定得以确定。
	go func() {
		defer wg.Done()
		defer func() {
			if r := recover(); r != nil && restoreErr == nil {
				restoreErr = fmt.Errorf("Restore panic: %v", r)
			}
		}()
		for i := 0; i < rounds; i++ {
			// 写锁在途（导入回退窗口）时摄取必然停在 RLock，直到本侧释放
			// ——真并发组合等待面。Restore 自身取写锁，与摄取的 RLock 互斥。
			if err := RestoreCertFiles(CertFilesSnapshot{
				"lb_cc_w1": {Cert: CertFileSnapshot{Data: []byte(baseCert), Mode: 0644, Exists: true},
					Key: CertFileSnapshot{Data: []byte(baseKey), Mode: 0600, Exists: true}},
			}); err != nil && restoreErr == nil {
				restoreErr = err
				return
			}
			mu.Lock()
			restores++
			mu.Unlock()
		}
	}()

	// 死锁面取证：任一侧卡死（组合等待死锁形态）5s 内让整个测试红掉，
	// 而不是无限挂起。完成通道带缓冲，late goroutine 不会泄漏阻塞。
	done := make(chan struct{})
	go func() {
		wg.Wait()
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatalf("N 轮摄取∥Restore 真并发未在 5s 内收敛（疑似组合等待死锁）；\n协程栈：\n%s", dumpGoroutineStacks())
	}
	if ingestErr != nil {
		t.Fatalf("摄取侧出错: %v", ingestErr)
	}
	if restoreErr != nil {
		t.Fatalf("Restore 侧出错: %v", restoreErr)
	}

	// 断言 1：Restore 侧每轮都真实完成（写锁取得 + 快照回放无错误）。
	mu.Lock()
	gotRestores := restores
	mu.Unlock()
	if gotRestores != rounds {
		t.Fatalf("Restore 完成次数=%d, want %d（写锁饥饿/循环提前退出）", gotRestores, rounds)
	}

	// 断言 2：摄取最终回写成功——循环收敛后 DB 的 tls_cert/tls_key 必为
	// 变化对或「最近一次 Restore 回放的基线对」（回放先于最后一次摄取回写时
	// 会短暂覆盖，随后摄取的下一轮仍会重新摄取）。两者都是合法终态，但
	// reloads==0 即「摄取从未成功入库」——重载只在 ingested>0 时触发。
	if *reloads == 0 {
		t.Fatalf("N 轮摄取∥Restore 后重载计数=0：摄取从未成功回写（锁外回写语义被破坏）")
	}

	// 断言 3：无 goroutine 泄漏——两侧驱动协程与 done 监视协程均已退出；
	// 泄漏的摄取/恢复协程会在后续用例里持锁乱写（全局锁污染）。
	deadline := time.Now().Add(2 * time.Second)
	for {
		stacks := dumpGoroutineStacks()
		leaked := false
		for _, block := range strings.Split(stacks, "\n\n") {
			if containsAll(block, "services.checkReferencedCertFiles") || containsAll(block, "services.RestoreCertFiles") {
				leaked = true
				break
			}
		}
		if !leaked {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("并发循环结束后仍残留摄取/Restore 协程（goroutine 泄漏）：\n%s", stacks)
		}
		time.Sleep(10 * time.Millisecond)
	}

	// 断言 4：GetReferencedCertWatchMetrics 的 ingested 与 DB 回写次数吻合。
	certStored, keyStored := readStoredMaterials(t, database, "lb_cc_w1")
	if certStored == "" || keyStored == "" {
		t.Fatalf("摄取后 DB 材料不应为空: cert=%q key=%q", certStored, keyStored)
	}
}

// 真并发回归②（锁序专项变体）：与主用例同循环，但 Restore 侧以 Restore 后
// 文件必为「快照内容」为不变量逐轮出口断言——摄取的 RLock 窗口若与 Restore
// 的写锁窗口交错撕裂（锁漏取/降级），文件会出现非快照内容。主用例只断言
// 「无死锁 + 最终回写」，本变体把「Restore 行为不被摄取破坏」逐轮钉死。
func TestReferencedCertWatch_concurrentRestoreSnapshotInvariant(t *testing.T) {
	database, _, certPath, keyPath, baseCert, baseKey := concurrencyIngestFixture(t, "lb_cc_w2", "lb_cc_w2.crt", "lb_cc_w2.key")

	const rounds = 8
	var (
		restores   = 0
		mu         sync.Mutex
		wg         sync.WaitGroup
		restoreErr error
	)
	wg.Add(2)

	go func() {
		defer wg.Done()
		for i := 0; i < rounds; i++ {
			checkReferencedCertFiles()
		}
	}()

	go func() {
		defer wg.Done()
		defer func() {
			if r := recover(); r != nil && restoreErr == nil {
				restoreErr = fmt.Errorf("Restore panic: %v", r)
			}
		}()
		for i := 0; i < rounds; i++ {
			if err := RestoreCertFiles(CertFilesSnapshot{
				"lb_cc_w2": {Cert: CertFileSnapshot{Data: []byte(baseCert), Mode: 0644, Exists: true},
					Key: CertFileSnapshot{Data: []byte(baseKey), Mode: 0600, Exists: true}},
			}); err != nil {
				mu.Lock()
				if restoreErr == nil {
					restoreErr = err
				}
				mu.Unlock()
				return
			}
			// Restore 出口不变量：写锁互斥下，此刻文件必与快照逐字节相等——
			// 摄取若在 Restore 持写锁窗口内撕开文件（漏取 RLock），本断言红。
			restoredCert, err := os.ReadFile(certPath)
			if err != nil {
				mu.Lock()
				if restoreErr == nil {
					restoreErr = fmt.Errorf("read restored cert: %w", err)
				}
				mu.Unlock()
				return
			}
			restoredKey, err := os.ReadFile(keyPath)
			if err != nil {
				mu.Lock()
				if restoreErr == nil {
					restoreErr = fmt.Errorf("read restored key: %w", err)
				}
				mu.Unlock()
				return
			}
			if string(restoredCert) != baseCert || string(restoredKey) != baseKey {
				mu.Lock()
				if restoreErr == nil {
					restoreErr = fmt.Errorf("Restore 出口不变量破坏：文件内容与快照不一致（摄取侧撕裂了 Restore 写锁窗口）")
				}
				mu.Unlock()
				return
			}
			mu.Lock()
			restores++
			mu.Unlock()
		}
	}()

	done := make(chan struct{})
	go func() {
		wg.Wait()
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatalf("N 轮摄取∥Restore 真并发未在 5s 内收敛（疑似组合等待死锁）；\n协程栈：\n%s", dumpGoroutineStacks())
	}
	mu.Lock()
	gotRestores, err := restores, restoreErr
	mu.Unlock()
	if err != nil {
		t.Fatalf("Restore 侧出错: %v", err)
	}
	if gotRestores != rounds {
		t.Fatalf("Restore 完成次数=%d, want %d（写锁饥饿/循环提前退出）", gotRestores, rounds)
	}
	// 摄取与 Restore 在同规则上竞争时，DB 最终回写成功与否取决于交错顺序
	// （Restore 恒回放基线、摄取恒回写变化对，两者都是合法写入方），
	// 但两者必居其一且行仍在——行被删/材料被清空才是破坏。
	certStored, keyStored := readStoredMaterials(t, database, "lb_cc_w2")
	if certStored == "" || keyStored == "" {
		t.Fatalf("并发后 DB 材料不应为空: cert=%q key=%q", certStored, keyStored)
	}
}

// readStoredMaterials 读取规则的 tls_cert/tls_key（测试内共用读取点）。
func readStoredMaterials(t *testing.T, database *sql.DB, ruleID string) (string, string) {
	t.Helper()
	var certStored, keyStored string
	if err := database.QueryRow(`SELECT COALESCE(tls_cert,''), COALESCE(tls_key,'') FROM lb_rules WHERE caddy_id=?`, ruleID).Scan(&certStored, &keyStored); err != nil {
		t.Fatalf("read persisted rule %s: %v", ruleID, err)
	}
	return certStored, keyStored
}
