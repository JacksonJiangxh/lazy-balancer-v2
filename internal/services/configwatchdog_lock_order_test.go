package services

import (
	"database/sql"
	"os"
	"strings"
	"testing"
	"time"
)

// 本文件钉死引用证书看门狗摄取路径的单一锁序（门下省准奏方案子任务 2）：
//
//	取 certWriteMu.RLock → 读源/比对文件 → 释放 RLock → 锁外回写 SQLite
//
// 死锁依据：RestoreCertFiles 取 certWriteMu 写锁（certstore.go:483-485）且在
// 导入事务内被调用（config_import_coordinator.go:670）。若看门狗在 RLock 窗口
// 内触碰 SQLite 写，即构成「看门狗持 RLock 等库 ∥ 导入事务持库等写锁」组合
// 等待死锁。
//
// 钉法：全部驱动真实的 checkReferencedCertFiles（非锁序复刻），以协程栈命中
// 「生产函数名 + 具体锁等待点」为证据——锁被漏取/挪位时协程不会停在对应等待
// 点上，waitGoroutineBlockedOn 5s 超时必红（已做变异验证：删 RLock 窗口后
// 钉测①红）。

// ingestLockOrderFixture 组装「已有基线 + 源文件已外部更新」的摄取夹具：
// 返回数据库句柄与重载计数指针，下一轮 checkReferencedCertFiles 必然进入
// 摄取循环（changed 非空）。
func ingestLockOrderFixture(t *testing.T, ruleID, certName, keyName string) (*sql.DB, *int, string, string) {
	t.Helper()
	dir := useTemporaryCertDir(t)
	certPath, keyPath := writeReferencedCertFiles(t, dir, certName, keyName)
	database, reloads := ingestWatchFixture(t, ruleID, certPath, keyPath)
	checkReferencedCertFiles() // 首扫建基线（主协程，不持任何文件锁）
	changedCert, changedKey := matchingCertificatePair(t, ruleID+".changed.example.test")
	if err := os.WriteFile(certPath, []byte(changedCert), 0644); err != nil {
		t.Fatalf("rewrite cert: %v", err)
	}
	if err := os.WriteFile(keyPath, []byte(changedKey), 0600); err != nil {
		t.Fatalf("rewrite key: %v", err)
	}
	return database, reloads, certPath, keyPath
}

// runIngestInBackground 后台跑一轮真实摄取，返回完成信号（不阻塞）。
func runIngestInBackground() chan struct{} {
	done := make(chan struct{})
	go func() {
		defer close(done)
		checkReferencedCertFiles()
	}()
	return done
}

// 锁序钉测①：摄取的文件校验阶段必须阻塞在 certWriteMu.RLock——
// RestoreCertFiles（写锁，导入回退窗口）持有期间摄取不得越过 RLock 直接读
// 文件。漏取 RLock（校验裸读）时协程不停在锁等待上，用例超时必红。
func TestReferencedCertWatch_ingestWaitsForCertWriteLock(t *testing.T) {
	ingestLockOrderFixture(t, "lb_lk_w1", "lk1.crt", "lk1.key")
	// Given：持 certWriteMu 写锁占坑（模拟导入事务内 RestoreCertFiles 窗口）
	certWriteMu.Lock()
	locked := true
	t.Cleanup(func() {
		if locked {
			certWriteMu.Unlock()
		}
	})

	// When/Then：后台摄取协程必须确定地阻塞在
	// checkReferencedCertFiles → sync.(*RWMutex).RLock。
	done := runIngestInBackground()
	waitGoroutineBlockedOn(t,
		"checkReferencedCertFiles",
		"sync.(*RWMutex).RLock")
	certWriteMu.Unlock()
	locked = false
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("释放写锁后摄取仍未完成")
	}
}

// 锁序钉测②：per-rule 文件锁在 RLock 之后获取——对手方持同规则 per-rule 锁
// （writeCertFiles/RemoveCertFiles 的 tmp→rename 窗口）时，摄取校验必须等待；
// 阻塞点须在 per-rule 的 sync.Mutex 上（RLock 与对手方的 RLock 并容，不得停在
// RWMutex）。漏取 per-rule 锁或顺序颠倒时阻塞点不成立，用例必红。
func TestReferencedCertWatch_ingestWaitsForPerRuleFileLock(t *testing.T) {
	ingestLockOrderFixture(t, "lb_lk_w2", "lk2.crt", "lk2.key")

	// Given：对手方以合法锁序（先 RLock）持 "lb_lk_w2" 的 per-rule 锁。
	certWriteMu.RLock()
	ruleLock := lockCertRuleFile("lb_lk_w2")
	ruleLock.Lock()
	released := false
	t.Cleanup(func() {
		if !released {
			ruleLock.Unlock()
			certWriteMu.RUnlock()
		}
	})

	// When/Then：后台摄取协程取 RLock 应并容通过（不得停在 RWMutex），
	// 随后阻塞在同规则 per-rule 锁（sync.(*Mutex).Lock）。
	done := runIngestInBackground()
	deadline := time.Now().Add(5 * time.Second)
	for {
		stacks := dumpGoroutineStacks()
		for _, block := range strings.Split(stacks, "\n\n") {
			if strings.Contains(block, "checkReferencedCertFiles") &&
				strings.Contains(block, "sync.(*Mutex).Lock") &&
				!strings.Contains(block, "sync.(*RWMutex).RLock") {
				goto blocked
			}
		}
		if time.Now().After(deadline) {
			t.Fatalf("5s 内未观察到摄取协程阻塞在 per-rule 文件锁：\n%s", stacks)
		}
		time.Sleep(10 * time.Millisecond)
	}
blocked:
	ruleLock.Unlock()
	certWriteMu.RUnlock()
	released = true
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("释放 per-rule 锁后摄取仍未完成")
	}
}

// 锁序钉测③：端到端口径——摄取的 DB 回写（含测试缝 hook）必须发生在文件锁
// 之外。写锁占坑期间摄取协程只应停在 RLock（文件校验是唯一锁窗口，位于 DB
// 回写之前）；释放写锁后整轮推进：hook 触发 + 新内容入库（回写在锁外完成的
// 证据）。若实现把 DB 写挪进文件锁窗口，导入事务场景即组合等待死锁。
func TestReferencedCertWatch_ingestWritesSQLiteOutsideFileLock(t *testing.T) {
	database, reloads, certPath, keyPath := ingestLockOrderFixture(t, "lb_lk_w3", "lk3.crt", "lk3.key")

	// Given：测试缝 hook 记录回写窗口（hook 在 DB 写之前触发，位置等价于
	// 写窗口起点）。
	hookFired := make(chan struct{}, 1)
	prevHook := referencedCertIngestBeforeWriteForTest
	referencedCertIngestBeforeWriteForTest = func(string) {
		select {
		case hookFired <- struct{}{}:
		default:
		}
	}
	t.Cleanup(func() { referencedCertIngestBeforeWriteForTest = prevHook })

	// When：持写锁占坑后后台跑一轮真实摄取。
	certWriteMu.Lock()
	locked := true
	t.Cleanup(func() {
		if locked {
			certWriteMu.Unlock()
		}
	})
	done := runIngestInBackground()
	waitGoroutineBlockedOn(t,
		"checkReferencedCertFiles",
		"sync.(*RWMutex).RLock")
	certWriteMu.Unlock()
	locked = false

	// Then：释放后整轮完成，回写在锁外发生（hook 触发）且新内容已入库。
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("释放写锁后摄取仍未完成")
	}
	select {
	case <-hookFired:
	case <-time.After(2 * time.Second):
		t.Fatal("摄取未推进到回写窗口（锁外回写语义被破坏）")
	}
	changedCert, _ := os.ReadFile(certPath)
	changedKey, _ := os.ReadFile(keyPath)
	assertRuleMaterials(t, database, "lb_lk_w3", string(changedCert), string(changedKey))
	if *reloads == 0 {
		t.Fatal("摄取成功后应触发强制重载")
	}
}

// 锁序钉测④（死锁场景直证）：若摄取在文件锁窗口内触碰 SQLite 写，则「导入
// 事务持库写锁 + certWriteMu 写锁在途」窗口会让摄取停在 RLock 等库、导入事务
// 停在写锁等 RLock——组合等待死锁。直证形态：对手方持 certWriteMu 写锁
// （模拟导入事务回退窗口），摄取的 DB 回写必须照常完成（hook 触发 + 内容
// 入库）——回写若在文件锁内，写锁占坑期间摄取永远到不了回写点，用例超时必红。
// 与钉测③的差别：③钉「摄取会等写锁释放才做文件校验」（锁序前置半边），
// ④钉「等到了也照样回写成功」（锁外回写半边），两半合并即完整单一锁序。
func TestReferencedCertWatch_ingestCompletesWhileRestoreLockHeld(t *testing.T) {
	database, reloads, certPath, keyPath := ingestLockOrderFixture(t, "lb_lk_w4", "lk4.crt", "lk4.key")

	// Given：hook 记录回写窗口触发时刻。
	hookFired := make(chan struct{}, 1)
	prevHook := referencedCertIngestBeforeWriteForTest
	referencedCertIngestBeforeWriteForTest = func(string) {
		select {
		case hookFired <- struct{}{}:
		default:
		}
	}
	t.Cleanup(func() { referencedCertIngestBeforeWriteForTest = prevHook })

	// When：先占 certWriteMu 写锁（RestoreCertFiles 窗口），再后台跑摄取；
	// 摄取应停在 RLock（文件校验半边）→ 释放 → 推进到回写（锁外半边）。
	certWriteMu.Lock()
	locked := true
	t.Cleanup(func() {
		if locked {
			certWriteMu.Unlock()
		}
	})
	done := runIngestInBackground()
	waitGoroutineBlockedOn(t, "checkReferencedCertFiles", "sync.(*RWMutex).RLock")
	certWriteMu.Unlock()
	locked = false

	// Then：写锁释放后摄取无阻塞地完成回写（hook 触发 + 入库 + 重载）——
	// 回写不依赖任何文件锁；若回写在文件锁内，本 select 与入库断言均不成立。
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("释放写锁后摄取仍未完成")
	}
	select {
	case <-hookFired:
	case <-time.After(2 * time.Second):
		t.Fatal("摄取未推进到回写窗口（回写疑似被挡在文件锁内）")
	}
	changedCert, _ := os.ReadFile(certPath)
	changedKey, _ := os.ReadFile(keyPath)
	assertRuleMaterials(t, database, "lb_lk_w4", string(changedCert), string(changedKey))
	if *reloads == 0 {
		t.Fatal("摄取成功后应触发强制重载")
	}
}
