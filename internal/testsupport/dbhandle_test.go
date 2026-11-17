package testsupport

import (
	"database/sql"
	"strings"
	"testing"
	"time"

	// 驱动注册（driver name "sqlite"）：本包自检要真开 *sql.DB 句柄，不能
	// 依赖调用方包的测试文件顺带注册。
	_ "github.com/glebarez/go-sqlite"
)

// JJC-20261115-003-B3：守卫的**判别力自证**随实现一并迁到本包（同包可直接调
// 私有函数，导出面仍只有 CheckDBHandleGoroutines）。三个自证分别覆盖：
// 截断检测（转储扩容）、计数面对泄漏的敏感性（+1）、守卫函数本身的返回码。

// TestGoroutineStackDump_growsInsteadOfReturningTruncated 是截断检测的判别力
// 自证：128 字节初始缓冲必然不足以装下全量栈，若实现不检查 n == len(buf)，
// 返回的就是被腰斩的 128 字节（帧名/分块均失真）。
func TestGoroutineStackDump_growsInsteadOfReturningTruncated(t *testing.T) {
	dump, err := goroutineStackDumpFrom(128)
	if err != nil {
		t.Fatalf("转储失败: %v", err)
	}
	if len(dump) <= 128 {
		t.Fatalf("转储长度=%d 不大于初始缓冲 128：截断未被检测（计数面不可信，守卫会安静判绿）", len(dump))
	}
	if !strings.Contains(string(dump), "goroutine ") {
		t.Fatalf("转储不含 goroutine 头行（分块口径失效）: %.120q", string(dump))
	}
}

// TestDBHandleGuardDetectorDetectsLeakedHandle 计数函数自检：故意留一个不
// Close 的 *sql.DB，断言 opener 计数 +1——证明计数面对泄漏敏感，不是恒过。
// 句柄在本用例内关闭，不向 suite 终态残留。
func TestDBHandleGuardDetectorDetectsLeakedHandle(t *testing.T) {
	before, _, err := countSQLPoolGoroutines()
	if err != nil {
		t.Fatalf("count before: %v", err)
	}
	database, err := sql.Open("sqlite", t.TempDir()+"/guard.db")
	if err != nil {
		t.Fatalf("open leaked handle: %v", err)
	}
	// 采样竞态：opener goroutine 由 sql.Open 创建，但被调度到可观测状态有
	// 延迟——紧邻 Open 单次采样偶得 before（全量跑实测），会误报「守卫不敏感」。
	// 界内轮询到 +1 为止，超时仍不等即真不敏感。
	after := before
	deadline := time.Now().Add(dbHandleGoroutineSettleWait)
	for {
		observed, _, countErr := countSQLPoolGoroutines()
		if countErr != nil {
			_ = database.Close()
			t.Fatalf("count after: %v", countErr)
		}
		after = observed
		if after > before || time.Now().After(deadline) {
			break
		}
		time.Sleep(20 * time.Millisecond)
	}
	_ = database.Close()
	if after != before+1 {
		t.Fatalf("opener count before=%d after=%d, want +1（守卫对泄漏不敏感即恒过）", before, after)
	}
}

// TestDBHandleGuardCheck_failsOnLeakedHandle 是**守卫函数本身**的端到端自检：
// 前面的用例只证明计数函数敏感，没证明守卫在超上限时真的会返回失败码（判据
// 接线断了同样是「恒过」）。这里留一个未关闭句柄直接调守卫（assert=true 强制
// 断言：否则以 -run 单独跑本用例时会被子集豁免，自检失效），断言 code=1；
// Close 后（由守卫的结算等待吸收异步退出）断言放行。
func TestDBHandleGuardCheck_failsOnLeakedHandle(t *testing.T) {
	database, err := sql.Open("sqlite", t.TempDir()+"/guard-e2e.db")
	if err != nil {
		t.Fatalf("open leaked handle: %v", err)
	}
	if err := database.Ping(); err != nil {
		_ = database.Close()
		t.Fatalf("建立测试连接失败: %v", err)
	}
	// 先轮询到计数面可观测再调守卫：sql.Open 只创建 opener goroutine，cleaner
	// 在首次建连后才起，两者被调度到可观测状态有延迟（2026-11-15 全量跑实测：
	// 紧邻 Open 采样偶得 openers=0，被守卫判成「判据未接线」——采样竞态，
	// 不是产品缺陷）。等不到协程即可判定守卫对真实泄漏不敏感。
	settleDeadline := time.Now().Add(dbHandleGoroutineSettleWait)
	for {
		openers, cleaners, countErr := countSQLPoolGoroutines()
		if countErr != nil {
			_ = database.Close()
			t.Fatalf("count leaked handle: %v", countErr)
		}
		if openers+cleaners > 0 {
			break
		}
		if time.Now().After(settleDeadline) {
			_ = database.Close()
			t.Fatalf("未关闭句柄未产生可观测的连接池协程（守卫对真实泄漏不敏感）")
		}
		time.Sleep(20 * time.Millisecond)
	}
	if code := checkDBHandleGoroutines(0, true); code != 1 {
		_ = database.Close()
		t.Fatalf("守卫对未关闭句柄返回 code=%d, want 1（守卫判据未接线，上限断言恒过）", code)
	}
	_ = database.Close()
	if code := checkDBHandleGoroutines(0, true); code != 0 {
		t.Fatalf("关闭句柄后守卫仍返回 code=%d（结算等待不足或计数泄漏）", code)
	}
}
