package testsupport

import (
	"flag"
	"fmt"
	"os"
	"runtime"
	"strings"
	"time"
)

// DB 句柄守卫（跨包单源，JJC-20261115-003-B3）：suite 结束时统计 database/sql
// 连接池驻留后台协程（connectionOpener/connectionCleaner）总量，按固定上限断言。
//
// 为什么收在 testsupport 单源：handlers 与 middleware 各留一份计数/结算/断言
// 实现时，任何一处判据修补都会漏掉另一处（「只修测到的包」），上限常量与结算
// 等待也会各自漂移。计数口径、结算等待与失败语义只允许一份实现，各包 TestMain
// 只调用 CheckDBHandleGoroutines（导出面仅此一个函数）。
//
// 背景（2026-11-15 前序排查）：handlers 全量跑完后残留 1032 个泄漏的
// opener/cleaner 协程（约 516 个未关闭 *sql.DB）。泄漏源不在生产迁移逻辑，
// 而在测试基建：db.Initialize/InitializeAuditDB 的成功路径直接覆盖包级
// 句柄且不关旧值（生产进程只调用一次无碍），测试反复调用时被覆盖的句柄
// 永久泄漏——每个未关闭句柄恒定残留 1 个 opener，出现过空闲连接再泄漏
// 1 个 cleaner。
//
// 为什么用 opener/cleaner 计数而不是句柄清单：被覆盖的 *sql.DB 指针已
// 不可达，无法枚举；其驻留协程是进程内唯一可观测的残留信号。
//
// 上限取值依据：2026-11-15 修复前基线（handlers 全量、-count=1）实测
// openers=598 cleaners=598 total=1196；收敛测试基建句柄生命周期后修后实测
// openers=0 cleaners=0 total=0（两次全量复跑一致）。上限即取修后实测 0：
// 句柄泄漏是**永久性**残留（未 Close 的 *sql.DB 不会自行消失），没有「合理
// 余量」的语义空间；Close 后 opener/cleaner 退出存在毫秒级异步窗口，由
// waitSQLPoolGoroutinesSettle 的界内轮询等待吸收，不靠放宽上限掩盖。真实
// 泄漏按每句柄 ≥1 协程计，任何一处漏关即触发失败。
const dbHandleGoroutineCap = 0

// dbHandleGoroutineSettleWait 是 Close 后 opener/cleaner 协程退出的结算
// 等待上界：轮询到计数落入上限即通过，超时才判失败。窗口只为吸收异步退出，
// 不放大上限——永久泄漏的计数不会随时间下降，等满即失败。
const dbHandleGoroutineSettleWait = 2 * time.Second

// 全量栈转储的缓冲策略：从 1MB 起，命中截断即翻倍重取样，上限 64MB（超过
// 说明进程 goroutine 规模异常，直接判失败而不是继续翻倍吃内存）。
const (
	dbHandleStackInitialSize = 1 << 20
	dbHandleStackMaxSize     = 64 << 20
)

// CheckDBHandleGoroutines 是 suite 终态守卫：全绿时打印一行实测值留痕（守卫
// 生效证据），超上限则置失败码——泄漏说明某用例的句柄替换缺 Close 配对。
// 只在全部用例已通过时拦截：失败用例的收尾中断本就不代表终态。
//
// -run 子集跑的语义是**定位**泄漏（按子集打印行做计数差归因）：此时非 0 是
// 待归因的输入而不是结论，守卫只打印 openers/cleaners/total 并标注「不断言」，
// 不让 exit 1 把分项差淹没。全量跑（未给 -run）才启用上限断言。
func CheckDBHandleGoroutines(code int) int {
	return checkDBHandleGoroutines(code, !runSubsetActive())
}

// checkDBHandleGoroutines 是断言开关注入版（私有）：判别力自证必须在
// 「-run 子集跑」（例如单独跑自检用例）下仍能证明超上限会返回 1，否则
// 守卫的自检恰好被自己的子集豁免废掉——自检传 assert=true 强制断言。
func checkDBHandleGoroutines(code int, assert bool) int {
	openers, cleaners, err := waitSQLPoolGoroutinesSettle()
	if err != nil {
		fmt.Fprintf(os.Stderr, "DB句柄守卫: 全量 goroutine 栈无法收口（截断/规模异常），按失败处理: %v\n", err)
		return 1
	}
	total := openers + cleaners
	if !assert {
		fmt.Fprintf(os.Stderr, "DB句柄守卫: openers=%d cleaners=%d total=%d（-run 子集跑：只打印，不断言）\n",
			openers, cleaners, total)
		return code
	}
	fmt.Fprintf(os.Stderr, "DB句柄守卫: openers=%d cleaners=%d total=%d (cap=%d)[断言: total > cap 即失败]\n",
		openers, cleaners, total, dbHandleGoroutineCap)
	if code != 0 {
		// 失败用例收尾中断不代表终态，不叠加句柄判据；计数照打供归因。
		return code
	}
	if total > dbHandleGoroutineCap {
		fmt.Fprintf(os.Stderr, "DB句柄守卫: suite 结束残留连接池后台协程超固定上限（存在未 Close 的 *sql.DB，泄漏点用 -run 子集与打印行计数差归因）\n")
		return 1
	}
	return code
}

// runSubsetActive 报告本次是否是 -run 子集跑。必须在 m.Run() 之后调用：
// TestMain 入口处 testing 尚未 flag.Parse（实测 test.run 恒空、parsed=false），
// 守卫在 m.Run 之后读到的才是真实值。
func runSubsetActive() bool {
	parsed := flag.Lookup("test.run")
	return parsed != nil && parsed.Value.String() != ""
}

// goroutineStackDump 返回**未被截断**的全量 goroutine 栈转储。
//
// 为什么必须检测截断：runtime.Stack 在缓冲不足时返回 n == len(buf) 并
// 静默腰斩——被切开的那个 goroutine 块既可能丢掉尾部帧（含连接池
// opener/cleaner 的帧名），也可能把残余半块并进下一个「块」，于是按空行
// 分块的计数直接失真（漏计或错计）。固定 8MB 缓冲在 goroutine 规模增长后
// 正落在这个陷阱里，且失真方向是「少数」——守卫会安静判绿。故 n == len(buf)
// 一律视为不可信，扩容重取样。
func goroutineStackDump() ([]byte, error) {
	return goroutineStackDumpFrom(dbHandleStackInitialSize)
}

// goroutineStackDumpFrom 是 goroutineStackDump 的可注入初始缓冲版本：初始
// 缓冲作为参数才能测试「截断→扩容」分支本身（用极小缓冲强制首轮截断）。
func goroutineStackDumpFrom(initialSize int) ([]byte, error) {
	for size := initialSize; size <= dbHandleStackMaxSize; size *= 2 {
		buf := make([]byte, size)
		n := runtime.Stack(buf, true)
		if n < len(buf) {
			return buf[:n], nil
		}
		// n == len(buf)：本次转储被截断，丢弃重取样（见函数注释的失真机理）。
	}
	return nil, fmt.Errorf("全量 goroutine 栈转储超过 %d 字节仍被截断（goroutine 规模异常），计数不可信", dbHandleStackMaxSize)
}

// countSQLPoolGoroutines 统计连接池驻留协程数；栈转储无法收口时返回错误，
// 由调用方按失败处理（不可信计数不得当成 0 通过）。
func countSQLPoolGoroutines() (openers, cleaners int, err error) {
	dump, err := goroutineStackDump()
	if err != nil {
		return 0, 0, err
	}
	// 全量栈转储按空行分块，一块一个 goroutine：帧名计数会把活跃 cleaner
	// 的嵌套帧（connectionCleaner→connectionCleanerRunLocked）重复计入。
	for _, block := range strings.Split(string(dump), "\n\n") {
		switch {
		case strings.Contains(block, "connectionOpener"):
			openers++
		case strings.Contains(block, "connectionCleaner"):
			cleaners++
		}
	}
	return openers, cleaners, nil
}

// waitSQLPoolGoroutinesSettle 轮询等待连接池协程退出（Close 是异步通知），
// 落入上限即返回；等满返回末次计数交由调用方断言。目的不是放宽判据：
// 永久泄漏的计数不会随时间下降。栈转储不可信时立即返回错误，不重试
// （规模异常不会因等待而消失）。
func waitSQLPoolGoroutinesSettle() (openers, cleaners int, err error) {
	deadline := time.Now().Add(dbHandleGoroutineSettleWait)
	for {
		openers, cleaners, err = countSQLPoolGoroutines()
		if err != nil {
			return 0, 0, err
		}
		if openers+cleaners <= dbHandleGoroutineCap || time.Now().After(deadline) {
			return openers, cleaners, nil
		}
		time.Sleep(20 * time.Millisecond)
	}
}
