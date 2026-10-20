package main

// 历史修复 历史修复 / 历史修复 钉测试：
//   - P2-1：关停总预算超出 compose stop_grace_period（HTTP≤10s + drainCaddy≤2s
//     + engine.Stop 30s + StopACME 无界 <-done）。Go 侧单一预算 + 各段派生，
//     最坏路径必须 ≤ grace；StopACME 的 <-done 必须有界。
//   - P3-4：signal.Notify 注册晚于 BootSync——启动窗口内 SIGTERM 走默认动作
//     立即退出。注册前置后，窗口内到达的信号必须在监听前被识别并走正常关停。

import (
	"log"
	"os"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"

	"lazy-balancer-v2/internal/services"
	"lazy-balancer-v2/internal/taskengine"
)

// composeStopGracePeriod 与 docker-compose.yml 的 stop_grace_period 同值
// （main 包不读 compose 文件；此常量仅作测试口径，改 compose 须同步）。
const composeStopGracePeriod = 30 * time.Second

// Given 关停预算（fake clock）。
// When 按真实顺序消耗各段（HTTP → Caddy 排水 → 引擎排空 → ACME 收尾）。
// Then 各段钳制正确、总和 ≤ processShutdownBudget（且 < compose grace）。
func TestShutdownBudgetWorstCaseFitsComposeGrace(t *testing.T) {
	if processShutdownBudget >= composeStopGracePeriod {
		t.Fatalf("关停总预算 %s 必须小于 compose stop_grace_period %s", processShutdownBudget, composeStopGracePeriod)
	}
	now := time.Date(2026, 10, 20, 12, 0, 0, 0, time.UTC)
	b := &shutdownBudget{now: func() time.Time { return now }}

	httpSeg := b.segment(httpShutdownSegmentMax)
	now = now.Add(httpSeg)
	caddySeg := b.segment(caddyDrainSegmentMax)
	now = now.Add(caddySeg)
	engineSeg := b.engineDrain()
	now = now.Add(engineSeg)
	acmeSeg := b.segment(acmeStopSegmentMax)
	now = now.Add(acmeSeg)

	if httpSeg != httpShutdownSegmentMax {
		t.Fatalf("HTTP 段=%s, want %s（预算充足时必须用满段上限）", httpSeg, httpShutdownSegmentMax)
	}
	if caddySeg != caddyDrainSegmentMax {
		t.Fatalf("Caddy 排水段=%s, want %s", caddySeg, caddyDrainSegmentMax)
	}
	wantEngine := processShutdownBudget - httpShutdownSegmentMax - caddyDrainSegmentMax - acmeStopSegmentMax
	if engineSeg != wantEngine {
		t.Fatalf("引擎排空=剩余−ACME 预留=%s, got %s", wantEngine, engineSeg)
	}
	if acmeSeg != acmeStopSegmentMax {
		t.Fatalf("ACME 段=%s, want %s", acmeSeg, acmeStopSegmentMax)
	}
	total := httpSeg + caddySeg + engineSeg + acmeSeg
	if total > processShutdownBudget {
		t.Fatalf("最坏路径总和 %s 超出总预算 %s", total, processShutdownBudget)
	}
	if total >= composeStopGracePeriod {
		t.Fatalf("最坏路径总和 %s 不得达到 compose grace %s（须留退出余量）", total, composeStopGracePeriod)
	}

	// 预算耗尽：各段归零，引擎排空不得回落引擎默认 30s（0 会被引擎当作未指定）。
	if got := b.segment(caddyDrainSegmentMax); got != 0 {
		t.Fatalf("预算耗尽后段上限=%s, want 0", got)
	}
	if got := b.engineDrain(); got <= 0 || got > time.Millisecond {
		t.Fatalf("预算耗尽后引擎排空=%s, want 极小正值（1ms 语义）", got)
	}
}

// Given 引擎有一个不消费取消信号的在途 Run（生产形态：长跑清理任务）。
// When stopTaskEngineWithin 在预算剩余 < ACME 预留时调用。
// Then 立即放弃等待（不得回落 Stop 的 30s 默认），并清除全局引擎句柄。
func TestStopTaskEngineWithinBoundedByRemainingBudget(t *testing.T) {
	te := taskengine.NewEngine(taskengine.Options{TickInterval: time.Hour})
	services.SetTaskEngineForTest(te)
	release := make(chan struct{})
	started := make(chan struct{})
	t.Cleanup(func() {
		close(release)
		services.StopTaskEngine()
	})
	if err := te.Register(taskengine.Descriptor{
		ID: "t-shutdown-block", Family: "t", Name: "关停阻塞",
		Kind: taskengine.KindOneshot, RunsOn: taskengine.RoleAny,
		Run: func(rc taskengine.RunContext) error {
			close(started)
			<-release // 故意不消费 rc.Ctx（等价于不响应取消的清理任务）
			return nil
		},
	}); err != nil {
		t.Fatal(err)
	}
	if err := te.RunAsync("t-shutdown-block", "manual", ""); err != nil {
		t.Fatalf("RunAsync: %v", err)
	}
	select {
	case <-started:
	case <-time.After(2 * time.Second):
		t.Fatal("任务未启动")
	}

	b := &shutdownBudget{now: time.Now, deadline: time.Now().Add(30 * time.Millisecond)}
	begin := time.Now()
	stopTaskEngineWithin(b)
	if elapsed := time.Since(begin); elapsed > 2*time.Second {
		t.Fatalf("引擎排空未受关停预算约束：耗时 %s（预算仅 30ms）", elapsed)
	}
	if services.TaskEngine() != nil {
		t.Fatal("stopTaskEngineWithin 必须清除全局引擎句柄")
	}
}

// stuckCertificateWorker Start 永不返回，Stop 只发信号不阻塞。
type stuckCertificateWorker struct {
	entered chan struct{}
	release chan struct{}
}

func (w *stuckCertificateWorker) Start() {
	close(w.entered)
	<-w.release
}
func (w *stuckCertificateWorker) Stop() {}

// Given 证书 worker 停止后不退出（Start 阻塞）。
// When ShutdownWithTimeout 以 50ms 上限调用。
// Then 有界返回并记录 error 日志（不再无界 <-done）。
func TestRuntimeLifecycle_ShutdownWithTimeoutBoundsStuckWorker(t *testing.T) {
	worker := &stuckCertificateWorker{entered: make(chan struct{}), release: make(chan struct{})}
	lifecycle := newRuntimeLifecycle(idleSyncWorker{}, func() certificateWorker { return worker })
	lifecycle.StartACME()
	select {
	case <-worker.entered:
	case <-time.After(2 * time.Second):
		t.Fatal("证书 worker 未启动")
	}
	t.Cleanup(func() { close(worker.release) })

	oldOutput := log.Writer()
	var buf strings.Builder
	log.SetOutput(&buf)
	oldLevel := services.CurrentLogLevel()
	if err := services.ConfigureLogLevel("info"); err != nil {
		t.Fatalf("configure log level: %v", err)
	}
	t.Cleanup(func() {
		log.SetOutput(oldOutput)
		_ = services.ConfigureLogLevel(oldLevel)
	})

	begin := time.Now()
	lifecycle.ShutdownWithTimeout(50 * time.Millisecond)
	if elapsed := time.Since(begin); elapsed > 2*time.Second {
		t.Fatalf("ShutdownWithTimeout 无界等待 worker 退出：耗时 %s", elapsed)
	}
	if !strings.Contains(buf.String(), "证书服务停止等待超时") {
		t.Fatalf("超时路径缺少 error 日志: %q", buf.String())
	}
	// 幂等：再次 Shutdown 不重复报告（stopped 门）。
	before := buf.Len()
	lifecycle.ShutdownWithTimeout(50 * time.Millisecond)
	if buf.Len() != before {
		t.Fatal("第二次 Shutdown 不得重复记录超时日志")
	}
}

// Given 启动窗口内到达并缓存在 quit 通道的 SIGTERM。
// When 监听前检查 takePendingSignal。
// Then 识别为已收到信号（走正常关停而非默认终止）。
func TestTakePendingSignal(t *testing.T) {
	quit := make(chan os.Signal, 1)
	if takePendingSignal(quit) {
		t.Fatal("空通道不得报告已收到信号")
	}
	quit <- syscall.SIGTERM
	if !takePendingSignal(quit) {
		t.Fatal("启动窗口内缓存 SIGTERM 未被识别")
	}
	if takePendingSignal(quit) {
		t.Fatal("信号已被消费，不得重复报告")
	}
}

// Given 启动窗口内 SIGTERM 已入 quit 缓冲、监听尚未开始。
// When waitForServerStop 进入等待。
// Then 立即消费该信号并完成正常关停（不等待第二个信号、不阻塞）。
func TestWaitForServerStopConsumesSignalBufferedDuringStartup(t *testing.T) {
	server := newAdminHTTPServer("127.0.0.1:0", nil)
	quit := make(chan os.Signal, 1)
	quit <- syscall.SIGTERM
	restart, _ := newRestartSignal()
	serverErrors := make(chan error, 1)

	var wg sync.WaitGroup
	wg.Add(1)
	var err error
	go func() {
		defer wg.Done()
		err = waitForServerStop(server, serverStopSignals{
			quit: quit, restart: restart, serverErrors: serverErrors,
			caddyAdminURL: "", budget: newShutdownBudget(),
		})
	}()
	done := make(chan struct{})
	go func() { wg.Wait(); close(done) }()
	select {
	case <-done:
	case <-time.After(3 * time.Second):
		t.Fatal("启动窗口内缓存的 SIGTERM 未被消费为关停（仍卡在等待）")
	}
	if err != nil {
		t.Fatalf("waitForServerStop: %v", err)
	}
	if got := len(quit); got != 0 {
		t.Fatalf("信号通道未消费干净：残留 %d", got)
	}
}
