package services

// 看门狗降级窗口收口钉测：BecomeSlave 的 SetRole(false) 会取消在途 Periodic
// Run 的 rc.Ctx——在途看门狗轮若不消费 ctx，会以旧主节点视角跑完并覆写
// 复位后的漂移态（复位→误报漂移的窗口）。

import (
	"context"
	"database/sql"
	"database/sql/driver"
	"errors"
	"log"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
	"time"

	"lazy-balancer-v2/internal/db"
	"lazy-balancer-v2/internal/taskengine"
)

// Given 主节点 + 已复位的漂移态 + 已取消的轮 ctx（降级/停机窗口形态）。
// When WatchdogCheckOnce 以取消 ctx 运行。
// Then 整轮中止（返回取消错误），漂移簿记/状态零改写（不覆写复位态）。
func TestWatchdogCheckOnce_cancelledCtxAbortsWithoutTouchingDriftState(t *testing.T) {
	_, database := newClusterTestService(t)
	seedGenerationRule(t, database, "lb_watchdog_inflight_demote", false)
	resetConfigWatchdogForTest(t)
	newTaskLogDir(t)
	server := fakeCaddyWithRoutes(t, emptyCaddyConfig)
	watchdogAdminURLValue = server.URL
	t.Cleanup(func() { watchdogAdminURLValue = "" })

	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	if err := WatchdogCheckOnce(ctx); err == nil {
		t.Fatal("取消 ctx 的看门狗轮必须中止并返回错误（不得在降级窗口跑完）")
	}
	if drift := CurrentConfigDrift(); !drift.Consistent || len(drift.Missing) != 0 || len(drift.Extra) != 0 {
		t.Fatalf("取消轮覆写复位态: %+v", drift)
	}
	configDriftMu.Lock()
	clean, skipped := configDriftCleanRounds, configDriftSkipped
	configDriftMu.Unlock()
	if clean != 0 || skipped != 0 {
		t.Fatalf("取消轮不得累积簿记: clean=%d skipped=%d", clean, skipped)
	}
}

// 中段取消（检查已开始、簿记未落）：在途轮照样不得落写——用可阻塞的
// admin 把取消精确落进比对窗口，钉住比对出口的第二复核点。前置 streak=1
// 使断言具备证伪力：取消轮若把 checkConfigConsistency 内部的第二轮防抖转移
// 留在进程里，状态会被确认为漂移（而该轮从未完成判定）。
func TestWatchdogCheckOnce_cancelAfterCheckSkipsBookkeeping(t *testing.T) {
	_, database := newClusterTestService(t)
	seedGenerationRule(t, database, "lb_watchdog_midround_cancel", false)
	resetConfigWatchdogForTest(t)
	newTaskLogDir(t)
	// 上一轮真实检查已观测一轮不一致（防抖窗口 streak=1），尚未确认漂移。
	configDriftMu.Lock()
	configDriftStreak = 1
	configDriftStatus.CheckedAt = time.Now().UTC().Format("2006-01-02 15:04:05")
	configDriftMu.Unlock()
	logs := captureStandardLog(t)
	started := make(chan struct{}, 1)
	release := make(chan struct{})
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		select {
		case started <- struct{}{}:
		default:
		}
		<-release
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(emptyCaddyConfig))
	}))
	defer server.Close()
	watchdogAdminURLValue = server.URL
	t.Cleanup(func() { watchdogAdminURLValue = "" })

	ctx, cancel := context.WithCancel(context.Background())
	errCh := make(chan error, 1)
	go func() { errCh <- WatchdogCheckOnce(ctx) }()
	select {
	case <-started:
	case <-time.After(5 * time.Second):
		cancel()
		close(release)
		t.Fatal("看门狗未抵达比对窗口（假 admin 未被请求）")
	}
	cancel()
	close(release)
	var err error
	select {
	case err = <-errCh:
	case <-time.After(5 * time.Second):
		t.Fatal("取消后的看门狗轮未返回")
	}

	if !errors.Is(err, context.Canceled) {
		t.Fatalf("中段取消轮必须返回取消错误: %v", err)
	}
	if drift := CurrentConfigDrift(); !drift.Consistent || len(drift.Missing) != 0 || len(drift.Extra) != 0 {
		t.Fatalf("中段取消轮不得确认漂移: %+v", drift)
	}
	configDriftMu.RLock()
	clean, skipped, heartbeatSkipped, streak := configDriftCleanRounds, configDriftSkipped, configDriftHeartbeatSkipped, configDriftStreak
	configDriftMu.RUnlock()
	if clean != 0 || skipped != 0 || heartbeatSkipped != 0 {
		t.Fatalf("中段取消轮不得累积簿记: clean=%d skipped=%d heartbeatSkipped=%d", clean, skipped, heartbeatSkipped)
	}
	// 取消轮必须把检查内部的 streak 转移回滚（1 → 2 会把防抖门推过，
	// 等于用一轮从未完成的判定确认了漂移）。
	if streak != 1 {
		t.Fatalf("中段取消轮必须回滚 streak：得到 %d，want 1", streak)
	}
	if data, readErr := os.ReadFile(taskengine.TaskLogPath("config-watchdog")); readErr == nil && len(data) != 0 {
		t.Fatalf("中段取消轮不得写任务日志: %q", string(data))
	}
	if data, readErr := os.ReadFile(taskengine.TaskLogPath("config-watchdog")); readErr == nil && strings.Contains(string(data), "配置漂移") {
		t.Fatalf("中段取消轮不得输出漂移结论: %q", string(data))
	}
	// 对账留痕必须与状态同一判定点产出：审计 append-only，回滚撤不回已落库的行，
	// 取消轮只能靠「不写」保证「审计怎么说、状态就怎样」。
	if audits := countConfigDriftAudits(t, "配置漂移"); audits != 0 {
		t.Fatalf("中段取消轮不得落「配置漂移」审计：得到 %d 条", audits)
	}
	if strings.Contains(logs.String(), "运行配置与规则数据不一致") {
		t.Fatalf("中段取消轮不得输出漂移运行日志: %q", logs.String())
	}
}

// countConfigDriftAudits 统计看门狗对账审计行数（取消轮必须为 0）。
func countConfigDriftAudits(t *testing.T, action string) int {
	t.Helper()
	var n int
	if err := db.AuditDB.QueryRow(`SELECT COUNT(*) FROM audit_log WHERE action = ? AND resource = 'Caddy配置'`, action).Scan(&n); err != nil {
		t.Fatalf("count %s audits: %v", action, err)
	}
	return n
}

// captureStandardLog 把标准 logger 输出改接到缓冲并返回缓冲（副作用：输出被接管）。
func captureStandardLog(t *testing.T) *syncLogBuffer {
	t.Helper()
	logs := &syncLogBuffer{}
	oldWriter := log.Writer()
	log.SetOutput(logs)
	t.Cleanup(func() { log.SetOutput(oldWriter) })
	return logs
}

// recoveredCaddyConfigForCancel 恢复形态夹具：运行配置含该规则的路由 @id，
// 与库内「启用规则 + 启用上游」形成一致比对结果。
const recoveredCaddyConfigForCancel = `{"apps":{"http":{"servers":{"http_8080":{"listen":[":8080"],"routes":[{"@id":"lb_watchdog_recover_cancel","handle":[{"handler":"reverse_proxy"}]}]}}}}}`

// 恢复方向：降级前已确认漂移，本轮比对一致——取消必须让「配置恢复」留痕
// 随内存状态一起作废（否则横幅继续亮、审计已称恢复）。
func TestWatchdogCheckOnce_cancelAfterRecoveryKeepsDriftAuditFree(t *testing.T) {
	_, database := newClusterTestService(t)
	seedGenerationRule(t, database, "lb_watchdog_recover_cancel", false)
	resetConfigWatchdogForTest(t)
	newTaskLogDir(t)
	// 前置：已确认漂移（streak=2、横幅亮）。
	configDriftMu.Lock()
	configDriftStatus = ConfigDriftStatus{
		Consistent: false,
		Missing:    []string{"lb_watchdog_recover_cancel（lb_watchdog_recover_cancel）"},
		Since:      "2026-10-01 00:00:00",
	}
	configDriftStreak = 2
	configDriftMu.Unlock()
	logs := captureStandardLog(t)
	// 非空洞性对照：同一场景在活 ctx 下必须真的落「配置恢复」留痕，
	// 否则下面的零断言对任何实现都成立。
	live := fakeCaddyWithRoutes(t, recoveredCaddyConfigForCancel)
	watchdogAdminURLValue = live.URL
	if err := WatchdogCheckOnce(context.Background()); err != nil {
		t.Fatalf("活 ctx 恢复轮应正常完成: %v", err)
	}
	if audits := countConfigDriftAudits(t, "配置恢复"); audits != 1 {
		t.Fatalf("前置：活 ctx 恢复轮必须落 1 条「配置恢复」审计：得到 %d 条", audits)
	}
	// 复位到「已确认漂移」形态，进入取消轮。
	configDriftMu.Lock()
	configDriftStatus = ConfigDriftStatus{
		Consistent: false,
		Missing:    []string{"lb_watchdog_recover_cancel（lb_watchdog_recover_cancel）"},
		Since:      "2026-10-01 00:00:00",
	}
	configDriftStreak = 2
	configDriftMu.Unlock()
	started := make(chan struct{}, 1)
	release := make(chan struct{})
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		select {
		case started <- struct{}{}:
		default:
		}
		<-release
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(recoveredCaddyConfigForCancel))
	}))
	defer server.Close()
	watchdogAdminURLValue = server.URL
	t.Cleanup(func() { watchdogAdminURLValue = "" })

	ctx, cancel := context.WithCancel(context.Background())
	errCh := make(chan error, 1)
	go func() { errCh <- WatchdogCheckOnce(ctx) }()
	select {
	case <-started:
	case <-time.After(5 * time.Second):
		cancel()
		close(release)
		t.Fatal("看门狗未抵达比对窗口（假 admin 未被请求）")
	}
	cancel()
	close(release)
	select {
	case err := <-errCh:
		if !errors.Is(err, context.Canceled) {
			t.Fatalf("中段取消轮必须返回取消错误: %v", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("取消后的看门狗轮未返回")
	}

	if drift := CurrentConfigDrift(); drift.Consistent || len(drift.Missing) != 1 {
		t.Fatalf("取消轮必须回滚到漂移快照: %+v", drift)
	}
	if audits := countConfigDriftAudits(t, "配置恢复"); audits != 1 {
		t.Fatalf("取消轮不得新增「配置恢复」审计（仅前置活 ctx 轮那 1 条）：得到 %d 条", audits)
	}
	if got := strings.Count(logs.String(), "运行配置与规则数据已恢复一致"); got != 1 {
		t.Fatalf("取消轮不得新增恢复运行日志（仅前置活 ctx 轮那 1 条）：得到 %d 条，%q", got, logs.String())
	}
}

// 回归形状：活 ctx 的主节点轮照常检查（空运行配置两轮置漂移态）。
func TestWatchdogCheckOnce_liveCtxChecksNormally(t *testing.T) {
	_, database := newClusterTestService(t)
	seedGenerationRule(t, database, "lb_watchdog_live_ctx", false)
	resetConfigWatchdogForTest(t)
	newTaskLogDir(t)
	server := fakeCaddyWithRoutes(t, emptyCaddyConfig)
	watchdogAdminURLValue = server.URL
	t.Cleanup(func() { watchdogAdminURLValue = "" })

	_ = WatchdogCheckOnce(context.Background())
	_ = WatchdogCheckOnce(context.Background())
	if drift := CurrentConfigDrift(); drift.Consistent {
		t.Fatal("活 ctx 主节点轮应照常检查（两轮不一致置漂移态）")
	}
	if data, err := os.ReadFile(taskengine.TaskLogPath("config-watchdog")); err != nil {
		t.Fatalf("read task log: %v", err)
	} else if !strings.Contains(string(data), "配置漂移") {
		t.Fatalf("确认漂移轮必须输出漂移结论行: %q", string(data))
	}
	// 活 ctx 的确认轮照常落账（留痕延后不得变成留痕丢失）。
	if audits := countConfigDriftAudits(t, "配置漂移"); audits != 1 {
		t.Fatalf("确认漂移轮必须落 1 条「配置漂移」审计：得到 %d 条", audits)
	}
}

// 角色读取（RoleOf）查询窗口内的取消不是「角色读取失败」：降级/停机取消
// 不得计入跳过轮、不得写任务日志、不得把角色状态机翻到 failed——与同文件
// 「降级窗口零簿记」承诺一致。
func TestWatchdogCheckOnce_roleReadCancelSkipsBookkeeping(t *testing.T) {
	_, _ = newClusterTestService(t)
	resetConfigWatchdogForTest(t)
	newTaskLogDir(t)
	previous := db.DB
	started := make(chan struct{}, 1)
	fake := sql.OpenDB(roleCancelConnector{started: started})
	db.DB = fake
	t.Cleanup(func() {
		_ = fake.Close()
		db.DB = previous
	})

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	errCh := make(chan error, 1)
	go func() { errCh <- WatchdogCheckOnce(ctx) }()
	select {
	case <-started:
	case <-time.After(5 * time.Second):
		t.Fatal("看门狗未抵达角色读取查询（假驱动未被调用）")
	}
	cancel()
	var err error
	select {
	case err = <-errCh:
	case <-time.After(5 * time.Second):
		t.Fatal("角色读取取消后看门狗轮未返回")
	}
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("取消轮必须返回取消错误: %v", err)
	}
	configDriftMu.RLock()
	skipped, heartbeatSkipped := configDriftSkipped, configDriftHeartbeatSkipped
	configDriftMu.RUnlock()
	if skipped != 0 || heartbeatSkipped != 0 {
		t.Fatalf("角色读取取消不得计入跳过轮: skipped=%d heartbeatSkipped=%d", skipped, heartbeatSkipped)
	}
	if data, readErr := os.ReadFile(taskengine.TaskLogPath("config-watchdog")); readErr == nil && len(data) != 0 {
		t.Fatalf("角色读取取消不得写任务日志: %q", string(data))
	}
}

// Given 已观测一轮不一致（streak=1）的主节点，随后角色读取失败一轮。
// When 该轮按「未判定」结束。
// Then 连续窗口必须被打断（streak=0）——否则「漂移→跳过→漂移」会被当作
// 两轮连续证据而误确认漂移；跳过计数照常累加。
func TestWatchdogCheckOnce_roleReadFailureBreaksStreak(t *testing.T) {
	_, _ = newClusterTestService(t)
	resetConfigWatchdogForTest(t)
	newTaskLogDir(t)
	configDriftMu.Lock()
	configDriftStreak = 1
	configDriftMu.Unlock()
	swapBrokenDB(t)

	if err := WatchdogCheckOnce(context.Background()); err == nil {
		t.Fatal("角色读取失败轮必须返回错误（任务面留痕）")
	}
	configDriftMu.RLock()
	streak, skipped := configDriftStreak, configDriftSkipped
	configDriftMu.RUnlock()
	if streak != 0 {
		t.Fatalf("角色读取失败轮必须打断连续窗口: streak=%d, want 0", streak)
	}
	if skipped != 1 {
		t.Fatalf("角色读取失败轮必须计入跳过簿记: skipped=%d, want 1", skipped)
	}
}

// Given 降级前已确认漂移的主节点 + 在途比较轮（快照已携带漂移态）。
// When 降级复位（ResetConfigDrift）先于取消在途轮发生。
// Then 取消轮不得把旧漂移快照写回（代际变化 → 放弃回滚），从节点保持复位态。
func TestWatchdogCheckOnce_resetDuringCancelledRoundKeepsResetState(t *testing.T) {
	_, database := newClusterTestService(t)
	seedGenerationRule(t, database, "lb_watchdog_reset_cancel", false)
	resetConfigWatchdogForTest(t)
	newTaskLogDir(t)
	configDriftMu.Lock()
	configDriftStatus = ConfigDriftStatus{
		Consistent: false,
		Missing:    []string{"lb_stale"},
		Since:      time.Now().UTC().Format("2006-01-02 15:04:05"),
	}
	configDriftStreak = 1
	configDriftMu.Unlock()
	started := make(chan struct{}, 1)
	release := make(chan struct{})
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		select {
		case started <- struct{}{}:
		default:
		}
		<-release
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(emptyCaddyConfig))
	}))
	defer server.Close()
	watchdogAdminURLValue = server.URL
	t.Cleanup(func() { watchdogAdminURLValue = "" })

	ctx, cancel := context.WithCancel(context.Background())
	errCh := make(chan error, 1)
	go func() { errCh <- WatchdogCheckOnce(ctx) }()
	select {
	case <-started:
	case <-time.After(5 * time.Second):
		cancel()
		close(release)
		t.Fatal("看门狗未抵达比对窗口（假 admin 未被请求）")
	}
	ResetConfigDrift()
	cancel()
	close(release)
	select {
	case err := <-errCh:
		if !errors.Is(err, context.Canceled) {
			t.Fatalf("取消轮必须返回取消错误: %v", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("取消后的看门狗轮未返回")
	}
	if drift := CurrentConfigDrift(); !drift.Consistent || len(drift.Missing) != 0 || len(drift.Extra) != 0 {
		t.Fatalf("取消轮覆写了降级复位态: %+v", drift)
	}
	configDriftMu.RLock()
	streak := configDriftStreak
	configDriftMu.RUnlock()
	if streak != 0 {
		t.Fatalf("取消轮回滚不得恢复复位前的 streak: %d", streak)
	}
}

// roleCancelConnector 假驱动：查询阻塞到 ctx 取消后返回 ctx.Err()——把取消
// 精确落进 RoleOf 的查询窗口。
type roleCancelConnector struct {
	started chan struct{}
}

func (c roleCancelConnector) Connect(context.Context) (driver.Conn, error) {
	return &roleCancelConn{started: c.started}, nil
}

func (c roleCancelConnector) Driver() driver.Driver { return roleCancelDriver{started: c.started} }

type roleCancelDriver struct {
	started chan struct{}
}

func (d roleCancelDriver) Open(string) (driver.Conn, error) {
	return &roleCancelConn{started: d.started}, nil
}

type roleCancelConn struct {
	started chan struct{}
}

func (c *roleCancelConn) Prepare(string) (driver.Stmt, error) {
	return nil, errors.New("prepare unsupported")
}

func (c *roleCancelConn) Close() error { return nil }

func (c *roleCancelConn) Begin() (driver.Tx, error) {
	return nil, errors.New("transactions unsupported")
}

func (c *roleCancelConn) QueryContext(ctx context.Context, _ string, _ []driver.NamedValue) (driver.Rows, error) {
	if c.started != nil {
		select {
		case c.started <- struct{}{}:
		default:
		}
	}
	<-ctx.Done()
	return nil, ctx.Err()
}
