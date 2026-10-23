package services

// 看门狗降级窗口收口钉测：BecomeSlave 的 SetRole(false) 会取消在途 Periodic
// Run 的 rc.Ctx——在途看门狗轮若不消费 ctx，会以旧主节点视角跑完并覆写
// 复位后的漂移态（复位→误报漂移的窗口）。

import (
	"context"
	"database/sql"
	"database/sql/driver"
	"errors"
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
