package services

// F-L2-68-01（第 68 轮，P4）：demote 在途 Scheduled 中止——三库 Run 体的
// runCtx 曾是独立 context.Background（crsupdate/ip2regionupdate/threatupdate），
// 引擎 SetRole 对 Scheduled 在途的取消（rc.Ctx）传不进去，demote 后任务跑完、
// 从节点写版本行/名单/规则树，打破只读不变量。修复：runCtx 派生自 rc.Ctx
// （nil 回退 Background——测试/内部路径不变）；中止点复核角色——非主节点落
// skipped（与三库起点角色复查同语义），主节点保持手动取消 cancelled 口径。

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
	"time"

	"lazy-balancer-v2/internal/db"
	"lazy-balancer-v2/internal/taskengine"
)

// Given CRS 更新在途（fetchLatestTag 阻塞于 runCtx）。
// When 运行中 demote（is_master=0）+ 引擎侧 rc.Ctx 取消（SetRole 中止语义）。
// Then 任务立即中止且落 skipped（旧形态：runCtx 独立 Background，取消传不入，
// 跑完才退出——RED 超时）。
func TestCRSUpdateRun_demoteMidFlightAbortsAsSkipped(t *testing.T) {
	m := newTestCRSManager(t)
	seedCRSVersionRow(t, "v4.14.0", true)

	entered := make(chan struct{})
	release := make(chan struct{})
	t.Cleanup(func() { close(release) })
	var once sync.Once
	m.fetchLatestTag = func(ctx context.Context) (string, error) {
		once.Do(func() { close(entered) })
		select {
		case <-ctx.Done():
			return "", ctx.Err()
		case <-release:
			return "", errors.New("released without cancel")
		}
	}

	ctx, cancel := context.WithCancel(context.Background())
	done, err := m.StartUpdate("auto", &taskengine.RunContext{Ctx: ctx, Trigger: "auto"})
	if err != nil {
		t.Fatal(err)
	}
	<-entered
	if _, err := db.DB.Exec("UPDATE global_config SET is_master=0 WHERE id=1"); err != nil {
		t.Fatal(err)
	}
	cancel()

	select {
	case <-done:
	case <-time.After(3 * time.Second):
		t.Fatal("demote 后在途 CRS 更新未被中止（runCtx 未随 rc.Ctx 取消）")
	}
	if snap := m.StatusSnapshot(); snap.Status != string(CRSStatusSkipped) {
		t.Fatalf("status=%q, want skipped（demote 中止与起点角色复查同语义）", snap.Status)
	}
}

// Given IP2Region 更新在途（fetchLatestTag 阻塞于 runCtx）。
// When 运行中 demote + rc.Ctx 取消。
// Then 立即中止且落 skipped（镜像 CRS 口径）。
func TestIP2RegionUpdateRun_demoteMidFlightAbortsAsSkipped(t *testing.T) {
	m := newTestIP2RegionManager(t)

	entered := make(chan struct{})
	release := make(chan struct{})
	t.Cleanup(func() { close(release) })
	var once sync.Once
	m.fetchLatestTag = func(ctx context.Context) (string, error) {
		once.Do(func() { close(entered) })
		select {
		case <-ctx.Done():
			return "", ctx.Err()
		case <-release:
			return "", errors.New("released without cancel")
		}
	}

	ctx, cancel := context.WithCancel(context.Background())
	done, err := m.StartUpdate("auto", &taskengine.RunContext{Ctx: ctx, Trigger: "auto"})
	if err != nil {
		t.Fatal(err)
	}
	<-entered
	if _, err := db.DB.Exec("UPDATE global_config SET is_master=0 WHERE id=1"); err != nil {
		t.Fatal(err)
	}
	cancel()

	select {
	case <-done:
	case <-time.After(3 * time.Second):
		t.Fatal("demote 后在途 IP2Region 更新未被中止（runCtx 未随 rc.Ctx 取消）")
	}
	if snap := m.StatusSnapshot(); snap.Status != string(IP2RegionStatusSkipped) {
		t.Fatalf("status=%q, want skipped（demote 中止与起点角色复查同语义）", snap.Status)
	}
}

// Given 威胁库更新在途（源下载阻塞于请求 ctx——经 runCtx 派生）。
// When 运行中 demote + rc.Ctx 取消。
// Then 立即中止且 outcome=skipped（非 cancelled——非用户取消；非 failed——非源失败语义）。
func TestThreatRunUpdate_demoteMidFlightAbortsAsSkipped(t *testing.T) {
	overrideWafDirForTest(t)
	newClusterTestService(t)
	setupThreatTest(t, nil, nil, nil)

	entered := make(chan struct{})
	release := make(chan struct{})
	t.Cleanup(func() { close(release) })
	var once sync.Once
	blocking := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		once.Do(func() { close(entered) })
		select {
		case <-r.Context().Done():
		case <-release:
		}
	}))
	t.Cleanup(blocking.Close)
	if _, err := db.DB.Exec(`UPDATE security_threat_sources SET url=? WHERE name='ustc'`, blocking.URL); err != nil {
		t.Fatal(err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	runErr := make(chan error, 1)
	go func() {
		runErr <- GetThreatUpdateManager().RunUpdate("manual", &taskengine.RunContext{Ctx: ctx, Trigger: "manual"})
	}()
	<-entered
	if _, err := db.DB.Exec("UPDATE global_config SET is_master=0 WHERE id=1"); err != nil {
		t.Fatal(err)
	}
	cancel()

	select {
	case err := <-runErr:
		if err != nil {
			t.Fatalf("demote 中止属跳过语义，RunUpdate err=%v, want nil", err)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("demote 后在途威胁库更新未被中止（runCtx 未随 rc.Ctx 取消）")
	}
	if got := GetThreatUpdateManager().StatusSnapshot().Outcome; got != "skipped" {
		t.Fatalf("outcome=%q, want skipped（demote 中止与起点角色复查同语义）", got)
	}
}

// 边界形状：demote 发生在末源在途（循环自然结束、不再经过顶部取消检查）——
// 中止点归一补判仍须落 skipped（不得因末源下载被中止而记 failed）。
func TestThreatRunUpdate_demoteOnLastSourceAbortsAsSkipped(t *testing.T) {
	overrideWafDirForTest(t)
	newClusterTestService(t)
	setupThreatTest(t, nil, nil, nil)

	var entriesMu sync.Mutex
	entries := 0
	enteredLast := make(chan struct{})
	release := make(chan struct{})
	t.Cleanup(func() { close(release) })
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		entriesMu.Lock()
		entries++
		last := entries == 3 // 三源按 id 序——第 3 个=末源
		entriesMu.Unlock()
		if !last {
			_, _ = w.Write([]byte("203.0.113.1\n10.9.0.0/24\n"))
			return
		}
		close(enteredLast)
		select {
		case <-r.Context().Done():
		case <-release:
		}
	}))
	t.Cleanup(server.Close)
	for _, name := range []string{"ustc", "firehol_l1", "et_compromised"} {
		if _, err := db.DB.Exec(`UPDATE security_threat_sources SET url=? WHERE name=?`, server.URL, name); err != nil {
			t.Fatal(err)
		}
	}

	ctx, cancel := context.WithCancel(context.Background())
	runErr := make(chan error, 1)
	go func() {
		runErr <- GetThreatUpdateManager().RunUpdate("manual", &taskengine.RunContext{Ctx: ctx, Trigger: "manual"})
	}()
	<-enteredLast
	if _, err := db.DB.Exec("UPDATE global_config SET is_master=0 WHERE id=1"); err != nil {
		t.Fatal(err)
	}
	cancel()

	select {
	case err := <-runErr:
		if err != nil {
			t.Fatalf("demote 中止属跳过语义，RunUpdate err=%v, want nil", err)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("demote 后末源在途更新未被中止")
	}
	if got := GetThreatUpdateManager().StatusSnapshot().Outcome; got != "skipped" {
		t.Fatalf("末源在途 demote outcome=%q, want skipped（中止点归一补判）", got)
	}
}
