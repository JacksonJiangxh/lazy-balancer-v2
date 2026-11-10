package services

// crs/ip2region 状态镜像只采纳「本进程真实在途」的运行：持久化活动态
// （进程崩溃残留/快照回放）不代表本进程在执行，采纳即让任务监控恒显
// 「运行中」并禁用运行按钮。终态（failed/skipped/success/idle）一律不
// running；在途阶段回归保持 running。

import (
	"testing"
	"time"

	"lazy-balancer-v2/internal/db"
	"lazy-balancer-v2/internal/taskengine"
)

func wireStatusMirror(t *testing.T, te *taskengine.Engine, id string) string {
	t.Helper()
	m, ok := te.Lookup(id)
	if !ok {
		t.Fatalf("%s 未注册", id)
	}
	return m.StatusMirror
}

// Given crs 版本行持久态（终态与活动态）而本进程无在途运行。
// When 引擎 Lookup 采纳 StatusFn 状态镜像。
// Then 一律不映射 running（活动态属于上次进程的生命周期）。
func TestWireCRSStatusFn_ignoresPersistedStatusWithoutInProcessRun(t *testing.T) {
	te := newWireTestEngine(t)
	ResetCRSUpdateManagerForTest()
	t.Cleanup(ResetCRSUpdateManagerForTest)
	crsUpdateManager = newTestCRSManager(t)
	if _, err := db.DB.Exec(`INSERT OR REPLACE INTO security_crs_version (id, version, auto_update) VALUES (1, 'v4.30.0', 1)`); err != nil {
		t.Fatal(err)
	}

	for _, status := range []string{"failed", "skipped", "success", "idle", "checking", "downloading", "installing", "reloading"} {
		if _, err := db.DB.Exec(`UPDATE security_crs_version SET update_status=? WHERE id=1`, status); err != nil {
			t.Fatal(err)
		}
		if got := wireStatusMirror(t, te, "crs"); got == "running" {
			t.Fatalf("crs 持久态 %q 在本进程无在途运行时不得映射 running", status)
		}
	}

	// 在途形状：本进程 manager 处于 running 且阶段为活动态 → 映射 running。
	crsUpdateManager.mu.Lock()
	crsUpdateManager.running = true
	crsUpdateManager.state = crsTaskState{status: CRSStatusDownloading, trigger: "auto", startedAt: time.Now().UTC()}
	crsUpdateManager.mu.Unlock()
	if got := wireStatusMirror(t, te, "crs"); got != "running" {
		t.Fatalf("本进程在途 downloading 应映射 running, got %q", got)
	}
}

// Given ip2region 版本行持久态（终态与活动态）而本进程无在途运行。
// When 引擎 Lookup 采纳 StatusFn 状态镜像。
// Then 一律不映射 running；本进程在途形状仍映射 running。
func TestWireIP2RegionStatusFn_ignoresPersistedStatusWithoutInProcessRun(t *testing.T) {
	te := newWireTestEngine(t)
	ResetIP2RegionUpdateManagerForTest()
	t.Cleanup(ResetIP2RegionUpdateManagerForTest)
	ip2RegionUpdateManager = newTestIP2RegionManager(t)
	if _, err := db.DB.Exec(`INSERT OR REPLACE INTO security_ip2region_version (id, version, auto_update) VALUES (1, 'v3.18.0', 1)`); err != nil {
		t.Fatal(err)
	}

	for _, status := range []string{"failed", "skipped", "success", "idle", "checking", "downloading", "installing", "reloading"} {
		if _, err := db.DB.Exec(`UPDATE security_ip2region_version SET update_status=? WHERE id=1`, status); err != nil {
			t.Fatal(err)
		}
		if got := wireStatusMirror(t, te, "ip2region"); got == "running" {
			t.Fatalf("ip2region 持久态 %q 在本进程无在途运行时不得映射 running", status)
		}
	}

	ip2RegionUpdateManager.mu.Lock()
	ip2RegionUpdateManager.running = true
	ip2RegionUpdateManager.mu.Unlock()
	if got := wireStatusMirror(t, te, "ip2region"); got != "running" {
		t.Fatalf("本进程在途 downloading 应映射 running, got %q", got)
	}
}
