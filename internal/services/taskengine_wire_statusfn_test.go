package services

// F-L1-68-02（第 68 轮，P2）：crs/ip2region 两 StatusFn 把 failed/skipped 持久
// 终态也映射 running（现逻辑：非 idle/success/空→running）——更新失败后面板
// 任务监控恒显「运行中」，终态失真。修复：仅 checking/downloading/installing/
// reloading 在途阶段映射 running，持久终态（failed/skipped/success/idle/空）
// 一律不 running。

import (
	"testing"

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

// Given crs 版本行持久终态（failed/skipped/success/idle）。
// When 引擎 Lookup 采纳 StatusFn 状态镜像。
// Then 终态不得映射 running（现实现映射 running——RED）；在途阶段回归保持 running。
func TestWireCRSStatusFn_terminalStatesNotRunning(t *testing.T) {
	te := newWireTestEngine(t)
	ResetCRSUpdateManagerForTest()
	InitCRSUpdateManager(nil)
	t.Cleanup(ResetCRSUpdateManagerForTest)

	for _, status := range []string{"failed", "skipped", "success", "idle"} {
		if _, err := db.DB.Exec(`UPDATE security_crs_version SET update_status=? WHERE id=1`, status); err != nil {
			t.Fatal(err)
		}
		if got := wireStatusMirror(t, te, "crs"); got == "running" {
			t.Fatalf("crs 持久终态 %q 不得映射 running（任务监控状态失真）", status)
		}
	}
	// 回归形状：在途阶段仍映射 running
	if _, err := db.DB.Exec(`UPDATE security_crs_version SET update_status='downloading' WHERE id=1`); err != nil {
		t.Fatal(err)
	}
	if got := wireStatusMirror(t, te, "crs"); got != "running" {
		t.Fatalf("crs 在途 downloading 应映射 running, got %q", got)
	}
}

// Given ip2region 版本行持久终态（failed/skipped/success/idle）。
// When 引擎 Lookup 采纳 StatusFn 状态镜像。
// Then 终态不得映射 running（现实现映射 running——RED）；在途阶段回归保持 running。
func TestWireIP2RegionStatusFn_terminalStatesNotRunning(t *testing.T) {
	te := newWireTestEngine(t)

	for _, status := range []string{"failed", "skipped", "success", "idle"} {
		if _, err := db.DB.Exec(`UPDATE security_ip2region_version SET update_status=? WHERE id=1`, status); err != nil {
			t.Fatal(err)
		}
		if got := wireStatusMirror(t, te, "ip2region"); got == "running" {
			t.Fatalf("ip2region 持久终态 %q 不得映射 running（任务监控状态失真）", status)
		}
	}
	if _, err := db.DB.Exec(`UPDATE security_ip2region_version SET update_status='downloading' WHERE id=1`); err != nil {
		t.Fatal(err)
	}
	if got := wireStatusMirror(t, te, "ip2region"); got != "running" {
		t.Fatalf("ip2region 在途 downloading 应映射 running, got %q", got)
	}
}
