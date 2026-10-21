package services

//   - 历史修复：Run 体业务门 StopLoop 前复查 AutobanEnabled——「首读 false 后、
//     停环前」与 PUT enabled=1 + StartLoop 交错时不得误杀新调度（终态
//     loopOn=true）。
//   - 历史修复（Ruling=自停）：消费侧护栏校验失败即停调度——持续性无效配置每轮
//     空转（1440 failed 行/天）无边际价值，与业务门同构（留痕+StopLoop）；
//     恢复路径=PUT 保存有效配置（校验过即 StartLoop）/重启回填收敛。
//   - 历史修复：名单条数与渲染生效面同口径——已到期未清理条目
//     （expires_at 可解析且 <= now）不计入；畸形 expires_at 保留不误删。
//     （banned_today 已改为审计事件计数——2026-10-15 用户裁定，见
//     autoban_test.go TestAutobanBannedToday。）
//   - 历史修复：AutobanIsMaster 导出（/status is_master 数据源，与调度门同源）。

import (
	"testing"

	"lazy-balancer-v2/internal/db"
	"lazy-balancer-v2/internal/taskengine"
)

// installAutobanEngineFixture 引擎装配（镜像业务门钉测形态：log dir+空 rerun+引擎）。
func installAutobanEngineFixture(t *testing.T) *taskengine.Engine {
	t.Helper()
	installAutobanFixture(t, "2026-10-14 10:00:00")
	newTaskLogDir(t)
	SetConfigLoadRerun(func(operator string) error { return nil })
	t.Cleanup(func() { SetConfigLoadRerun(nil) })
	te := InitTaskEngine("", t.TempDir()+"/app.log")
	t.Cleanup(te.Stop)
	return te
}

// TestAutobanRunGate_recheckPreservesConcurrentlyEnabledLoop（历史修复）：Given 手动
// 触发的 Run 在未启用态进入业务门（首读 false），首读之后、停环之前 PUT
// enabled=1 + StartLoop 已并发发生（缝内注入，镜像 UpdateAutobanConfig 保存
// 联动启停两步）。When Run 体到停环判定点。Then 复查读 true → 不停环、本轮按
// 启用继续（返回 nil）——终态 loopOn=true，enabled=1 而调度停的不可自愈形态
// 不再出现。
func TestAutobanRunGate_recheckPreservesConcurrentlyEnabledLoop(t *testing.T) {
	te := installAutobanEngineFixture(t)
	setAutobanConfigRaw(t, false, 1, 5, "1h", "all", true)

	// 交错窗：首读 false 之后、复查之前的「PUT enabled=1 + StartLoop」。
	oldRecheck := autobanRecheckEnabled
	autobanRecheckEnabled = func() bool {
		if _, err := db.DB.Exec(`UPDATE global_config SET autoban_enabled=1 WHERE id=1`); err != nil {
			t.Fatalf("flip enabled: %v", err)
		}
		te.StartLoop(AutobanTaskID)
		return AutobanEnabled()
	}
	t.Cleanup(func() { autobanRecheckEnabled = oldRecheck })

	if err := RunAutobanCycle(taskengine.RunContext{Trigger: "manual"}); err != nil {
		t.Fatalf("复查转 true 必须按启用继续（不停止调度）: %v", err)
	}
	if m, _ := te.Lookup(AutobanTaskID); !m.LoopOn {
		t.Fatal("终态必须 loopOn=true：StopLoop 前复查发现已并发启用，不得误杀新调度")
	}
}

// TestAutobanRunGate_stopsLoopWhenStillDisabledAfterRecheck（回归形状）：首读与
// 复查均 false（真未启用）照旧停环——复查不得放松业务门。
func TestAutobanRunGate_stopsLoopWhenStillDisabledAfterRecheck(t *testing.T) {
	te := installAutobanEngineFixture(t)
	setAutobanConfigRaw(t, false, 1, 5, "1h", "all", true)
	te.StartLoop(AutobanTaskID)

	if err := RunAutobanCycle(taskengine.RunContext{Trigger: "manual"}); err == nil {
		t.Fatal("未启用（复查亦 false）必须拒绝执行")
	}
	if m, _ := te.Lookup(AutobanTaskID); m.LoopOn {
		t.Fatal("未启用仍必须重禁调度（复查不放松业务门）")
	}
}

// TestAutobanRunCycle_invalidConfigStopsLoop（历史修复，Ruling=自停）：Given 带外
// 污染（threshold=0）+调度开。When Run 体护栏校验失败。Then 拒绝执行之外必须
// 停调度（LoopOn=false）——持续性无效配置每轮空转（约 1440 failed 行/天）无
// 边际价值；留痕=错误返回+failed 行，恢复路径=保存有效配置（校验过即
// StartLoop）或重启（启动回填收敛后按启用对齐拉起）。
func TestAutobanRunCycle_invalidConfigStopsLoop(t *testing.T) {
	te := installAutobanEngineFixture(t)
	setAutobanConfigRaw(t, true, 0, 5, "1h", "all", false)
	te.StartLoop(AutobanTaskID)
	if m, _ := te.Lookup(AutobanTaskID); !m.LoopOn {
		t.Fatal("前置：调度应已开启")
	}

	err := RunAutobanCycle(taskengine.RunContext{Trigger: "auto"})
	if err == nil {
		t.Fatal("无效配置必须拒绝执行")
	}
	if m, _ := te.Lookup(AutobanTaskID); m.LoopOn {
		t.Fatal("护栏校验失败必须停调度（自停——持续空转无边际价值，AB-3 Ruling）")
	}
}

// TestAutobanRunCycle_validConfigKeepsLoopOn（回归形状）：护栏不得误伤正常轮，
// 合法配置照常执行且不停调度。
func TestAutobanRunCycle_validConfigKeepsLoopOn(t *testing.T) {
	te := installAutobanEngineFixture(t)
	setAutobanConfigRaw(t, true, 1, 5, "24h", "all", true)
	te.StartLoop(AutobanTaskID)

	if err := RunAutobanCycle(taskengine.RunContext{Trigger: "auto"}); err != nil {
		t.Fatalf("合法配置不得被护栏拦截: %v", err)
	}
	if m, _ := te.Lookup(AutobanTaskID); !m.LoopOn {
		t.Fatal("合法配置不得停调度")
	}
}

// TestAutobanStatusCounters_matchRenderActiveCaliber（历史修复）：Given 名单含
// 自动条目三条（一条生效、一条已到期未清理、一条畸形 expires_at）+ 手动条目。
// When 计算生效条目视图。Then 已到期未清理条目不计入（与渲染投影层
// loadIPListEntriesVia 同口径）；畸形 expires_at 保留不误删；AutobanListEntries
// 原始视图不变（条目管理数据源仍见全量）。（banned_today 已改审计事件计数，
// 不在本测——见 TestAutobanBannedToday。）
func TestAutobanStatusCounters_matchRenderActiveCaliber(t *testing.T) {
	installAutobanFixture(t, "2026-10-14 10:00:00")
	seedPresetEntriesForTest(t, `[
		{"value":"203.0.113.1","remark":"自动封禁","created_at":"2026-10-14 09:00:00","expires_at":"2026-10-15 09:00:00"},
		{"value":"203.0.113.2","remark":"自动封禁","created_at":"2026-10-14 09:30:00","expires_at":"2026-10-14 09:45:00"},
		{"value":"203.0.113.3","remark":"自动封禁","created_at":"2026-10-14 09:40:00","expires_at":"not-a-time"},
		{"value":"198.51.100.1","remark":"","created_at":"2026-10-14 08:00:00"}
	]`)

	entries, _, err := AutobanListEntries()
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 4 {
		t.Fatalf("原始条目视图不得被计数口径改动，entries=%d, want 4", len(entries))
	}
	active := AutobanActiveEntries(entries)
	if len(active) != 3 {
		t.Fatalf("active entries=%d, want 3（仅剔除已到期未清理一条）", len(active))
	}
	for _, e := range active {
		if e.Value == "203.0.113.2" {
			t.Fatal("已到期未清理条目不得出现在生效视图")
		}
	}
}

// TestAutobanIsMaster_exportsSchedulerRole（历史修复）：导出包装与调度门同源
// （引擎角色缝）——生产装配下默认 true，从端/缝覆写为 false。
func TestAutobanIsMaster_exportsSchedulerRole(t *testing.T) {
	installAutobanFixture(t, "2026-10-14 10:00:00")
	if !AutobanIsMaster() {
		t.Fatal("夹具默认主节点，AutobanIsMaster 应为 true")
	}
	old := autobanIsMaster
	autobanIsMaster = func() bool { return false }
	t.Cleanup(func() { autobanIsMaster = old })
	if AutobanIsMaster() {
		t.Fatal("缝覆写后应如实反映（同源）")
	}
}

// seedPresetEntriesForTest 直接覆写预置名单条目（本文件专用，避免与既有
// 助手命名冲突）。
func seedPresetEntriesForTest(t *testing.T, entriesJSON string) {
	t.Helper()
	if _, err := db.DB.Exec(`UPDATE security_ip_lists SET entries=? WHERE name=?`, entriesJSON, AutobanPresetListName); err != nil {
		t.Fatalf("seed preset entries: %v", err)
	}
}
