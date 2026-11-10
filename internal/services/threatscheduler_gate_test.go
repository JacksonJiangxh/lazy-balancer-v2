package services

import (
	"testing"
	"time"

	"lazy-balancer-v2/internal/db"
)

// 威胁库自动更新总开关（v2.3.2 用户裁定）：global_config.threat_auto_update
// 为任务级总闸（卡片父行开关）；逐源 update_enabled 决定任务更新哪些源
// （弹框内开关）。调度器：总闸关闭时整任务不启动（即使源全开且到期）。
//
// 断言必须落在引擎调度面（LoopOn + NextSlot），而非 setter/getter 往返：
// 只比 ThreatAutoUpdateEnabled() 的返回值时，删掉 wire 的 EnabledFn/NextSlotFn
// 总闸分支测试依然绿（总闸失效无人钉）。
func TestThreatScheduler_masterSwitchGatesTask(t *testing.T) {
	te := newWireTestEngine(t)
	// Given：带外把源槽清空（随后由总闸开启武装首槽）
	if _, err := db.DB.Exec(`UPDATE security_threat_sources SET next_update=NULL`); err != nil {
		t.Fatal(err)
	}

	// 总闸开 → 调度面启用且槽位非空
	if err := SetThreatAutoUpdate(true); err != nil {
		t.Fatalf("set master on: %v", err)
	}
	SyncBusinessTaskDrivers()
	m, ok := te.Lookup("threat")
	if !ok {
		t.Fatal("threat 任务未注册")
	}
	if !m.LoopOn {
		t.Fatal("总闸开启后 threat 必须 LoopOn=true")
	}
	if m.NextSlot == "" {
		t.Fatal("总闸开启后 NextSlot 不得为空（源槽已武装）")
	}

	// 总闸关闭 → 整任务不启动（EnabledFn 关 + NextSlotFn 零值，双门同关）
	if err := SetThreatAutoUpdate(false); err != nil {
		t.Fatalf("set master off: %v", err)
	}
	if ThreatAutoUpdateEnabled() {
		t.Fatal("总闸关闭后 threatAutoUpdateEnabled 须为 false")
	}
	SyncBusinessTaskDrivers()
	m, _ = te.Lookup("threat")
	if m.LoopOn {
		t.Fatal("总闸关闭后 threat 必须 LoopOn=false（EnabledFn 门失效）")
	}
	if m.NextSlot != "" {
		t.Fatalf("总闸关闭后 NextSlot=%q, want 空（NextSlotFn 门失效）", m.NextSlot)
	}

	// 重开 → 恢复调度与槽位
	if err := SetThreatAutoUpdate(true); err != nil {
		t.Fatal(err)
	}
	SyncBusinessTaskDrivers()
	m, _ = te.Lookup("threat")
	if !m.LoopOn || m.NextSlot == "" {
		t.Fatalf("总闸重开后必须恢复调度：LoopOn=%v NextSlot=%q", m.LoopOn, m.NextSlot)
	}
}

// 开启业务自动更新时必须为全部启用源补首槽——只补一个源会让其余源
// NextSlotFn 永不到期（静默不更新）。三源逐个解析为合法未来 UTC 槽。
func TestSetThreatAutoUpdate_armsAllEmptySlots(t *testing.T) {
	// Given：业务曾关闭，全部威胁源 next_update 为空
	newClusterTestService(t)
	if _, err := db.DB.Exec(`UPDATE security_threat_sources SET next_update=''`); err != nil {
		t.Fatal(err)
	}

	// When：开启业务自动更新
	if err := SetThreatAutoUpdate(true); err != nil {
		t.Fatal(err)
	}

	// Then：每个启用源都必须有合法且位于未来的 UTC 排程槽
	now := time.Now().UTC()
	for _, name := range []string{"ustc", "firehol_l1", "et_compromised"} {
		var next string
		if err := db.DB.QueryRow(`SELECT COALESCE(next_update,'') FROM security_threat_sources WHERE name=? AND update_enabled=1`, name).Scan(&next); err != nil {
			t.Fatalf("读取源 %s 排程槽: %v", name, err)
		}
		if next == "" {
			t.Fatalf("威胁源 %s 开启后仍未补首槽", name)
		}
		slot := parseUTCSlot(next)
		if slot.IsZero() {
			t.Fatalf("威胁源 %s 排程槽 %q 不是合法 UTC 时间", name, next)
		}
		if !slot.After(now.Add(-time.Minute)) {
			t.Fatalf("威胁源 %s 排程槽 %q 不在未来（now=%s）", name, next, now.Format(time.RFC3339))
		}
	}
}
