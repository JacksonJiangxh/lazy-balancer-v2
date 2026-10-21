package services

// 容量挤出的复杂度钉子：挤出序一次预计算（排序）后批量删，不再每挤出一个
// 就全表扫描并重新 time.Parse 全部条目。行为等价由「挤出优先级逐项对齐 +
// 最终名单集合/顺序」双重断言，复杂度由 time.Parse 调用计数上界断言。

import (
	"fmt"
	"testing"

	"lazy-balancer-v2/internal/models"
)

func TestAutobanMerge_evictionPrecomputedOrderAndParseBound(t *testing.T) {
	installAutobanFixture(t, "2026-10-14 10:00:00")
	oldCap := AutobanListEntryCap
	AutobanListEntryCap = 30
	t.Cleanup(func() { AutobanListEntryCap = oldCap })

	const (
		manualCount = 20
		expiring    = 60
		permanent   = 10
		newBanned   = 10
	)
	var seeded []models.IPListEntry
	var wantExpiringOrder []string
	var wantPermanentOrder []string
	for i := range manualCount {
		seeded = append(seeded, models.IPListEntry{
			Value: fmt.Sprintf("192.0.2.%d", i+1), Remark: "事件处置",
		})
	}
	// 到期时间倒序写入（最早到期排在名单末尾）：挤出序必须按到期升序，
	// 而非名单顺序。
	for i := range expiring {
		value := fmt.Sprintf("198.51.100.%d", i+1)
		expires := fmt.Sprintf("2026-10-14 11:%02d:00", expiring-1-i)
		seeded = append(seeded, models.IPListEntry{
			Value: value, Remark: AutobanEntryRemark, ExpiresAt: expires,
		})
		wantExpiringOrder = append([]string{value}, wantExpiringOrder...)
	}
	// 永久条目：created_at 升序者先挤（created_at 递减写入，期望顺序即反向）。
	for i := range permanent {
		value := fmt.Sprintf("203.0.113.%d", i+1)
		seeded = append(seeded, models.IPListEntry{
			Value: value, Remark: AutobanEntryRemark,
			CreatedAt: fmt.Sprintf("2026-10-10 00:00:%02d", permanent-i),
		})
		wantPermanentOrder = append([]string{value}, wantPermanentOrder...)
	}
	seedPresetEntries(t, seeded)

	candidates := make([]AutobanSuggestion, 0, newBanned)
	for i := range newBanned {
		candidates = append(candidates, AutobanSuggestion{IP: fmt.Sprintf("10.10.0.%d", i+1), Count: 100 - i})
	}

	baseParses := autobanEntryTimeParses.Load()
	out, err := autobanMergeEntries(AutobanConfig{
		Enabled: true, Threshold: 1, WindowMinutes: 5, Duration: "1h", Scope: "all", DryRun: false,
	}, candidates)
	if err != nil {
		t.Fatalf("merge: %v", err)
	}
	parses := autobanEntryTimeParses.Load() - baseParses

	// 行为等价①：挤出数与顺序 = 到期升序（60）→ 永久 created_at 升序（10）。
	if out.Evicted != expiring+permanent {
		t.Fatalf("evicted=%d, want %d", out.Evicted, expiring+permanent)
	}
	if out.DroppedNew != 0 {
		t.Fatalf("dropped_new=%d, want 0（自动条目足够挤出）", out.DroppedNew)
	}
	want := append(append([]string{}, wantExpiringOrder...), wantPermanentOrder...)
	if len(out.EvictedIPs) != len(want) {
		t.Fatalf("EvictedIPs 条数=%d, want %d", len(out.EvictedIPs), len(want))
	}
	for i := range want {
		if out.EvictedIPs[i] != want[i] {
			t.Fatalf("挤出序第 %d 项=%s, want %s（优先级与逐次挑选必须一致）", i, out.EvictedIPs[i], want[i])
		}
	}

	// 行为等价②：最终名单 = 全部手动条目 + 本轮新封，顺序保持原相对次序。
	final := presetEntries(t)
	if len(final) != AutobanListEntryCap {
		t.Fatalf("条目数=%d, want %d", len(final), AutobanListEntryCap)
	}
	for i := range manualCount {
		wantValue := fmt.Sprintf("192.0.2.%d", i+1)
		if final[i].Value != wantValue || final[i].Remark != "事件处置" {
			t.Fatalf("第 %d 条=%+v, want 手动条目 %s", i, final[i], wantValue)
		}
	}
	for i := range newBanned {
		wantValue := fmt.Sprintf("10.10.0.%d", i+1)
		got := final[manualCount+i]
		if got.Value != wantValue || got.Remark != AutobanEntryRemark {
			t.Fatalf("新封第 %d 条=%+v, want %s", i, got, wantValue)
		}
	}

	// 复杂度：时间解析次数与条目数线性相关（旧实现每挤出一个全表重解析，
	// 本例约 70 次挤出 × 平均 55 条 ≈ 4000 次）。
	upperBound := int64(3 * (len(seeded) + newBanned + 8))
	if parses > upperBound {
		t.Fatalf("time.Parse 次数=%d, 超过线性上界 %d（挤出仍为 O(n²) 逐次重解析）", parses, upperBound)
	}
}
