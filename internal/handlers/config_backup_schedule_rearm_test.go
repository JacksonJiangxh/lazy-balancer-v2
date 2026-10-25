package handlers

import (
	"net/http"
	"testing"
	"time"

	"lazy-balancer-v2/internal/db"
	"lazy-balancer-v2/internal/services"
)

// 导入/还原提交后必须按**本机**时区重算已武装排程族的未来槽。
// 场景（分区/跨机备份）：A 机 UTC 导出的安全防护分类携带按 UTC 算出的
// next_update，B 机（Asia/Shanghai）只导入该分类时本机时区不变——
// 「下次更新」显示 04:00 而槽实际落在本地 12:00，首轮错时执行。
// 保存时区路径已接 RearmScheduleSlotsAfterTimezoneChange（caddy.go
// UpdateConfig），导入路径此前漏接，故本钉测以「导入后槽 == 本机排程槽」
// 为唯一收敛判据；注释掉提交后重排即变红。
//
// 纯 JSON 备份不携带 CRS/xdb 文件（版本表被剔除），可随纯 JSON 进入的
// 排程行是 security_crawler_sources（任务级排程 + 逐源 next_update）。
func TestImportConfigBackup_rearmsImportedFutureSlotsToLocalSchedule(t *testing.T) {
	h := newBackupTestHandlers(t)
	seedLiveAdminShared(t)
	// 本机时区（security 分类不携带 global_config，导入后必须仍是它）。
	if _, err := db.DB.Exec(`UPDATE global_config SET timezone='Asia/Shanghai' WHERE id=1`); err != nil {
		t.Fatalf("seed timezone: %v", err)
	}
	// 任务级排程取治理默认 04:00 全周（DDL 默认值），显式固化避免依赖 schema。
	if _, err := db.DB.Exec(`UPDATE global_config SET crawler_schedule_days='1,2,3,4,5,6,7', crawler_schedule_time='04:00' WHERE id=1`); err != nil {
		t.Fatalf("seed crawler schedule: %v", err)
	}
	now := time.Now()
	correct := services.NextScheduledSlot(now, []int{1, 2, 3, 4, 5, 6, 7}, "04:00", services.CurrentLocation())
	if correct.IsZero() {
		t.Fatal("测试前提：排程槽不可为零值")
	}
	// 源机（UTC）算出的未来槽形态 = 本机 04:00 槽再 +8h（修复后按本机重算
	// 必然与之不同，且仍是未来槽，重排门不会因过期而跳过）。
	stale := correct.UTC().Add(8 * time.Hour).Format(flatUTCTimeLayout)
	if !correct.UTC().Add(8 * time.Hour).After(now.UTC()) {
		t.Fatalf("测试前提：导入槽必须是未来槽，got %s", stale)
	}

	payload := backupJSONFixture(t, map[string][]map[string]any{
		"security_crawler_sources": {
			{
				"name": "googlebot", "display_name": "Googlebot", "entry_count": 1,
				"version": "2026.10.01", "update_status": "idle", "update_enabled": 1,
				"next_update": stale,
			},
		},
	}, nil, []string{"security"})
	rec := postImportBytes(t, h, payload)
	if rec.Code != http.StatusOK {
		t.Fatalf("import status=%d body=%s", rec.Code, rec.Body.String())
	}
	var timezone string
	if err := db.DB.QueryRow(`SELECT COALESCE(timezone,'') FROM global_config WHERE id=1`).Scan(&timezone); err != nil {
		t.Fatalf("read timezone: %v", err)
	}
	if timezone != "Asia/Shanghai" {
		t.Fatalf("测试前提：security 分类导入不得替换 global_config timezone，got %q", timezone)
	}

	var got string
	if err := db.DB.QueryRow(`SELECT COALESCE(next_update,'') FROM security_crawler_sources WHERE name='googlebot'`).Scan(&got); err != nil {
		t.Fatalf("read imported slot: %v", err)
	}
	want := services.NextScheduledSlot(time.Now(), []int{1, 2, 3, 4, 5, 6, 7}, "04:00", services.CurrentLocation()).UTC().Format(flatUTCTimeLayout)
	if got == stale {
		t.Fatalf("导入槽未被重排：仍为源机形态 %q", stale)
	}
	if got != want {
		t.Fatalf("导入后 next_update=%q, want 本机排程槽 %q（旧槽 %q 必须被重排）", got, want, stale)
	}
}

// 导入后重排不得动**已过期**槽（补跑语义）：钉住「只改未来槽」的调用安全性，
// 防止后续把重排改成无条件重写而吞掉等待中的补跑轮。同时确认未来槽被重排
// （与过期槽同一次调用内分流的两个方向）。
func TestImportConfigBackup_keepsExpiredSlotsWhenRearming(t *testing.T) {
	h := newBackupTestHandlers(t)
	seedLiveAdminShared(t)
	if _, err := db.DB.Exec(`UPDATE global_config SET timezone='Asia/Shanghai' WHERE id=1`); err != nil {
		t.Fatalf("seed timezone: %v", err)
	}
	now := time.Now()
	expired := now.UTC().Add(-2 * time.Hour).Format(flatUTCTimeLayout)
	freshSlot := services.NextScheduledSlot(now, []int{1, 2, 3, 4, 5, 6, 7}, "04:00", services.CurrentLocation())
	stale := freshSlot.UTC().Add(8 * time.Hour).Format(flatUTCTimeLayout)
	payload := backupJSONFixture(t, map[string][]map[string]any{
		"security_crawler_sources": {
			{
				"name": "googlebot", "display_name": "Googlebot", "entry_count": 1,
				"version": "2026.10.01", "update_status": "idle", "update_enabled": 1,
				"next_update": expired,
			},
			{
				"name": "gptbot", "display_name": "GPTBot", "entry_count": 2,
				"version": "2026.10.01", "update_status": "idle", "update_enabled": 1,
				"next_update": stale,
			},
		},
	}, nil, []string{"security"})
	rec := postImportBytes(t, h, payload)
	if rec.Code != http.StatusOK {
		t.Fatalf("import status=%d body=%s", rec.Code, rec.Body.String())
	}

	read := func(name string) string {
		t.Helper()
		var slot string
		if err := db.DB.QueryRow(`SELECT COALESCE(next_update,'') FROM security_crawler_sources WHERE name=?`, name).Scan(&slot); err != nil {
			t.Fatalf("read %s slot: %v", name, err)
		}
		return slot
	}
	if got := read("googlebot"); got != expired {
		t.Fatalf("过期槽=%q, want 保留 %q（到期补跑语义）", got, expired)
	}
	want := services.NextScheduledSlot(time.Now(), []int{1, 2, 3, 4, 5, 6, 7}, "04:00", services.CurrentLocation()).UTC().Format(flatUTCTimeLayout)
	if got := read("gptbot"); got != want {
		t.Fatalf("未来槽=%q, want 重排为 %q（旧槽 %q）", got, want, stale)
	}
}

// flatUTCTimeLayout 是排程槽落库的平面 UTC 串形态（services.crsTimeLayout
// 未导出，测试侧按同一形态断言）。
const flatUTCTimeLayout = "2006-01-02 15:04:05"
