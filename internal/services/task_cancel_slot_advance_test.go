package services

// 用户取消自动轮后的排程槽语义（四个规则库族统一）：
//  ① 用户取消=显式放弃本槽——与失败同源推进到下一排程槽，否则引擎已消费
//     本槽而业务槽恒过期，tick 的「槽 > 已消费水位」门永不成立（静默停摆）；
//  ② 手动轮取消不推进（手动不改变预约）；
//  ③ demote/导入排空/进程停止的取消不推进（引擎侧同样不消费槽，恢复后
//     到期轮补跑）。
//
// 判定源=运行 ctx 的取消原因（taskengine.ErrUserCancelled）。

import (
	"context"
	"errors"
	"testing"
	"time"

	"lazy-balancer-v2/internal/db"
	"lazy-balancer-v2/internal/taskengine"
)

// expiredSlot 过期槽串（crsTimeLayout，UTC）。
func expiredSlot() string {
	return time.Now().UTC().Add(-time.Hour).Format(crsTimeLayout)
}

// assertFutureSlot 断言槽串为可解析且位于现在的未来（下一排程槽形态）。
func assertFutureSlot(t *testing.T, label, slot string) {
	t.Helper()
	parsed, err := time.ParseInLocation(crsTimeLayout, slot, time.UTC)
	if err != nil {
		t.Fatalf("%s: next_update=%q 不可解析: %v", label, slot, err)
	}
	if !parsed.After(time.Now().UTC().Add(-time.Minute)) {
		t.Fatalf("%s: next_update=%q 仍在过去（排程未推进）", label, slot)
	}
}

// Given auto 轮在途（fetch 阶段阻塞）。When 用户取消（CancelRunning）。
// Then 终态 cancelled 且 next_update 推进到未来排程槽——下一槽可正常投递。
func TestCRSUpdate_userCancelAdvancesScheduleSlot(t *testing.T) {
	m := newTestCRSManager(t)
	seedCRSVersionRow(t, "v4.30.0", true)
	setCRSSlot(t, expiredSlot())
	m.fetchLatestTag = func(ctx context.Context) (string, error) {
		<-ctx.Done()
		return "", ctx.Err()
	}

	done, err := m.StartUpdate("auto", nil)
	if err != nil {
		t.Fatal(err)
	}
	if !m.CancelRunning() {
		t.Fatal("在途运行 CancelRunning 应返回 true")
	}
	<-done

	if _, status, message, _, _, _, _ := crsVersionRow(t); status != string(CRSStatusCancelled) {
		t.Fatalf("update_status=%q, want cancelled (message=%q)", status, message)
	}
	assertFutureSlot(t, "CRS 用户取消后", crsNextUpdate(t))
}

// Given auto 轮在途。When 系统性中止（导入排空/进程停止形态：ctx 普通取消，
// 无 ErrUserCancelled 原因）。Then 终态 cancelled 但槽保持原值——恢复后到期
// 轮补跑，不得被取消动作吞掉。
func TestCRSUpdate_systemAbortKeepsDueSlot(t *testing.T) {
	m := newTestCRSManager(t)
	seedCRSVersionRow(t, "v4.30.0", true)
	slot := expiredSlot()
	setCRSSlot(t, slot)
	m.fetchLatestTag = func(ctx context.Context) (string, error) {
		<-ctx.Done()
		return "", ctx.Err()
	}

	base, cancelBase := context.WithCancel(context.Background())
	done, err := m.StartUpdate("auto", &taskengine.RunContext{Ctx: base})
	if err != nil {
		t.Fatal(err)
	}
	cancelBase()
	<-done

	if _, status, message, _, _, _, _ := crsVersionRow(t); status != string(CRSStatusCancelled) {
		t.Fatalf("update_status=%q, want cancelled (message=%q)", status, message)
	}
	if got := crsNextUpdate(t); got != slot {
		t.Fatalf("系统性中止后 next_update=%q, want 保持原值 %q（恢复后补跑）", got, slot)
	}
}

// Given 手动轮在途。When 用户取消。Then 槽不动（手动执行不改变预约）。
func TestCRSUpdate_manualUserCancelKeepsScheduleSlot(t *testing.T) {
	m := newTestCRSManager(t)
	seedCRSVersionRow(t, "v4.30.0", true)
	slot := expiredSlot()
	setCRSSlot(t, slot)
	m.fetchLatestTag = func(ctx context.Context) (string, error) {
		<-ctx.Done()
		return "", ctx.Err()
	}

	done, err := m.StartUpdate("manual", nil)
	if err != nil {
		t.Fatal(err)
	}
	if !m.CancelRunning() {
		t.Fatal("在途运行 CancelRunning 应返回 true")
	}
	<-done

	if got := crsNextUpdate(t); got != slot {
		t.Fatalf("手动取消后 next_update=%q, want 保持预约 %q", got, slot)
	}
}

// Given auto 轮在途（fetch 阶段阻塞）。When 用户取消。
// Then next_update 推进到未来排程槽（与 CRS 同构）。
func TestIP2RegionUpdate_userCancelAdvancesScheduleSlot(t *testing.T) {
	m := newTestIP2RegionManager(t)
	seedIP2RegionVersionRow(t, "v3.18.0", true)
	setIP2RSlot(t, expiredSlot())
	m.fetchLatestTag = func(ctx context.Context) (string, error) {
		<-ctx.Done()
		return "", ctx.Err()
	}

	done, err := m.StartUpdate("auto", nil)
	if err != nil {
		t.Fatal(err)
	}
	if !m.CancelRunning() {
		t.Fatal("在途运行 CancelRunning 应返回 true")
	}
	<-done

	if _, status, message, _, _, _, _ := ip2RegionVersionRow(t); status != string(IP2RegionStatusCancelled) {
		t.Fatalf("update_status=%q, want cancelled (message=%q)", status, message)
	}
	assertFutureSlot(t, "IP2Region 用户取消后", ip2rNextUpdate(t))
}

// 设置源表全部启用行的槽为过期值。
func setSourceSlotsPast(t *testing.T, table string) {
	t.Helper()
	if _, err := db.DB.Exec(`UPDATE `+table+` SET next_update=? WHERE update_enabled=1`, expiredSlot()); err != nil {
		t.Fatal(err)
	}
}

// assertAllSourceSlotsFuture 断言启用源全部推进到未来槽（引擎排程槽=最早
// 启用源槽，任一源留在旧值即永久压住整个任务）。
func assertAllSourceSlotsFuture(t *testing.T, table string) {
	t.Helper()
	rows, err := db.DB.Query(`SELECT COALESCE(next_update,'') FROM ` + table + ` WHERE update_enabled=1`)
	if err != nil {
		t.Fatal(err)
	}
	defer rows.Close()
	count := 0
	for rows.Next() {
		var slot string
		if err := rows.Scan(&slot); err != nil {
			t.Fatal(err)
		}
		count++
		assertFutureSlot(t, table, slot)
	}
	if err := rows.Err(); err != nil {
		t.Fatal(err)
	}
	if count == 0 {
		t.Fatalf("%s 无启用行，断言失效", table)
	}
}

// Given 威胁情报库 auto 轮在途（源下载前取消）。When 用户取消。
// Then 全部启用源槽推进到未来——引擎排程槽（最早源槽）随之进入下一槽。
func TestThreatUpdate_userCancelAdvancesAllDueSourceSlots(t *testing.T) {
	overrideWafDirForTest(t)
	newClusterTestService(t)
	setupThreatTest(t, nil, nil, nil)
	if _, err := db.DB.Exec(`UPDATE security_threat_sources SET update_enabled=1`); err != nil {
		t.Fatal(err)
	}
	setSourceSlotsPast(t, "security_threat_sources")

	m := GetThreatUpdateManager()
	ctx, cancel := context.WithCancelCause(context.Background())
	cancel(taskengine.ErrUserCancelled)
	if err := m.RunUpdate("auto", &taskengine.RunContext{Ctx: ctx, Trigger: "auto"}); err != nil {
		t.Fatalf("RunUpdate: %v", err)
	}
	if outcome := m.StatusSnapshot().Outcome; outcome != "cancelled" {
		t.Fatalf("outcome=%q, want cancelled", outcome)
	}
	assertAllSourceSlotsFuture(t, "security_threat_sources")
}

// Given 威胁情报库 auto 轮在途。When 系统性中止（无 ErrUserCancelled）。
// Then 源槽保持原值（恢复后到期轮补跑）。
func TestThreatUpdate_systemAbortKeepsSourceSlots(t *testing.T) {
	overrideWafDirForTest(t)
	newClusterTestService(t)
	setupThreatTest(t, nil, nil, nil)
	if _, err := db.DB.Exec(`UPDATE security_threat_sources SET update_enabled=1`); err != nil {
		t.Fatal(err)
	}
	setSourceSlotsPast(t, "security_threat_sources")
	var before string
	if err := db.DB.QueryRow(`SELECT COALESCE(next_update,'') FROM security_threat_sources WHERE update_enabled=1 ORDER BY id LIMIT 1`).Scan(&before); err != nil {
		t.Fatal(err)
	}

	m := GetThreatUpdateManager()
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if err := m.RunUpdate("auto", &taskengine.RunContext{Ctx: ctx, Trigger: "auto"}); err != nil {
		t.Fatalf("RunUpdate: %v", err)
	}
	var after string
	if err := db.DB.QueryRow(`SELECT COALESCE(next_update,'') FROM security_threat_sources WHERE update_enabled=1 ORDER BY id LIMIT 1`).Scan(&after); err != nil {
		t.Fatal(err)
	}
	if after != before {
		t.Fatalf("系统性中止后 next_update=%q, want 保持原值 %q", after, before)
	}
}

// Given 爬虫地址库 auto 轮开跑前取消（零源行写入）。When 用户取消。
// Then 全部启用源槽推进到未来（含未处理源）。
func TestCrawlerUpdate_userCancelAdvancesAllDueSourceSlots(t *testing.T) {
	newClusterTestService(t)
	if err := ensureCrawlerSources(); err != nil {
		t.Fatal(err)
	}
	setSourceSlotsPast(t, "security_crawler_sources")
	if _, err := db.DB.Exec(`UPDATE security_crawler_sources SET update_enabled=1 WHERE name IN ('googlebot','bingbot')`); err != nil {
		t.Fatal(err)
	}

	ctx, cancel := context.WithCancelCause(context.Background())
	cancel(taskengine.ErrUserCancelled)
	err := GetCrawlerUpdateManager().RunUpdate(ctx, taskengine.RunContext{Ctx: ctx, Trigger: "auto"})
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("RunUpdate err=%v, want context.Canceled", err)
	}
	assertAllSourceSlotsFuture(t, "security_crawler_sources")
}

// Given 爬虫地址库 auto 轮开跑前系统性中止。Then 源槽保持原值。
func TestCrawlerUpdate_systemAbortKeepsSourceSlots(t *testing.T) {
	newClusterTestService(t)
	if err := ensureCrawlerSources(); err != nil {
		t.Fatal(err)
	}
	setSourceSlotsPast(t, "security_crawler_sources")
	var before string
	if err := db.DB.QueryRow(`SELECT COALESCE(next_update,'') FROM security_crawler_sources WHERE update_enabled=1 ORDER BY id LIMIT 1`).Scan(&before); err != nil {
		t.Fatal(err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	_ = GetCrawlerUpdateManager().RunUpdate(ctx, taskengine.RunContext{Ctx: ctx, Trigger: "auto"})
	var after string
	if err := db.DB.QueryRow(`SELECT COALESCE(next_update,'') FROM security_crawler_sources WHERE update_enabled=1 ORDER BY id LIMIT 1`).Scan(&after); err != nil {
		t.Fatal(err)
	}
	if after != before {
		t.Fatalf("系统性中止后 next_update=%q, want 保持原值 %q", after, before)
	}
}
