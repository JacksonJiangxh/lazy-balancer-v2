package services

// 自动封禁（历史问题）核心行为钉：固定桶计数器（重置语义/上限保护）、摄取
// 提交点喂入门（主节点+启用+口径+WAF 事件）、名单 merge（清到期/保留手动/
// 抑制过滤/超限挤最早到期）、重载节流（<60s 暂存合并）、EnabledFn fail-closed、
// 配置校验与口径/窗口变更重置、投影层过期条目过滤。

import (
	"encoding/json"
	"fmt"
	"sync"
	"testing"
	"time"

	"lazy-balancer-v2/internal/db"
	"lazy-balancer-v2/internal/models"
	"lazy-balancer-v2/internal/taskengine"
)

// ---- 夹具 ----

// autobanTestClock 可注入时钟（重置语义/节流/抑制窗口断言的时间轴）。
type autobanTestClock struct {
	mu  sync.Mutex
	now time.Time
}

func newAutobanTestClock(start string) *autobanTestClock {
	ts, _ := time.ParseInLocation("2006-01-02 15:04:05", start, time.UTC)
	return &autobanTestClock{now: ts}
}

func (c *autobanTestClock) Now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.now
}

func (c *autobanTestClock) Advance(d time.Duration) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.now = c.now.Add(d)
}

// installAutobanFixture：初始化临时库+接管全局时钟缝。LIFO 清理还原。
func installAutobanFixture(t *testing.T, start string) *autobanTestClock {
	t.Helper()
	oldDB, oldMetricsDB, oldAuditDB := db.DB, db.MetricsDB, db.AuditDB
	if err := db.Initialize(t.TempDir()); err != nil {
		t.Fatalf("initialize test database: %v", err)
	}
	t.Cleanup(func() {
		_ = db.Close()
		db.DB, db.MetricsDB, db.AuditDB = oldDB, oldMetricsDB, oldAuditDB
	})
	taskengine.SetLogDir(t.TempDir())
	t.Cleanup(func() { taskengine.SetLogDir("") })

	clock := newAutobanTestClock(start)
	oldNow := autobanNow
	autobanNow = clock.Now
	t.Cleanup(func() { autobanNow = oldNow })

	// 默认主节点（喂入门默认通过——主节点门单独有负向钉测）。
	oldMaster := autobanIsMaster
	autobanIsMaster = func() bool { return true }
	t.Cleanup(func() { autobanIsMaster = oldMaster })

	resetAutobanStateForTest()
	t.Cleanup(resetAutobanStateForTest)
	return clock
}

func resetAutobanStateForTest() {
	autobanMu.Lock()
	defer autobanMu.Unlock()
	autobanWindows = make(map[string]*autobanCounter)
	autobanSuggestions = nil
	autobanReloadPending = false
	autobanLastReload = time.Time{}
	autobanCapWarned = false
}

// setAutobanConfigRaw 直接写列（绕过 SetAutobanConfig 的重置副作用——
// 重置语义单独钉）。
func setAutobanConfigRaw(t *testing.T, enabled bool, threshold, windowMin int, duration, scope string, dryRun bool) {
	t.Helper()
	ei, di := 0, 0
	if enabled {
		ei = 1
	}
	if dryRun {
		di = 1
	}
	if _, err := db.DB.Exec(`UPDATE global_config SET autoban_enabled=?, autoban_threshold=?, autoban_window_minutes=?, autoban_duration=?, autoban_scope=?, autoban_dry_run=? WHERE id=1`,
		ei, threshold, windowMin, duration, scope, di); err != nil {
		t.Fatalf("seed autoban config: %v", err)
	}
}

func presetListID(t *testing.T) int64 {
	t.Helper()
	var id int64
	if err := db.DB.QueryRow(`SELECT id FROM security_ip_lists WHERE name=?`, AutobanPresetListName).Scan(&id); err != nil {
		t.Fatalf("preset list missing: %v", err)
	}
	return id
}

func presetEntries(t *testing.T) []models.IPListEntry {
	t.Helper()
	var raw string
	if err := db.DB.QueryRow(`SELECT COALESCE(entries,'[]') FROM security_ip_lists WHERE id=?`, presetListID(t)).Scan(&raw); err != nil {
		t.Fatalf("read preset entries: %v", err)
	}
	var entries []models.IPListEntry
	if err := json.Unmarshal([]byte(raw), &entries); err != nil {
		t.Fatalf("parse preset entries %q: %v", raw, err)
	}
	return entries
}

func entryValues(entries []models.IPListEntry) map[string]models.IPListEntry {
	m := make(map[string]models.IPListEntry, len(entries))
	for _, e := range entries {
		m[e.Value] = e
	}
	return m
}

// ---- 计数器：固定桶重置语义 ----

// Given 同一 IP 在窗口内多次命中。
// When 跨过窗口边界后再命中。
// Then 计数从新窗口起算（固定桶重置），不与旧窗口累计。
func TestAutobanCounter_fixedWindowResets(t *testing.T) {
	f := installAutobanFixture(t, "2026-10-14 10:00:00")
	setAutobanConfigRaw(t, true, 3, 5, "1h", "all", true)

	autobanObserveEvent("203.0.113.7", "blocked", "942100")
	autobanObserveEvent("203.0.113.7", "blocked", "942100")
	f.Advance(6 * time.Minute) // 越过 5 分钟窗口
	autobanObserveEvent("203.0.113.7", "blocked", "942100")

	autobanMu.Lock()
	w := autobanWindows["203.0.113.7"]
	autobanMu.Unlock()
	if w == nil || w.Count != 1 {
		t.Fatalf("跨窗口后计数应重置为 1，得到 %+v", w)
	}
}

// Given 计数器键达到上限。
// When 新键继续喂入。
// Then 新键丢弃并告警一次；既有键不受影响继续累计。
func TestAutobanCounter_capProtection(t *testing.T) {
	installAutobanFixture(t, "2026-10-14 10:00:00")
	setAutobanConfigRaw(t, true, 1, 5, "1h", "all", true)
	oldCap := autobanMaxTrackedIPs
	autobanMaxTrackedIPs = 3
	t.Cleanup(func() { autobanMaxTrackedIPs = oldCap })

	for i := range 3 {
		autobanObserveEvent(fmt.Sprintf("198.51.100.%d", i+1), "blocked", "942100")
	}
	autobanObserveEvent("203.0.113.99", "blocked", "942100") // 超限新键→丢弃
	autobanObserveEvent("198.51.100.1", "blocked", "942100") // 既有键→继续累计

	autobanMu.Lock()
	defer autobanMu.Unlock()
	if _, exists := autobanWindows["203.0.113.99"]; exists {
		t.Fatal("超限新键不得进入计数器")
	}
	if autobanWindows["198.51.100.1"].Count != 2 {
		t.Fatalf("既有键计数=%d, want 2（超限不挤占既有键）", autobanWindows["198.51.100.1"].Count)
	}
	if !autobanCapWarned {
		t.Fatal("超限丢弃必须置位告警标记（留痕）")
	}
}

// ---- 摄取喂入门：主节点+启用+口径+WAF 事件 ----

func TestAutobanObserve_gates(t *testing.T) {
	t.Run("非主节点不喂", func(t *testing.T) {
		installAutobanFixture(t, "2026-10-14 10:00:00")
		setAutobanConfigRaw(t, true, 1, 5, "1h", "all", true)
		oldMaster := autobanIsMaster
		autobanIsMaster = func() bool { return false }
		t.Cleanup(func() { autobanIsMaster = oldMaster })
		autobanObserveEvent("203.0.113.1", "blocked", "942100")
		autobanMu.Lock()
		n := len(autobanWindows)
		autobanMu.Unlock()
		if n != 0 {
			t.Fatalf("非主节点不得喂计数器，得到 %d 键", n)
		}
	})
	t.Run("未启用不喂", func(t *testing.T) {
		installAutobanFixture(t, "2026-10-14 10:00:00")
		setAutobanConfigRaw(t, false, 1, 5, "1h", "all", true)
		autobanObserveEvent("203.0.113.1", "blocked", "942100")
		autobanMu.Lock()
		n := len(autobanWindows)
		autobanMu.Unlock()
		if n != 0 {
			t.Fatalf("未启用不得喂计数器，得到 %d 键", n)
		}
	})
	t.Run("非WAF事件不喂", func(t *testing.T) {
		installAutobanFixture(t, "2026-10-14 10:00:00")
		setAutobanConfigRaw(t, true, 1, 5, "1h", "all", true)
		autobanObserveEvent("203.0.113.1", "blocked", "")
		autobanMu.Lock()
		n := len(autobanWindows)
		autobanMu.Unlock()
		if n != 0 {
			t.Fatalf("rule_triggered 为空（非 WAF 事件）不得喂计数器，得到 %d 键", n)
		}
	})
	t.Run("口径过滤blocked", func(t *testing.T) {
		installAutobanFixture(t, "2026-10-14 10:00:00")
		setAutobanConfigRaw(t, true, 1, 5, "1h", "blocked", true)
		autobanObserveEvent("203.0.113.1", "logged", "942100")
		autobanObserveEvent("203.0.113.2", "blocked", "942100")
		autobanMu.Lock()
		_, loggedFed := autobanWindows["203.0.113.1"]
		_, blockedFed := autobanWindows["203.0.113.2"]
		autobanMu.Unlock()
		if loggedFed {
			t.Fatal("scope=blocked 时 logged 事件不得喂入")
		}
		if !blockedFed {
			t.Fatal("scope=blocked 时 blocked 事件必须喂入")
		}
	})
	t.Run("口径过滤logged", func(t *testing.T) {
		installAutobanFixture(t, "2026-10-14 10:00:00")
		setAutobanConfigRaw(t, true, 1, 5, "1h", "logged", true)
		autobanObserveEvent("203.0.113.1", "blocked", "942100")
		autobanObserveEvent("203.0.113.2", "logged", "942100")
		autobanMu.Lock()
		_, blockedFed := autobanWindows["203.0.113.1"]
		_, loggedFed := autobanWindows["203.0.113.2"]
		autobanMu.Unlock()
		if blockedFed || !loggedFed {
			t.Fatalf("scope=logged 口径失真：blocked 喂入=%v logged 喂入=%v", blockedFed, loggedFed)
		}
	})
}

// ---- 配置：校验 + 口径/窗口变更重置 ----

func TestAutobanConfig_validation(t *testing.T) {
	for _, d := range []string{"10m", "30m", "1h", "6h", "12h", "24h", "permanent"} {
		if !ValidAutobanDuration(d) {
			t.Errorf("ValidAutobanDuration(%q)=false, want true", d)
		}
	}
	for _, d := range []string{"", "5m", "2h", "forever", "1H"} {
		if ValidAutobanDuration(d) {
			t.Errorf("ValidAutobanDuration(%q)=true, want false", d)
		}
	}
	for _, s := range []string{"blocked", "logged", "all"} {
		if !ValidAutobanScope(s) {
			t.Errorf("ValidAutobanScope(%q)=false, want true", s)
		}
	}
	for _, s := range []string{"", "deny", "BLOCKED"} {
		if ValidAutobanScope(s) {
			t.Errorf("ValidAutobanScope(%q)=true, want false", s)
		}
	}
}

// Given 计数器已有键。
// When 窗口或口径配置变更。
// Then 计数器清空（口径/窗口变更重置语义）；仅改其他字段不清空。
func TestAutobanSetConfig_resetsCountersOnWindowOrScopeChange(t *testing.T) {
	installAutobanFixture(t, "2026-10-14 10:00:00")
	setAutobanConfigRaw(t, true, 100, 5, "1h", "all", true)
	autobanObserveEvent("203.0.113.1", "blocked", "942100")

	// 同值写（仅改阈值）→ 不清空
	if err := SetAutobanConfig(AutobanConfig{Enabled: true, Threshold: 50, WindowMinutes: 5, Duration: "1h", Scope: "all", DryRun: true}); err != nil {
		t.Fatalf("SetAutobanConfig: %v", err)
	}
	autobanMu.Lock()
	n := len(autobanWindows)
	autobanMu.Unlock()
	if n != 1 {
		t.Fatalf("未变更窗口/口径时计数器不得清空，得到 %d 键", n)
	}

	// 变更窗口 → 清空
	if err := SetAutobanConfig(AutobanConfig{Enabled: true, Threshold: 50, WindowMinutes: 10, Duration: "1h", Scope: "all", DryRun: true}); err != nil {
		t.Fatalf("SetAutobanConfig window: %v", err)
	}
	autobanMu.Lock()
	n = len(autobanWindows)
	autobanMu.Unlock()
	if n != 0 {
		t.Fatalf("窗口变更必须重置计数器，残留 %d 键", n)
	}

	// 变更口径 → 清空
	autobanObserveEvent("203.0.113.1", "blocked", "942100")
	if err := SetAutobanConfig(AutobanConfig{Enabled: true, Threshold: 50, WindowMinutes: 10, Duration: "1h", Scope: "blocked", DryRun: true}); err != nil {
		t.Fatalf("SetAutobanConfig scope: %v", err)
	}
	autobanMu.Lock()
	n = len(autobanWindows)
	autobanMu.Unlock()
	if n != 0 {
		t.Fatalf("口径变更必须重置计数器，残留 %d 键", n)
	}
}

func TestAutobanSetConfig_rejectsOutOfRange(t *testing.T) {
	installAutobanFixture(t, "2026-10-14 10:00:00")
	cases := []AutobanConfig{
		{Enabled: true, Threshold: 0, WindowMinutes: 5, Duration: "1h", Scope: "all", DryRun: true},
		{Enabled: true, Threshold: 10001, WindowMinutes: 5, Duration: "1h", Scope: "all", DryRun: true},
		{Enabled: true, Threshold: 100, WindowMinutes: 0, Duration: "1h", Scope: "all", DryRun: true},
		{Enabled: true, Threshold: 100, WindowMinutes: 61, Duration: "1h", Scope: "all", DryRun: true},
		{Enabled: true, Threshold: 100, WindowMinutes: 5, Duration: "2h", Scope: "all", DryRun: true},
		{Enabled: true, Threshold: 100, WindowMinutes: 5, Duration: "1h", Scope: "deny", DryRun: true},
	}
	for i, cfg := range cases {
		if err := SetAutobanConfig(cfg); err == nil {
			t.Errorf("case %d (%+v) 应校验拒绝", i, cfg)
		}
	}
}

// ---- EnabledFn：fail-closed ----

func TestAutobanEnabledFn(t *testing.T) {
	installAutobanFixture(t, "2026-10-14 10:00:00")
	setAutobanConfigRaw(t, false, 100, 5, "1h", "all", true)
	if AutobanEnabled() {
		t.Fatal("autoban_enabled=0 时 AutobanEnabled() 应为 false")
	}
	setAutobanConfigRaw(t, true, 100, 5, "1h", "all", true)
	if !AutobanEnabled() {
		t.Fatal("autoban_enabled=1 时 AutobanEnabled() 应为 true")
	}
	swapBrokenDB(t)
	if AutobanEnabled() {
		t.Fatal("读库失败应 fail-closed（false）")
	}
}

// ---- 名单 merge ----

func seedPresetEntries(t *testing.T, entries []models.IPListEntry) {
	t.Helper()
	raw, err := json.Marshal(entries)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := db.DB.Exec(`UPDATE security_ip_lists SET entries=? WHERE id=?`, string(raw), presetListID(t)); err != nil {
		t.Fatalf("seed preset entries: %v", err)
	}
}

// Given 名单含「已到期自动条目/手动条目/未到期自动条目」；候选含「已在名单/
// 抑制期内/新 IP」。
// When 执行 merge。
// Then 到期条目清除、手动条目保留、抑制 IP 不重封、新 IP 带到期时间追加。
func TestAutobanMerge_expiryManualSuppression(t *testing.T) {
	f := installAutobanFixture(t, "2026-10-14 10:00:00")
	setAutobanConfigRaw(t, true, 1, 5, "1h", "all", false)
	seedPresetEntries(t, []models.IPListEntry{
		{Value: "198.51.100.1", Remark: AutobanEntryRemark, CreatedAt: "2026-10-13 10:00:00", ExpiresAt: "2026-10-14 09:00:00"}, // 已到期
		{Value: "198.51.100.2", Remark: "事件处置", CreatedAt: "2026-10-13 10:00:00"},                                               // 手动条目
		{Value: "198.51.100.3", Remark: AutobanEntryRemark, CreatedAt: "2026-10-14 09:30:00", ExpiresAt: "2026-10-14 10:30:00"}, // 未到期
	})
	if err := SuppressAutobanIP("203.0.113.9"); err != nil {
		t.Fatalf("suppress: %v", err)
	}

	out, err := autobanMergeEntries(AutobanConfig{Enabled: true, Threshold: 1, WindowMinutes: 5, Duration: "1h", Scope: "all", DryRun: false},
		[]AutobanSuggestion{
			{IP: "198.51.100.3", Count: 10},  // 已在名单→跳过
			{IP: "203.0.113.9", Count: 10},   // 抑制期内→跳过
			{IP: "203.0.113.10", Count: 120}, // 新封
			{IP: "203.0.113.11", Count: 101}, // 新封
		})
	if err != nil {
		t.Fatalf("merge: %v", err)
	}

	entries := entryValues(presetEntries(t))
	if _, exists := entries["198.51.100.1"]; exists {
		t.Fatal("到期条目必须清除")
	}
	if e, exists := entries["198.51.100.2"]; !exists || e.Remark != "事件处置" {
		t.Fatalf("手动条目必须原样保留，得到 %+v", e)
	}
	if _, exists := entries["203.0.113.9"]; exists {
		t.Fatal("抑制期内 IP 不得重封")
	}
	newEntry, exists := entries["203.0.113.10"]
	if !exists {
		t.Fatal("新 IP 必须追加")
	}
	if newEntry.Remark != AutobanEntryRemark {
		t.Fatalf("新封条目 remark=%q, want %q", newEntry.Remark, AutobanEntryRemark)
	}
	exp, perr := time.ParseInLocation("2006-01-02 15:04:05", newEntry.ExpiresAt, time.UTC)
	if perr != nil {
		t.Fatalf("新封条目 expires_at=%q 不可解析", newEntry.ExpiresAt)
	}
	want := f.Now().Add(time.Hour)
	if d := exp.Sub(want); d > time.Second || d < -time.Second {
		t.Fatalf("expires_at=%s, want ≈%s", newEntry.ExpiresAt, want)
	}
	if newEntry.CreatedAt == "" {
		t.Fatal("新封条目必须带 created_at")
	}
	if !out.Changed {
		t.Fatal("有清除+新增时 Changed 必须为 true")
	}
	if len(out.Banned) != 2 || len(out.Expired) != 1 || out.SkippedSuppressed != 1 {
		t.Fatalf("merge 计数失真：banned=%v expired=%v suppressed=%d", out.Banned, out.Expired, out.SkippedSuppressed)
	}
}

// Given 名单条目接近上限。
// When 新封导致超限。
// Then 优先挤出最早到期的自动条目；手动条目不挤出；仅剩永久自动条目可挤时
// 挤永久条目。
func TestAutobanMerge_evictsEarliestExpiringAutobanEntries(t *testing.T) {
	installAutobanFixture(t, "2026-10-14 10:00:00")
	setAutobanConfigRaw(t, true, 1, 5, "1h", "all", false)
	oldCap := AutobanListEntryCap
	t.Cleanup(func() { AutobanListEntryCap = oldCap })

	t.Run("最早到期自动条目先挤", func(t *testing.T) {
		AutobanListEntryCap = 4
		seedPresetEntries(t, []models.IPListEntry{
			{Value: "198.51.100.2", Remark: "事件处置"},                                               // 手动
			{Value: "198.51.100.3", Remark: AutobanEntryRemark, ExpiresAt: "2026-10-14 12:00:00"}, // 自动，晚到期
			{Value: "198.51.100.4", Remark: AutobanEntryRemark, ExpiresAt: "2026-10-14 11:00:00"}, // 自动，最早到期
			{Value: "198.51.100.6", Remark: AutobanEntryRemark, CreatedAt: "2026-10-13 10:00:00"}, // 自动，永久
		})
		out, err := autobanMergeEntries(AutobanConfig{Enabled: true, Threshold: 1, WindowMinutes: 5, Duration: "1h", Scope: "all", DryRun: false},
			[]AutobanSuggestion{{IP: "203.0.113.10", Count: 120}})
		if err != nil {
			t.Fatalf("merge: %v", err)
		}
		entries := entryValues(presetEntries(t))
		if len(entries) != AutobanListEntryCap {
			t.Fatalf("条目数=%d, want 恰好上限 %d", len(entries), AutobanListEntryCap)
		}
		if _, exists := entries["198.51.100.4"]; exists {
			t.Fatal("最早到期自动条目必须先被挤出")
		}
		if _, exists := entries["198.51.100.2"]; !exists {
			t.Fatal("手动条目不得挤出")
		}
		if _, exists := entries["203.0.113.10"]; !exists {
			t.Fatal("挤出一个后应容纳新封")
		}
		if out.Evicted != 1 {
			t.Fatalf("evicted=%d, want 1", out.Evicted)
		}
	})

	t.Run("仅剩永久自动条目时挤永久", func(t *testing.T) {
		AutobanListEntryCap = 2
		seedPresetEntries(t, []models.IPListEntry{
			{Value: "198.51.100.2", Remark: "事件处置"},                                               // 手动
			{Value: "198.51.100.7", Remark: AutobanEntryRemark, CreatedAt: "2026-10-13 08:00:00"}, // 自动，永久
		})
		out, err := autobanMergeEntries(AutobanConfig{Enabled: true, Threshold: 1, WindowMinutes: 5, Duration: "permanent", Scope: "all", DryRun: false},
			[]AutobanSuggestion{{IP: "203.0.113.10", Count: 120}})
		if err != nil {
			t.Fatalf("merge: %v", err)
		}
		entries := entryValues(presetEntries(t))
		if len(entries) != AutobanListEntryCap {
			t.Fatalf("条目数=%d, want 恰好上限 %d", len(entries), AutobanListEntryCap)
		}
		if _, exists := entries["198.51.100.7"]; exists {
			t.Fatal("容量不足时永久自动条目必须被挤出（手动条目不挤）")
		}
		if _, exists := entries["203.0.113.10"]; !exists {
			t.Fatal("挤出永久条目后应容纳新封")
		}
		if out.Evicted != 1 {
			t.Fatalf("evicted=%d, want 1", out.Evicted)
		}
	})
}

// ---- 抑制表 ----

func TestAutobanSuppression_upsertAndExpiry(t *testing.T) {
	f := installAutobanFixture(t, "2026-10-14 10:00:00")
	if err := SuppressAutobanIP("203.0.113.1"); err != nil {
		t.Fatalf("suppress: %v", err)
	}
	f.Advance(24 * time.Hour)
	if err := SuppressAutobanIP("203.0.113.1"); err != nil {
		t.Fatalf("suppress again: %v", err)
	}
	var rows int
	if err := db.DB.QueryRow(`SELECT COUNT(*) FROM autoban_suppressed WHERE ip='203.0.113.1'`).Scan(&rows); err != nil {
		t.Fatal(err)
	}
	if rows != 1 {
		t.Fatalf("重复解封应 UPSERT 单行，得到 %d 行", rows)
	}
	set := autobanSuppressedSet(f.Now())
	if _, ok := set["203.0.113.1"]; !ok {
		t.Fatal("抑制期内 IP 必须在抑制集合中")
	}
	// 30 天后过期
	f.Advance(30*24*time.Hour + time.Minute)
	set = autobanSuppressedSet(f.Now())
	if _, ok := set["203.0.113.1"]; ok {
		t.Fatal("抑制到期后必须离开抑制集合")
	}
}

// ---- 重载节流 ----

func TestAutobanReloadThrottle(t *testing.T) {
	f := installAutobanFixture(t, "2026-10-14 10:00:00")
	reloads := 0
	oldFn := autobanReloader
	autobanReloader = func() error { reloads++; return nil }
	t.Cleanup(func() { autobanReloader = oldFn })

	autobanRequestReload("test")
	if reloads != 1 {
		t.Fatalf("首次请求应立即重载，reloads=%d", reloads)
	}
	autobanRequestReload("test") // <60s → 暂存
	if reloads != 1 {
		t.Fatalf("节流窗口内不得立即重载，reloads=%d", reloads)
	}
	autobanMu.Lock()
	pending := autobanReloadPending
	autobanMu.Unlock()
	if !pending {
		t.Fatal("节流窗口内的重载请求必须置位暂存")
	}
	f.Advance(61 * time.Second)
	autobanFlushPendingReload()
	if reloads != 2 {
		t.Fatalf("窗口过后暂存重载应执行，reloads=%d", reloads)
	}
	autobanMu.Lock()
	pending = autobanReloadPending
	autobanMu.Unlock()
	if pending {
		t.Fatal("执行后暂存标记必须清除")
	}
}

// ---- Run 循环：观察模式与正式封禁 ----

func TestAutobanRunCycle_dryRunStoresSuggestionsOnly(t *testing.T) {
	installAutobanFixture(t, "2026-10-14 10:00:00")
	setAutobanConfigRaw(t, true, 2, 5, "1h", "all", true)
	autobanObserveEvent("203.0.113.1", "blocked", "942100")
	autobanObserveEvent("203.0.113.1", "blocked", "942100")
	autobanObserveEvent("203.0.113.1", "blocked", "942100")
	autobanObserveEvent("203.0.113.2", "blocked", "942100") // 1 次 < 阈值

	if err := RunAutobanCycle(taskengine.RunContext{Trigger: "auto"}); err != nil {
		t.Fatalf("RunAutobanCycle: %v", err)
	}
	sugg := AutobanSuggestions()
	if len(sugg) != 1 || sugg[0].IP != "203.0.113.1" || sugg[0].Count != 3 {
		t.Fatalf("观察建议=%+v, want [{203.0.113.1 3}]", sugg)
	}
	if entries := presetEntries(t); len(entries) != 0 {
		t.Fatalf("观察模式不得写名单，得到 %d 条", len(entries))
	}
}

func TestAutobanRunCycle_bansAndReloads(t *testing.T) {
	installAutobanFixture(t, "2026-10-14 10:00:00")
	setAutobanConfigRaw(t, true, 2, 5, "1h", "all", false)
	reloads := 0
	oldFn := autobanReloader
	autobanReloader = func() error { reloads++; return nil }
	t.Cleanup(func() { autobanReloader = oldFn })
	autobanObserveEvent("203.0.113.1", "blocked", "942100")
	autobanObserveEvent("203.0.113.1", "blocked", "942100")

	if err := RunAutobanCycle(taskengine.RunContext{Trigger: "auto"}); err != nil {
		t.Fatalf("RunAutobanCycle: %v", err)
	}
	entries := presetEntries(t)
	if len(entries) != 1 || entries[0].Value != "203.0.113.1" {
		t.Fatalf("达阈值 IP 必须落名单，得到 %+v", entries)
	}
	if reloads != 1 {
		t.Fatalf("名单变化后应触发重载，reloads=%d", reloads)
	}
}

func TestAutobanRunCycle_permanentBanHasNoExpiry(t *testing.T) {
	installAutobanFixture(t, "2026-10-14 10:00:00")
	setAutobanConfigRaw(t, true, 1, 5, "permanent", "all", false)
	autobanObserveEvent("203.0.113.1", "blocked", "942100")
	if err := RunAutobanCycle(taskengine.RunContext{Trigger: "auto"}); err != nil {
		t.Fatalf("RunAutobanCycle: %v", err)
	}
	entries := presetEntries(t)
	if len(entries) != 1 || entries[0].ExpiresAt != "" {
		t.Fatalf("permanent 封禁不得带 expires_at，得到 %+v", entries)
	}
}

// ---- 投影层：过期条目过滤 ----

func TestIPListProjection_filtersExpiredEntries(t *testing.T) {
	installAutobanFixture(t, "2026-10-14 10:00:00")
	var id int64
	if err := db.DB.QueryRow(`INSERT INTO security_ip_lists (name, category, entries) VALUES ('投影过期钉', '', ?) RETURNING id`,
		`[{"value":"198.51.100.1","remark":"已到期","expires_at":"2026-10-14 09:00:00"},{"value":"198.51.100.2","remark":"未到期","expires_at":"2026-10-14 11:00:00"},{"value":"198.51.100.3","remark":"无到期"}]`).Scan(&id); err != nil {
		t.Fatalf("seed list: %v", err)
	}
	got, err := LoadIPListEntriesByID([]int64{id})
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	vals := got[id]
	if len(vals) != 2 || vals[0] != "198.51.100.2" || vals[1] != "198.51.100.3" {
		t.Fatalf("投影必须过滤已到期条目（保留未到期与无到期），得到 %v", vals)
	}
}

// ---- 摄取提交点批量喂入 ----

func TestAutobanObserveBatch_commitPointFeed(t *testing.T) {
	installAutobanFixture(t, "2026-10-14 10:00:00")
	setAutobanConfigRaw(t, true, 2, 5, "1h", "all", true)
	autobanObserveBatch([]autobanFeedItem{
		{IP: "203.0.113.1", Action: "blocked", RuleTriggered: "942100"},
		{IP: "203.0.113.1", Action: "logged", RuleTriggered: "942100"},
		{IP: "203.0.113.2", Action: "blocked", RuleTriggered: ""}, // 非 WAF→丢
	})
	autobanMu.Lock()
	w := autobanWindows["203.0.113.1"]
	_, second := autobanWindows["203.0.113.2"]
	autobanMu.Unlock()
	if w == nil || w.Count != 2 {
		t.Fatalf("批量喂入计数=%+v, want 同 IP 两事件累计 2", w)
	}
	if second {
		t.Fatal("非 WAF 事件不得入计数器")
	}
}

// ---- 计数器修剪：过期桶不产生候选 ----

func TestAutobanCandidates_pruneStaleBuckets(t *testing.T) {
	f := installAutobanFixture(t, "2026-10-14 10:00:00")
	setAutobanConfigRaw(t, true, 1, 5, "1h", "all", true)
	autobanObserveEvent("203.0.113.1", "blocked", "942100")
	f.Advance(6 * time.Minute)
	cands := autobanCandidates(1, 5*time.Minute)
	if len(cands) != 0 {
		t.Fatalf("窗口过期桶不得产生候选，得到 %v", cands)
	}
	autobanMu.Lock()
	_, stillThere := autobanWindows["203.0.113.1"]
	autobanMu.Unlock()
	if stillThere {
		t.Fatal("过期桶应被修剪")
	}
}

// ---- Status 辅助 ----

func TestAutobanBannedToday_countsTodayAutobanEntries(t *testing.T) {
	installAutobanFixture(t, "2026-10-14 10:00:00")
	seedPresetEntries(t, []models.IPListEntry{
		{Value: "198.51.100.1", Remark: AutobanEntryRemark, CreatedAt: "2026-10-14 09:00:00"},
		{Value: "198.51.100.2", Remark: AutobanEntryRemark, CreatedAt: "2026-10-13 09:00:00"},
		{Value: "198.51.100.3", Remark: "事件处置", CreatedAt: "2026-10-14 09:00:00"},
	})
	if n := AutobanBannedToday(); n != 1 {
		t.Fatalf("今日自动封禁数=%d, want 1（仅今日+自动条目）", n)
	}
}

// ---- wire 接线钉：Descriptor 标准七字段 + EnabledFn 业务开关联动 ----

// Given 引擎装配（InitTaskEngine）。
// When 查 autoban 元数据。
// Then 循环族 60s 间隔、主节点角色门、默认调度开、Enabled 随 autoban_enabled。
func TestTaskEngineWire_AutobanDescriptor(t *testing.T) {
	oldDB, oldMetricsDB, oldAuditDB := db.DB, db.MetricsDB, db.AuditDB
	if err := db.Initialize(t.TempDir()); err != nil {
		t.Fatalf("initialize: %v", err)
	}
	t.Cleanup(func() {
		StopTaskEngine()
		_ = db.Close()
		db.DB, db.MetricsDB, db.AuditDB = oldDB, oldMetricsDB, oldAuditDB
	})
	SetConfigLoadRerun(func(operator string) error { return nil })
	t.Cleanup(func() { SetConfigLoadRerun(nil) })
	te := InitTaskEngine("", t.TempDir()+"/app.log")

	m, ok := te.Lookup(AutobanTaskID)
	if !ok {
		t.Fatal("autoban 未注册")
	}
	if m.Kind != "periodic" {
		t.Fatalf("kind=%s, want periodic（固定间隔循环族）", m.Kind)
	}
	if m.IntervalSec != 60 {
		t.Fatalf("interval=%ds, want 60s", m.IntervalSec)
	}
	if !m.LoopOn {
		t.Fatal("默认调度应开启（StartLoop 清单含 autoban）")
	}
	if !m.CanTrigger {
		t.Fatal("循环族应可手动触发")
	}
	// EnabledFn 读 autoban_enabled：默认 0 → 已停止；置 1 → 启用。
	if m.Enabled {
		t.Fatal("autoban_enabled 默认 0 时 Enabled 应为 false（已停止）")
	}
	if _, err := db.DB.Exec(`UPDATE global_config SET autoban_enabled=1 WHERE id=1`); err != nil {
		t.Fatal(err)
	}
	if m2, _ := te.Lookup(AutobanTaskID); !m2.Enabled {
		t.Fatal("autoban_enabled=1 时 Enabled 应为 true")
	}
	if _, err := db.DB.Exec(`UPDATE global_config SET autoban_enabled=0 WHERE id=1`); err != nil {
		t.Fatal(err)
	}
	if m3, _ := te.Lookup(AutobanTaskID); m3.Enabled {
		t.Fatal("autoban_enabled=0 时 Enabled 应回落 false")
	}
}

// Given 读库失败。
// When 查 autoban 元数据。
// Then Enabled=false（fail-closed——与 crs/ip2region 同口径）。
func TestTaskEngineWire_AutobanEnabledFnFailsClosedOnDBError(t *testing.T) {
	te := newWireTestEngine(t)
	swapBrokenDB(t)
	if enabledOf(t, te, AutobanTaskID) {
		t.Fatal("autoban EnabledFn 读库失败应 fail-closed（Enabled=false/已停止），得到 true")
	}
}
