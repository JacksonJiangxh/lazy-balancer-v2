package services

// 规则访问日志的周期兜底：规则删除/导入差集/集群差集三个事件型删除入口任一
// 失败即永久残留（单规则含轮转副本上限约 6×caddy_log_size_mb），故 log-cleanup
// 按「存活规则清单」求差兜底，与 metrics 孤儿清理同构。

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// seedRuleLogFiles 在规则日志目录写入活动文件 + 三形态轮转副本。
func seedRuleLogFiles(t *testing.T, dir, component string) []string {
	t.Helper()
	names := []string{
		component + ".log",
		component + ".log.1",
		component + "-2026-01-02T03-04-05.123-size.log.gz",
	}
	for _, name := range names {
		if err := os.WriteFile(filepath.Join(dir, name), []byte("{}\n"), 0o644); err != nil {
			t.Fatalf("seed rule log %s: %v", name, err)
		}
	}
	return names
}

// Given 存活规则与已删除规则各有一族日志文件，另有一个外来文件。
// When 执行孤儿规则日志清理。
// Then 只删已删除规则的活动文件与全部轮转副本；存活规则与外来文件保留。
func TestPurgeOrphanRuleLogs_deletesRemovedRuleKeepsLiveAndForeign(t *testing.T) {
	_, database := newClusterTestService(t)
	dir := t.TempDir()
	t.Cleanup(SetRuleLogDirForTest(dir))
	if _, err := database.Exec(`INSERT INTO lb_rules (caddy_id,name,protocol,listen_port,enabled) VALUES ('lb_live','live','http',18093,1)`); err != nil {
		t.Fatalf("seed live rule: %v", err)
	}
	liveFiles := seedRuleLogFiles(t, dir, "lb_live")
	orphanFiles := seedRuleLogFiles(t, dir, "lb_gone")
	foreign := filepath.Join(dir, "notes.txt")
	if err := os.WriteFile(foreign, []byte("keep\n"), 0o644); err != nil {
		t.Fatal(err)
	}

	result := PurgeOrphanRuleLogs()

	if result.ScanError != "" {
		t.Fatalf("ScanError=%q, want 空", result.ScanError)
	}
	if len(result.Purged) != 1 || result.Purged[0] != "lb_gone" {
		t.Fatalf("Purged=%v, want [lb_gone]", result.Purged)
	}
	for _, name := range orphanFiles {
		if _, err := os.Stat(filepath.Join(dir, name)); !os.IsNotExist(err) {
			t.Fatalf("孤儿规则日志 %s 未删除（err=%v）", name, err)
		}
	}
	for _, name := range liveFiles {
		if _, err := os.Stat(filepath.Join(dir, name)); err != nil {
			t.Fatalf("存活规则日志 %s 被误删: %v", name, err)
		}
	}
	if _, err := os.Stat(foreign); err != nil {
		t.Fatalf("外来文件被误删: %v", err)
	}
}

// Given 存活规则清单读不出来（lb_rules 不可读）。When 执行孤儿清理。
// Then 一个文件都不删，失败进结果错误面——无法区分「规则已删除」与「清单读
// 不出来」时删除会清掉存活规则的日志。
func TestPurgeOrphanRuleLogs_survivesRuleListReadFailureWithoutDeleting(t *testing.T) {
	_, database := newClusterTestService(t)
	dir := t.TempDir()
	t.Cleanup(SetRuleLogDirForTest(dir))
	names := seedRuleLogFiles(t, dir, "lb_any")
	if _, err := database.Exec(`ALTER TABLE lb_rules RENAME TO lb_rules_unreadable`); err != nil {
		t.Fatalf("注入清单读失败: %v", err)
	}

	result := PurgeOrphanRuleLogs()

	if result.ScanError == "" {
		t.Fatal("存活规则清单读失败必须进 ScanError（不得静默当作无孤儿）")
	}
	if len(result.Purged) != 0 {
		t.Fatalf("清单不可读时不得删除任何文件，实际清理 %v", result.Purged)
	}
	for _, name := range names {
		if _, err := os.Stat(filepath.Join(dir, name)); err != nil {
			t.Fatalf("清单读失败时文件 %s 被误删: %v", name, err)
		}
	}
	if err := (RuntimeCleanupResult{RuleLogs: result}).Err(); err == nil {
		t.Fatal("扫描失败必须进 log-cleanup 错误面（任务落 failed）")
	}
}

// Given 规则日志目录不可写（删除失败）。When 执行孤儿清理。
// Then 失败计数进结果与错误面，摘要不得称完成。
func TestPurgeOrphanRuleLogs_removeFailureSurfaces(t *testing.T) {
	_, database := newClusterTestService(t)
	dir := t.TempDir()
	t.Cleanup(SetRuleLogDirForTest(dir))
	seedRuleLogFiles(t, dir, "lb_stuck")
	if _, err := database.Exec(`INSERT INTO lb_rules (caddy_id,name,protocol,listen_port,enabled) VALUES ('lb_kept','kept','http',18094,1)`); err != nil {
		t.Fatalf("seed live rule: %v", err)
	}
	if err := os.Chmod(dir, 0o500); err != nil {
		t.Fatalf("目录降权: %v", err)
	}
	t.Cleanup(func() { _ = os.Chmod(dir, 0o755) })

	result := PurgeOrphanRuleLogs()

	if result.RemoveFailed == 0 {
		t.Fatalf("删除失败未计数（Purged=%v）", result.Purged)
	}
	if len(result.Purged) != 0 {
		t.Fatalf("删除失败不得计入已清理：%v", result.Purged)
	}
	res := RuntimeCleanupResult{RuleLogs: result}
	if err := res.Err(); err == nil {
		t.Fatal("删除失败必须进 log-cleanup 错误面（任务落 failed）")
	}
	if err := os.Chmod(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	if summary := res.RuleLogs.Summary(); !containsAll(summary, "删除失败", "1 个") {
		t.Fatalf("摘要未披露删除失败：%s", summary)
	}
}

// 规则日志文件名还原：活动文件、移位副本、timberjack 时间戳副本与编码 ID
// 三形态单源；非本族文件返回 false（不得清理）。
func TestRuleLogComponentOf_recognizesLogFamilyShapes(t *testing.T) {
	cases := []struct {
		name      string
		component string
		ok        bool
	}{
		{name: "lb_abc.log", component: "lb_abc", ok: true},
		{name: "lb_abc.log.1", component: "lb_abc", ok: true},
		{name: "lb_abc.log.12.gz", component: "lb_abc", ok: true},
		{name: "lb_abc-2026-01-02T03-04-05.123-size.log", component: "lb_abc", ok: true},
		{name: "lb_abc-2026-01-02T03-04-05-size_1.log.gz", component: "lb_abc", ok: true},
		{name: "lb_abc-123.log", component: "lb_abc-123", ok: true},
		{name: "%6c622e646f74.log", component: "%6c622e646f74", ok: true},
		{name: "notes.txt", component: "", ok: false},
		{name: "lb_abc.log.tmp", component: "", ok: false},
	}
	for _, tc := range cases {
		got, ok := ruleLogComponentOf(tc.name)
		if ok != tc.ok || got != tc.component {
			t.Fatalf("ruleLogComponentOf(%q)=(%q,%v), want (%q,%v)", tc.name, got, ok, tc.component, tc.ok)
		}
	}
	if got := decodeFileComponent("%6c622e646f74"); got != "lb.dot" {
		t.Fatalf("编码主体还原=%q, want lb.dot", got)
	}
}

// containsAll 报告 s 是否包含全部子串（测试断言用）。
func containsAll(s string, subs ...string) bool {
	for _, sub := range subs {
		if !strings.Contains(s, sub) {
			return false
		}
	}
	return true
}
