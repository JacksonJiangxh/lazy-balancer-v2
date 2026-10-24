package services

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// CRS 重载失败回滚若未能完整还原规则树，不得无条件把 VERSION 标记
// 与 DB 版本行回写成 prevTag——那会制造「live 新树 + 旧版本」跨代态（版本行
// 是 crsPoolFingerprint 的池键输入）。此时保留更新后的版本并落 ERROR 留痕。
func TestCRSRollback_skipsVersionRowWhenTreeNotRestored(t *testing.T) {
	m := newTestCRSManager(t)
	seedCRSVersionRow(t, "v4.14.0", true)
	// live 规则树退化（缺探针文件）：本运行备份随之退化，restoreRulesBackup
	// 按既有退化门拒绝还原——回滚只能停留在新树上。
	writeTestFile(t, filepath.Join(m.crsDir, "rules", "REQUEST-900.conf"), "SecRule legacy-without-probe")

	m.fetchLatestTag = func(context.Context) (string, error) { return "v4.15.0", nil }
	m.downloadTarball = fakeCRSDownload(t, map[string]string{
		"coreruleset-4.15.0/crs-setup.conf.example":     "# new setup",
		"coreruleset-4.15.0/rules/" + crsRulesProbeFile: "# init probe\n",
		"coreruleset-4.15.0/rules/REQUEST-941.conf":     "SecRule c\n",
	})
	m.reloader = func() error { return errors.New("reload boom") }

	m.run("manual", nil)

	if _, status, _, _, _, _, _ := crsVersionRow(t); status != "failed" {
		t.Fatalf("update_status=%q, want failed", status)
	}
	// 树未被还原（仍是新树）→ 版本行必须与新树同代，不得回写 prevTag。
	if version, _, _, _, _, _, _ := crsVersionRow(t); version != "v4.15.0" {
		t.Fatalf("version=%q, want v4.15.0（树未还原时不得把版本行回写为旧 tag，避免跨代态）", version)
	}
	if data, err := os.ReadFile(filepath.Join(m.crsDir, "rules", "REQUEST-941.conf")); err != nil || !strings.Contains(string(data), "SecRule c") {
		t.Fatalf("live rules 应仍为本次安装的新树: err=%v data=%q", err, data)
	}
}

// 备份创建失败时不得丢失上一运行崩溃现场残留的 rules.bak
// （唯一恢复素材）。旧实现在安装段前无条件 RemoveAll(rules.bak)。
func TestCRSBackupFailure_preservesStaleRulesBak(t *testing.T) {
	m := newTestCRSManager(t)
	seedCRSVersionRow(t, "v4.14.0", true)
	// live 规则树含悬空符号链接 → 本运行备份拷贝必失败
	writeTestFile(t, filepath.Join(m.crsDir, "rules", "REQUEST-900.conf"), "SecRule a")
	if err := os.Symlink("missing-target", filepath.Join(m.crsDir, "rules", "REQUEST-901.conf")); err != nil {
		t.Fatal(err)
	}
	staleBak := crsTransientPath(m.crsDir, "rules.bak")
	writeTestFile(t, filepath.Join(staleBak, crsRulesProbeFile), "SecRule stale-crash-site")

	m.fetchLatestTag = func(context.Context) (string, error) { return "v4.15.0", nil }
	m.downloadTarball = fakeCRSDownload(t, map[string]string{
		"coreruleset-4.15.0/crs-setup.conf.example":     "# new setup",
		"coreruleset-4.15.0/rules/" + crsRulesProbeFile: "# init probe\n",
	})
	m.reloader = func() error { return nil }

	m.run("manual", nil)

	if _, status, _, _, _, _, _ := crsVersionRow(t); status != "failed" {
		t.Fatalf("update_status=%q, want failed", status)
	}
	data, err := os.ReadFile(filepath.Join(staleBak, crsRulesProbeFile))
	if err != nil {
		t.Fatalf("陈旧 rules.bak 不得被删除（崩溃现场唯一恢复素材）: %v", err)
	}
	if string(data) != "SecRule stale-crash-site" {
		t.Fatalf("stale rules.bak content=%q, want 原样保全", data)
	}
}

// 快照持久化必须先构建完成再替换——拷贝中途失败时旧快照必须保持
// 完整（旧实现先 RemoveAll(snapshotDir) 再逐项 copy）。
func TestPersistCRSSnapshot_failureKeepsPreviousSnapshot(t *testing.T) {
	liveDir := t.TempDir()
	snapshotDir := filepath.Join(t.TempDir(), "snapshot")
	writeTestFile(t, filepath.Join(liveDir, "rules", crsRulesProbeFile), "SecRule new")
	writeTestFile(t, filepath.Join(liveDir, crsVersionFile), "v4.15.0\n")
	if err := os.Symlink("missing-target", filepath.Join(liveDir, "rules", "REQUEST-941.conf")); err != nil {
		t.Fatal(err)
	}
	writeTestFile(t, filepath.Join(snapshotDir, "rules", crsRulesProbeFile), "SecRule previous")
	writeTestFile(t, filepath.Join(snapshotDir, crsVersionFile), "v4.14.0\n")

	if err := persistCRSSnapshotFrom(liveDir, snapshotDir, "v4.15.0"); err == nil {
		t.Fatal("persist snapshot 应因悬空符号链接失败")
	}

	data, err := os.ReadFile(filepath.Join(snapshotDir, "rules", crsRulesProbeFile))
	if err != nil || string(data) != "SecRule previous" {
		t.Fatalf("旧快照必须保持完整: err=%v data=%q", err, data)
	}
	if marker, err := os.ReadFile(filepath.Join(snapshotDir, crsVersionFile)); err != nil || strings.TrimSpace(string(marker)) != "v4.14.0" {
		t.Fatalf("旧快照版本标记不得被半成品覆盖: err=%v marker=%q", err, marker)
	}
}

// 同族：快照恢复必须先完整拷贝再替换 live rules——中途失败不得留下
// 半树或空树（旧实现先 RemoveAll(live/rules) 再 copyDir）。
func TestRestoreCRSFromSnapshot_failureKeepsLiveTree(t *testing.T) {
	liveDir := t.TempDir()
	snapshotDir := t.TempDir()
	writeTestFile(t, filepath.Join(liveDir, "rules", crsRulesProbeFile), "SecRule live")
	writeTestFile(t, filepath.Join(liveDir, "rules", "REQUEST-900.conf"), "SecRule live-900")
	writeTestFile(t, filepath.Join(snapshotDir, "rules", crsRulesProbeFile), "SecRule snap")
	if err := os.Symlink("missing-target", filepath.Join(snapshotDir, "rules", "REQUEST-941.conf")); err != nil {
		t.Fatal(err)
	}

	if err := restoreCRSFromSnapshot(liveDir, snapshotDir, "v4.14.0"); err == nil {
		t.Fatal("restore 应因快照内悬空符号链接失败")
	}

	for _, name := range []string{crsRulesProbeFile, "REQUEST-900.conf"} {
		if _, err := os.Stat(filepath.Join(liveDir, "rules", name)); err != nil {
			t.Fatalf("live rules %s 必须在恢复失败后保持原样: %v", name, err)
		}
	}
	if data, _ := os.ReadFile(filepath.Join(liveDir, "rules", crsRulesProbeFile)); string(data) != "SecRule live" {
		t.Fatalf("live rules 被半成品替换: %q", data)
	}
}

// 规则数缓存必须可跨通道失效（集群同步 / 备份导入替换 live 树后）。
func TestCRSManager_InvalidateRuleCount_rescans(t *testing.T) {
	m := newTestCRSManager(t)
	writeTestFile(t, filepath.Join(m.crsDir, "rules", "REQUEST-901.conf"), "SecRule a\nSecRule b\n")
	if got := m.RuleCount(); got != 2 {
		t.Fatalf("RuleCount=%d, want 2", got)
	}

	// 带外树替换（模拟集群同步 / 导入）
	writeTestFile(t, filepath.Join(m.crsDir, "rules", "REQUEST-942.conf"), "SecRule c\n")

	m.InvalidateRuleCount()

	if got := m.RuleCount(); got != 3 {
		t.Fatalf("RuleCount=%d, want 3（失效后必须重扫，不得滞留旧值）", got)
	}
}

// 快照替换阶段 rename 失败不得同时丢失两份快照：旧实现在 RemoveAll(snapshot)
// 之后 rename 失败即 cleanupTmp()——旧快照已删、完整新树被清理，两份皆失，
// 容器重建回退镜像捆绑版本且快照缺席不会自愈。两阶段替换下失败时旧快照
// （.old）与完整新树（.tmp）都必须留在盘上。
func TestPersistCRSSnapshot_replaceRenameFailureKeepsBothCopies(t *testing.T) {
	liveDir := t.TempDir()
	snapshotDir := filepath.Join(t.TempDir(), "snapshot")
	writeTestFile(t, filepath.Join(liveDir, "rules", crsRulesProbeFile), "SecRule new")
	writeTestFile(t, filepath.Join(liveDir, crsVersionFile), "v4.15.0\n")
	writeTestFile(t, filepath.Join(snapshotDir, "rules", crsRulesProbeFile), "SecRule previous")
	writeTestFile(t, filepath.Join(snapshotDir, crsVersionFile), "v4.14.0\n")

	oldRename := osRename
	osRename = func(src, dst string) error {
		if dst == snapshotDir {
			return errors.New("rename boom")
		}
		return oldRename(src, dst)
	}
	t.Cleanup(func() { osRename = oldRename })

	if err := persistCRSSnapshotFrom(liveDir, snapshotDir, "v4.15.0"); err == nil {
		t.Fatal("替换阶段 rename 失败必须返回错误（不得静默成功）")
	}
	prev, err := os.ReadFile(filepath.Join(snapshotDir+".old", "rules", crsRulesProbeFile))
	if err != nil || string(prev) != "SecRule previous" {
		t.Fatalf("旧快照必须保留在 .old: err=%v data=%q", err, prev)
	}
	fresh, err := os.ReadFile(filepath.Join(snapshotDir+".tmp", "rules", crsRulesProbeFile))
	if err != nil || string(fresh) != "SecRule new" {
		t.Fatalf("完整新快照必须保留在 .tmp（不得被 cleanup 删除）: err=%v data=%q", err, fresh)
	}
}

// 两阶段替换的第一步（旧快照改名到 .old）失败时旧快照必须原封不动，暂存
// 目录清理干净——不得留下「旧快照已移走」的半途态。
func TestPersistCRSSnapshot_staleRenameFailureKeepsSnapshot(t *testing.T) {
	liveDir := t.TempDir()
	snapshotDir := filepath.Join(t.TempDir(), "snapshot")
	writeTestFile(t, filepath.Join(liveDir, "rules", crsRulesProbeFile), "SecRule new")
	writeTestFile(t, filepath.Join(liveDir, crsVersionFile), "v4.15.0\n")
	writeTestFile(t, filepath.Join(snapshotDir, "rules", crsRulesProbeFile), "SecRule previous")

	oldRename := osRename
	osRename = func(src, dst string) error {
		if dst == snapshotDir+".old" {
			return errors.New("rename boom")
		}
		return oldRename(src, dst)
	}
	t.Cleanup(func() { osRename = oldRename })

	if err := persistCRSSnapshotFrom(liveDir, snapshotDir, "v4.15.0"); err == nil {
		t.Fatal("旧快照改名失败必须返回错误")
	}
	prev, err := os.ReadFile(filepath.Join(snapshotDir, "rules", crsRulesProbeFile))
	if err != nil || string(prev) != "SecRule previous" {
		t.Fatalf("旧快照必须原封不动: err=%v data=%q", err, prev)
	}
	if _, err := os.Stat(snapshotDir + ".tmp"); !os.IsNotExist(err) {
		t.Fatalf("暂存目录应已清理: stat err=%v", err)
	}
	if _, err := os.Stat(snapshotDir + ".old"); !os.IsNotExist(err) {
		t.Fatalf("改名失败不得留下 .old: stat err=%v", err)
	}
}
