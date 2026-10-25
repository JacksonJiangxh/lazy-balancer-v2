package services

import (
	"os"
	"path/filepath"
	"testing"
)

// 崩溃窗口第二形态：live 是「非空的部分新树」且 .sync-bak 在场。入口判据
// 只看 live 缺失/为空会漏掉该形态——下一轮先把部分树覆盖成备份（好旧树
// 永久丢失），失败恢复也只能恢复到部分树。声明哈希不符即上次 apply 未完成，
// 必须按备份恢复旧树（旧树优于半新树）。
func TestUntarGzTo_healsPartialNewTreeResidueFromBackup(t *testing.T) {
	root := t.TempDir()
	destDir := filepath.Join(root, "crs")
	writeTestFile(t, filepath.Join(destDir, "rules", "REQUEST-900.conf"), "SecRule old-kept")
	writeTestFile(t, filepath.Join(destDir, "rules", "REQUEST-901-PARTIAL.conf"), "SecRule half-copied")
	writeTestFile(t, filepath.Join(destDir+".sync-bak", "rules", "REQUEST-900.conf"), "SecRule old-kept")
	writeTestFile(t, filepath.Join(destDir+".sync-bak", "rules", crsRulesProbeFile), "SecRule init")

	payload := rawTarGz(t, []tarEntry{
		{name: "rules/REQUEST-901.conf", body: []byte("SecRule new")},
	})
	// 声明哈希与实际不符 → 拒绝落盘（校验门在替换 live 之前）。
	if err := untarGzTo(payload, destDir, "deadbeef"); err == nil {
		t.Fatal("哈希不匹配必须拒绝落盘")
	}

	if _, err := os.Stat(filepath.Join(destDir, "rules", "REQUEST-901-PARTIAL.conf")); !os.IsNotExist(err) {
		t.Fatal("部分新树文件必须被旧树替换（旧树优于半新树）")
	}
	if data, err := os.ReadFile(filepath.Join(destDir, "rules", "REQUEST-900.conf")); err != nil || string(data) != "SecRule old-kept" {
		t.Fatalf("live 必须恢复为备份中的旧树: err=%v data=%q", err, data)
	}
	assertNoStagingRemains(t, destDir)
}

// 备份也可能是残缺的：拷贝中途 ENOSPC/EIO 失败会在 .sync-bak 留下半份旧树。
// 入口自愈必须校验备份完整性（探针文件 + ≥1 .conf），残缺备份按「无备份」
// 处理——否则拿半份备份覆盖仍健康的 live 树，恢复方向反了。
func TestUntarGzTo_doesNotRestoreFromIncompleteBackup(t *testing.T) {
	root := t.TempDir()
	destDir := filepath.Join(root, "crs")
	writeTestFile(t, filepath.Join(destDir, "rules", crsRulesProbeFile), "SecRule init")
	writeTestFile(t, filepath.Join(destDir, "rules", "REQUEST-900.conf"), "SecRule healthy-kept")
	// 半份备份：缺探针文件
	writeTestFile(t, filepath.Join(destDir+".sync-bak", "rules", "REQUEST-900.conf"), "SecRule half-copied")

	payload := rawTarGz(t, []tarEntry{
		{name: "rules/REQUEST-902.conf", body: []byte("SecRule new")},
	})
	// 声明哈希不符 → 本轮拒绝落盘（入口判据先于哈希门执行）。
	if err := untarGzTo(payload, destDir, "deadbeef"); err == nil {
		t.Fatal("哈希不匹配必须拒绝落盘")
	}

	if data, err := os.ReadFile(filepath.Join(destDir, "rules", "REQUEST-900.conf")); err != nil || string(data) != "SecRule healthy-kept" {
		t.Fatalf("残缺备份不得覆盖健康 live 树: err=%v data=%q", err, data)
	}
	if _, err := os.Stat(filepath.Join(destDir, "rules", "REQUEST-902.conf")); !os.IsNotExist(err) {
		t.Fatal("本轮被拒的包内容不得落 live")
	}
}

// 备份构造必须事务化：拷贝中途失败不得留下半份 .sync-bak（下一轮入口会拿它
// 覆盖 live），也不得改动 live 树。
func TestUntarGzTo_backupCopyFailureLeavesNoPartialBackup(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("root 忽略文件权限，无法注入拷贝失败")
	}
	root := t.TempDir()
	destDir := filepath.Join(root, "crs")
	writeTestFile(t, filepath.Join(destDir, "rules", crsRulesProbeFile), "SecRule init")
	unreadable := filepath.Join(destDir, "rules", "zz-broken.conf")
	writeTestFile(t, unreadable, "SecRule x")
	if err := os.Chmod(unreadable, 0000); err != nil {
		t.Fatalf("chmod unreadable: %v", err)
	}
	t.Cleanup(func() { _ = os.Chmod(unreadable, 0644) })

	payload := rawTarGz(t, []tarEntry{
		{name: "rules/REQUEST-902.conf", body: []byte("SecRule new")},
	})
	if err := untarGzTo(payload, destDir, ""); err == nil {
		t.Fatal("备份拷贝失败必须中止本轮")
	}

	if _, err := os.Stat(destDir + ".sync-bak"); !os.IsNotExist(err) {
		t.Fatalf("备份拷贝失败不得留下半份 .sync-bak (err=%v)", err)
	}
	if _, err := os.Stat(destDir + ".sync-bak.tmp"); !os.IsNotExist(err) {
		t.Fatalf("备份事务暂存 .sync-bak.tmp 必须清理 (err=%v)", err)
	}
	if data, err := os.ReadFile(filepath.Join(destDir, "rules", crsRulesProbeFile)); err != nil || string(data) != "SecRule init" {
		t.Fatalf("备份失败不得改动 live: err=%v data=%q", err, data)
	}
	assertNoStagingRemains(t, destDir)
}
