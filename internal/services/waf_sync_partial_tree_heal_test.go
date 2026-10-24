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
