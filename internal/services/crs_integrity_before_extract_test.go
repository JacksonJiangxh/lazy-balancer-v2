package services

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"testing"
)

// TOFU 比对必须先于解包：否则被劫持/损坏的工件会先展开到数据卷（上限
// 500MB）才被否决，磁盘/CPU 放大且发现点远离真实原因。非归档字节的
// 「同 tag 新内容」必须以完整性错误中止，而不是解压错误。
func TestCRSUpdateRun_integrityMismatchPrecedesExtraction(t *testing.T) {
	m := newTestCRSManager(t)
	seedCRSVersionRow(t, "v4.14.0", true)
	writeTestFile(t, filepath.Join(m.crsDir, "rules", crsRulesProbeFile), "SecRule init")
	writeTestFile(t, filepath.Join(m.crsDir, "crs-setup.conf"), "# setup")

	m.downloadTarball = fakeCRSDownload(t, map[string]string{
		"coreruleset-4.15.0/crs-setup.conf.example":     "# setup-v1",
		"coreruleset-4.15.0/rules/" + crsRulesProbeFile: "# init probe\n",
	})
	if err := m.downloadAndInstall(context.Background(), "v4.15.0"); err != nil {
		t.Fatalf("首次安装应成功（建立 TOFU 基线）: %v", err)
	}

	// 同 tag 第二次下载：字节既非归档也不匹配基线。
	m.downloadTarball = func(_ context.Context, _ string, destPath string, _ downloadProgressFunc) error {
		return os.WriteFile(destPath, []byte("not-a-crs-tarball"), 0o644)
	}
	err := m.downloadAndInstall(context.Background(), "v4.15.0")
	if !errors.Is(err, errDownloadIntegrityMismatch) {
		t.Fatalf("err=%v, want errDownloadIntegrityMismatch（基线比对必须发生在解包之前）", err)
	}
}
