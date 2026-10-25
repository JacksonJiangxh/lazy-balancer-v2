package services

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// 解包写入的条目集必须与打包/整树哈希/漂移判定同一谓词：包内瞬态命名
// （点前缀任意段、*.bak/*.old）若被写入 staging，会进入 live 树却不参与声明
// 哈希与漂移检测——coraza 的 Include glob 会匹配点前缀 .conf，等于绕开哈希门
// 注入规则。与打包侧同谓词拒绝使「门覆盖集 = 打包集」成为结构性不变量。
func TestUntarGzTo_rejectsTransientEntries(t *testing.T) {
	cases := []string{
		".hidden.conf",
		"rules/.hidden.conf",
		"rules/REQUEST-900.conf.bak",
		"rules/REQUEST-900.old",
		".staging/nested.conf",
	}
	for _, name := range cases {
		t.Run(name, func(t *testing.T) {
			destDir := t.TempDir()
			data := rawTarGz(t, []tarEntry{{name: name, body: []byte("SecRule X EVIL")}})
			err := untarGzTo(data, destDir, "")
			if err == nil || !strings.Contains(err.Error(), "瞬态路径") {
				t.Fatalf("error=%v, want transient-path rejection", err)
			}
			assertNoStagingRemains(t, destDir)
			if _, statErr := os.Stat(filepath.Join(destDir, filepath.FromSlash(name))); statErr == nil {
				t.Fatalf("瞬态条目 %q 不得落盘", name)
			}
		})
	}
}

// 上一轮 staging 清理失败留下的瞬态残留会被整树搬到 live：落 live 前必须按
// 同一谓词剔除（哈希覆盖集 == 打包集 == live 集）。
func TestRemoveTransientWafSyncPaths_stripsOnlyTransient(t *testing.T) {
	root := t.TempDir()
	writeTestFile(t, filepath.Join(root, ".hidden.conf"), "SecRule hidden")
	writeTestFile(t, filepath.Join(root, "rules", "REQUEST-900.conf.bak"), "SecRule bak")
	writeTestFile(t, filepath.Join(root, "rules", "REQUEST-901.old"), "SecRule old")
	writeTestFile(t, filepath.Join(root, ".staging", "nested.conf"), "SecRule nested")
	writeTestFile(t, filepath.Join(root, "rules", "REQUEST-900.conf"), "SecRule keep")
	writeTestFile(t, filepath.Join(root, "crs-setup.conf"), "# keep")

	if err := removeTransientWafSyncPaths(root); err != nil {
		t.Fatalf("removeTransientWafSyncPaths: %v", err)
	}

	for _, gone := range []string{
		".hidden.conf",
		"rules/REQUEST-900.conf.bak",
		"rules/REQUEST-901.old",
		".staging",
	} {
		if _, err := os.Stat(filepath.Join(root, filepath.FromSlash(gone))); !os.IsNotExist(err) {
			t.Errorf("瞬态路径 %q 未被剔除: %v", gone, err)
		}
	}
	for _, kept := range []string{"rules/REQUEST-900.conf", "crs-setup.conf"} {
		if _, err := os.Stat(filepath.Join(root, filepath.FromSlash(kept))); err != nil {
			t.Errorf("正常文件 %q 不得被剔除: %v", kept, err)
		}
	}
}
