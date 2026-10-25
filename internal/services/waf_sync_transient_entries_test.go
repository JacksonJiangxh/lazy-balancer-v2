package services

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"io"
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

// tarNames 解出 tar.gz 包内的条目名（打包集断言的测试缝）。
func tarNames(t *testing.T, data []byte) []string {
	t.Helper()
	gz, err := gzip.NewReader(bytes.NewReader(data))
	if err != nil {
		t.Fatalf("gzip: %v", err)
	}
	tr := tar.NewReader(gz)
	var names []string
	for {
		hdr, err := tr.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			t.Fatalf("tar next: %v", err)
		}
		names = append(names, hdr.Name)
	}
	return names
}

// 目录形备份树（rules.bak/x.conf）必须在**每一段**命中谓词：整串后缀判定对
// 子文件不成立，会让打包收入该子树而清残按目录段整棵删除 → 两端哈希恒不等
// （从节点 WAF 永不收敛，lbbak 导入同样失败）。
func TestSkipWafSyncTransient_directoryForm(t *testing.T) {
	cases := map[string]bool{
		"rules.bak/x.conf":             true,
		"rules/x.conf.old":             true,
		"crs-setup.conf.bak":           true,
		"nested/rules.bak/deep/x.conf": true,
		".sync-in/x.conf":              true,
		"rules/REQUEST-900.conf":       false,
		"rules/bak/x.conf":             false, // 仅点前缀/后缀命中，名中段不算
		"crs-setup.conf":               false,
	}
	for rel, want := range cases {
		if got := skipWafSyncTransient(rel); got != want {
			t.Errorf("skipWafSyncTransient(%q)=%v, want %v", rel, got, want)
		}
	}
}

// 打包侧与清残侧必须同谓词：目录形备份树既不进 tar，也不残留 staging。
func TestWafSync_directoryFormBackupTreeExcluded(t *testing.T) {
	root := t.TempDir()
	writeTestFile(t, filepath.Join(root, "rules", "REQUEST-900.conf"), "SecRule keep")
	writeTestFile(t, filepath.Join(root, "rules.bak", "REQUEST-900.conf"), "SecRule stale")
	writeTestFile(t, filepath.Join(root, "rules.old", "REQUEST-901.conf"), "SecRule stale")

	data, sum, err := tarGzDir(root)
	if err != nil {
		t.Fatalf("tarGzDir: %v", err)
	}
	if sum == "" {
		t.Fatal("tarGzDirSum 哈希缺失")
	}
	names := tarNames(t, data)
	for _, name := range names {
		if strings.Contains(name, ".bak") || strings.Contains(name, ".old") {
			t.Fatalf("打包收入目录形备份树条目 %q（names=%v）", name, names)
		}
	}
	if len(names) != 1 || names[0] != "rules/REQUEST-900.conf" {
		t.Fatalf("打包条目=%v, want 仅正式规则文件", names)
	}

	// 解包侧同一谓词：目录形条目整包拒绝。
	destDir := t.TempDir()
	pkg := rawTarGz(t, []tarEntry{{name: "rules.bak/x.conf", body: []byte("SecRule X EVIL")}})
	if err := untarGzTo(pkg, destDir, ""); err == nil || !strings.Contains(err.Error(), "瞬态路径") {
		t.Fatalf("error=%v, want transient-path rejection for directory-form backup tree", err)
	}
	assertNoStagingRemains(t, destDir)

	// 清残侧整棵删除。
	if err := removeTransientWafSyncPaths(root); err != nil {
		t.Fatalf("removeTransientWafSyncPaths: %v", err)
	}
	for _, gone := range []string{"rules.bak", "rules.old"} {
		if _, err := os.Stat(filepath.Join(root, gone)); !os.IsNotExist(err) {
			t.Errorf("目录形备份树 %q 未被剔除: %v", gone, err)
		}
	}
	if _, err := os.Stat(filepath.Join(root, "rules", "REQUEST-900.conf")); err != nil {
		t.Errorf("正式规则文件不得被剔除: %v", err)
	}
}
