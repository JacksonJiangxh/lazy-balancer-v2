package services

import (
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
)

// VERSION 标记是 planCRSReconcile 的权威输入：裸 os.WriteFile 的崩溃窗口会
// 留下 0 字节/半截内容，让下一次启动的对账基于错误版本选方向。原子写
// （tmp+fsync+rename）保证「要么旧值完整、要么新值完整」，且替换换 inode
// （原地截断写保持同一 inode，崩溃即截断）。
func TestWriteCRSVersionMarker_atomicAndReadable(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, crsVersionFile)
	writeCRSVersionMarker(dir, "v4.14.0")
	if got := readCRSVersionMarker(dir); got != "v4.14.0" {
		t.Fatalf("marker=%q, want v4.14.0", got)
	}

	inode := func() uint64 {
		t.Helper()
		info, err := os.Stat(path)
		if err != nil {
			t.Fatalf("stat marker: %v", err)
		}
		st, ok := info.Sys().(*syscall.Stat_t)
		if !ok {
			t.Skip("平台无 syscall.Stat_t，跳过 inode 口径")
		}
		return st.Ino
	}
	before := inode()
	writeCRSVersionMarker(dir, "v4.15.0")
	if got := readCRSVersionMarker(dir); got != "v4.15.0" {
		t.Fatalf("marker=%q, want v4.15.0（覆盖写必须生效）", got)
	}
	if after := inode(); after == before {
		t.Fatalf("marker 写入未更换 inode（原地截断写会在中途崩溃留下半截 VERSION）")
	}

	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	for _, entry := range entries {
		if strings.HasPrefix(entry.Name(), ".") {
			t.Fatalf("原子写不得留下临时文件: %s", entry.Name())
		}
	}

	// 失败形态：目录不可写时旧标记必须原样保留（不得出现空/半截文件）。
	if os.Geteuid() == 0 {
		t.Skip("root 忽略目录权限位，无法构造写失败形态")
	}
	if err := os.Chmod(dir, 0o555); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Chmod(dir, 0o755) })
	writeCRSVersionMarker(dir, "v9.9.9")
	if got := readCRSVersionMarker(dir); got != "v4.15.0" {
		t.Fatalf("写失败后 marker=%q, want 旧值 v4.15.0（不得截断/清空）", got)
	}
}
