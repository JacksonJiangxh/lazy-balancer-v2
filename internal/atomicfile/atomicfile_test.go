package atomicfile

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// 原子持久化落盘：内容与权限正确、覆盖既有文件、失败不残留临时文件。
func TestWriteAtomic_writesModeAndReplaces(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "state.txt")
	if err := WriteAtomic(path, []byte("first"), 0o600); err != nil {
		t.Fatalf("write: %v", err)
	}
	assertFile(t, path, "first", 0o600)
	if err := WriteAtomic(path, []byte("second"), 0o640); err != nil {
		t.Fatalf("rewrite: %v", err)
	}
	assertFile(t, path, "second", 0o640)
	assertNoTemporaryArtifacts(t, dir)
}

// 目标目录不存在必须在创建临时文件阶段失败，不得静默落到当前目录或残留制品。
func TestWriteAtomic_missingDirFailsWithoutArtifacts(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "missing", "state.txt")
	err := WriteAtomic(path, []byte("x"), 0o600)
	if err == nil {
		t.Fatal("write into missing directory succeeded")
	}
	entries, readErr := os.ReadDir(dir)
	if readErr != nil {
		t.Fatalf("read dir: %v", readErr)
	}
	if len(entries) != 0 {
		t.Fatalf("entries=%v, want 空目录（失败路径不得留下制品）", entries)
	}
}

// 父目录 fsync 是 rename 后的必要一步：目录打不开必须返回错误（调用方据此
// 判定「新文件名尚未持久」）。
func TestSyncParent_missingDirFails(t *testing.T) {
	if err := SyncParent(filepath.Join(t.TempDir(), "missing", "state.txt")); err == nil {
		t.Fatal("sync of missing parent directory succeeded")
	}
}

func assertFile(t *testing.T, path, content string, mode os.FileMode) {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read %s: %v", path, err)
	}
	if string(data) != content {
		t.Fatalf("%s=%q, want %q", path, string(data), content)
	}
	info, err := os.Stat(path)
	if err != nil {
		t.Fatalf("stat %s: %v", path, err)
	}
	if got := info.Mode().Perm(); got != mode {
		t.Fatalf("%s mode=%#o, want %#o", path, got, mode)
	}
}

func assertNoTemporaryArtifacts(t *testing.T, dir string) {
	t.Helper()
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatalf("read dir: %v", err)
	}
	for _, entry := range entries {
		if strings.HasSuffix(entry.Name(), ".tmp") {
			t.Fatalf("leftover temporary artifact %q", entry.Name())
		}
	}
}
