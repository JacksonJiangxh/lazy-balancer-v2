package atomicfile

import (
	"errors"
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

// swap 临时替换失败注入面，测试结束还原（表驱动共享同一助手，避免每个用例
// 各写一遍 old/restore）。
func swap[T any](t *testing.T, target *T, replacement T) {
	t.Helper()
	old := *target
	*target = replacement
	t.Cleanup(func() { *target = old })
}

// 注入失败后：错误必须上抛（含原始 cause）、目标文件不得出现、目录里不得
// 残留临时文件。这是本原语相对 os.WriteFile 的全部价值——只成功不清理会让
// 盘满/只读挂载事故在磁盘上留下一堆半截 .tmp 制品。
func TestWriteAtomic_failurePathsCleanUp(t *testing.T) {
	injected := errors.New("injected")
	boom := func() error { return injected }

	cases := []struct {
		name   string
		inject func(t *testing.T)
	}{
		{"chmod", func(t *testing.T) {
			swap(t, &fileChmod, func(*os.File, os.FileMode) error { return injected })
		}},
		{"write", func(t *testing.T) {
			swap(t, &fileWrite, func(*os.File, []byte) (int, error) { return 0, injected })
		}},
		{"sync", func(t *testing.T) {
			swap(t, &fileSync, func(*os.File) error { return injected })
		}},
		{"close", func(t *testing.T) {
			swap(t, &fileClose, func(*os.File) error { return injected })
		}},
		{"rename", func(t *testing.T) {
			swap(t, &renamePath, func(string, string) error { return injected })
		}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			tc.inject(t)
			dir := t.TempDir()
			path := filepath.Join(dir, "state.txt")
			err := WriteAtomic(path, []byte("payload"), 0o600)
			if err == nil {
				t.Fatalf("%s 失败未上抛错误", tc.name)
			}
			if !errors.Is(err, boom()) {
				t.Fatalf("%s 错误丢失原始 cause：%v", tc.name, err)
			}
			if _, statErr := os.Stat(path); !os.IsNotExist(statErr) {
				t.Fatalf("%s 失败后目标文件仍存在（stat err=%v）", tc.name, statErr)
			}
			assertNoTemporaryArtifacts(t, dir)
		})
	}
}

// rename 的真实失败形态（不注入）：目标是既有非空目录 → ENOTEMPTY/EISDIR。
// 临时文件已创建，清理必须仍然生效。
func TestWriteAtomic_renameOntoDirectoryCleansTemp(t *testing.T) {
	dir := t.TempDir()
	target := filepath.Join(dir, "state.txt")
	if err := os.MkdirAll(filepath.Join(target, "child"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := WriteAtomic(target, []byte("payload"), 0o600); err == nil {
		t.Fatal("rename onto non-empty directory succeeded")
	}
	assertNoTemporaryArtifacts(t, dir)
}

// 目录 fsync 失败（rename 已生效，仅持久性未确认）：错误必须上抛，不能因为
// 「内容已写好」就吞掉——调用方据此判定新文件名是否持久。
func TestWriteAtomic_parentSyncFailureIsReported(t *testing.T) {
	injected := errors.New("injected dir sync")
	swap(t, &dirSync, func(*os.File) error { return injected })
	dir := t.TempDir()
	path := filepath.Join(dir, "state.txt")
	err := WriteAtomic(path, []byte("payload"), 0o600)
	if err == nil {
		t.Fatal("目录 fsync 失败未上抛错误")
	}
	if !errors.Is(err, injected) {
		t.Fatalf("错误丢失原始 cause：%v", err)
	}
	// rename 已经生效：内容可见，但临时文件必须已被消费（rename 走的是移动，
	// 不留同名制品）。
	assertFile(t, path, "payload", 0o600)
	assertNoTemporaryArtifacts(t, dir)
}
