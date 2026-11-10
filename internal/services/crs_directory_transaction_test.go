package services

import (
	"errors"
	"os"
	"path/filepath"
	"testing"
)

func writeDirectoryTransactionFile(t *testing.T, path, content string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}
}

// live 树替换的新树 rename 失败时，旧树必须复位，完整暂存树保留供诊断。
func TestCRSReplaceDir_replaceRenameFailureRestoresOldTree(t *testing.T) {
	root := t.TempDir()
	src := filepath.Join(root, "snapshot-rules")
	dst := filepath.Join(root, "live", "rules")
	writeDirectoryTransactionFile(t, filepath.Join(src, crsRulesProbeFile), "SecRule new")
	writeDirectoryTransactionFile(t, filepath.Join(dst, crsRulesProbeFile), "SecRule old")

	oldRename := osRename
	osRename = func(src, target string) error {
		if src == dst+".tmp" && target == dst {
			return errors.New("rename boom")
		}
		return oldRename(src, target)
	}
	t.Cleanup(func() { osRename = oldRename })

	if err := replaceDirFromInWindow(src, dst); err == nil {
		t.Fatal("新树 rename 失败必须返回错误")
	}
	data, err := os.ReadFile(filepath.Join(dst, crsRulesProbeFile))
	if err != nil || string(data) != "SecRule old" {
		t.Fatalf("旧 live 树必须完整复位: err=%v data=%q", err, data)
	}
	if _, err := os.Stat(dst + ".old"); !os.IsNotExist(err) {
		t.Fatalf("复位成功后不得残留 .old: stat err=%v", err)
	}
	fresh, err := os.ReadFile(filepath.Join(dst+".tmp", crsRulesProbeFile))
	if err != nil || string(fresh) != "SecRule new" {
		t.Fatalf("完整新树必须保留在 .tmp 供诊断: err=%v data=%q", err, fresh)
	}
}

// 回滚失败后 .old 是唯一旧树；重试不得把它当普通残骸删除。
func TestCRSReplaceDir_retryAfterRestoreFailureKeepsRecoverableTree(t *testing.T) {
	root := t.TempDir()
	src := filepath.Join(root, "snapshot-rules")
	dst := filepath.Join(root, "live", "rules")
	writeDirectoryTransactionFile(t, filepath.Join(src, crsRulesProbeFile), "SecRule new")
	writeDirectoryTransactionFile(t, filepath.Join(dst, crsRulesProbeFile), "SecRule old")

	oldRename := osRename
	restoreFails := true
	osRename = func(src, target string) error {
		if src == dst+".tmp" && target == dst {
			return errors.New("install boom")
		}
		if src == dst+".old" && target == dst && restoreFails {
			return errors.New("restore boom")
		}
		return oldRename(src, target)
	}
	t.Cleanup(func() { osRename = oldRename })

	if err := replaceDirFromInWindow(src, dst); err == nil {
		t.Fatal("首次替换与回滚失败必须返回错误")
	}
	if _, err := os.Stat(dst); !os.IsNotExist(err) {
		t.Fatalf("回滚失败时 dst 应保持缺失: stat err=%v", err)
	}
	data, err := os.ReadFile(filepath.Join(dst+".old", crsRulesProbeFile))
	if err != nil || string(data) != "SecRule old" {
		t.Fatalf("回滚失败后旧树必须保留在 .old: err=%v data=%q", err, data)
	}

	restoreFails = false
	if err := replaceDirFromInWindow(src, dst); err == nil {
		t.Fatal("重试的新树 rename 仍失败，必须返回错误")
	}
	data, err = os.ReadFile(filepath.Join(dst, crsRulesProbeFile))
	if err != nil || string(data) != "SecRule old" {
		t.Fatalf("重试必须从既有 .old 恢复旧树: err=%v data=%q", err, data)
	}
	fresh, err := os.ReadFile(filepath.Join(dst+".tmp", crsRulesProbeFile))
	if err != nil || string(fresh) != "SecRule new" {
		t.Fatalf("重试失败后完整新树仍须保留: err=%v data=%q", err, fresh)
	}
}

// 旧树移至 .old 失败时必须中止，dst 原样保留且暂存树不残留。
func TestCRSReplaceDir_staleRenameFailureKeepsOldTree(t *testing.T) {
	root := t.TempDir()
	src := filepath.Join(root, "snapshot-rules")
	dst := filepath.Join(root, "live", "rules")
	writeDirectoryTransactionFile(t, filepath.Join(src, crsRulesProbeFile), "SecRule new")
	writeDirectoryTransactionFile(t, filepath.Join(dst, crsRulesProbeFile), "SecRule old")

	oldRename := osRename
	osRename = func(src, target string) error {
		if src == dst && target == dst+".old" {
			return errors.New("rename boom")
		}
		return oldRename(src, target)
	}
	t.Cleanup(func() { osRename = oldRename })

	if err := replaceDirFromInWindow(src, dst); err == nil {
		t.Fatal("旧树 rename 失败必须中止替换")
	}
	data, err := os.ReadFile(filepath.Join(dst, crsRulesProbeFile))
	if err != nil || string(data) != "SecRule old" {
		t.Fatalf("旧树 rename 失败不得改动 dst: err=%v data=%q", err, data)
	}
	for _, path := range []string{dst + ".tmp", dst + ".old"} {
		if _, err := os.Stat(path); !os.IsNotExist(err) {
			t.Fatalf("第一步 rename 失败不得残留 %s: stat err=%v", path, err)
		}
	}
}

// 成功换入新树后清理本次旧树与上一运行残留的 .old。
func TestCRSReplaceDir_successRemovesOldTree(t *testing.T) {
	root := t.TempDir()
	src := filepath.Join(root, "snapshot-rules")
	dst := filepath.Join(root, "live", "rules")
	writeDirectoryTransactionFile(t, filepath.Join(src, crsRulesProbeFile), "SecRule new")
	writeDirectoryTransactionFile(t, filepath.Join(dst, crsRulesProbeFile), "SecRule old")
	writeDirectoryTransactionFile(t, filepath.Join(dst+".old", "stale.conf"), "SecRule stale")

	if err := replaceDirFromInWindow(src, dst); err != nil {
		t.Fatalf("replace: %v", err)
	}
	data, err := os.ReadFile(filepath.Join(dst, crsRulesProbeFile))
	if err != nil || string(data) != "SecRule new" {
		t.Fatalf("新树必须完整生效: err=%v data=%q", err, data)
	}
	for _, path := range []string{dst + ".tmp", dst + ".old"} {
		if _, err := os.Stat(path); !os.IsNotExist(err) {
			t.Fatalf("成功路径不得残留 %s: stat err=%v", path, err)
		}
	}
}
