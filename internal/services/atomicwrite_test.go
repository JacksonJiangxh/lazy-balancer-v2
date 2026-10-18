package services

import (
	"os"
	"path/filepath"
	"testing"
)

// D1-历史问题 单源原子落盘 helper：写入内容/权限、覆盖既有文件、失败清理。
func TestWriteFileAtomicSynced_WritesAndReplaces(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "artifact.json")

	if err := writeFileAtomicSynced(path, []byte("first"), 0o600); err != nil {
		t.Fatalf("first atomic write: %v", err)
	}
	if raw, err := os.ReadFile(path); err != nil || string(raw) != "first" {
		t.Fatalf("content=%q err=%v, want first", raw, err)
	}
	if info, err := os.Stat(path); err != nil || info.Mode().Perm() != 0o600 {
		t.Fatalf("mode=%v err=%v, want 0600", infoMode(info), err)
	}

	// 覆盖既有文件：内容与权限都随新写入生效，且不留临时文件。
	if err := writeFileAtomicSynced(path, []byte("second"), 0o644); err != nil {
		t.Fatalf("replace atomic write: %v", err)
	}
	if raw, err := os.ReadFile(path); err != nil || string(raw) != "second" {
		t.Fatalf("content=%q err=%v, want second", raw, err)
	}
	if info, err := os.Stat(path); err != nil || info.Mode().Perm() != 0o644 {
		t.Fatalf("mode=%v err=%v, want 0644", infoMode(info), err)
	}
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatalf("read dir: %v", err)
	}
	if len(entries) != 1 || entries[0].Name() != "artifact.json" {
		t.Fatalf("leftover temp files: %v", entries)
	}
}

func infoMode(info os.FileInfo) os.FileMode {
	if info == nil {
		return 0
	}
	return info.Mode().Perm()
}

// 目标目录不存在时必须在创建临时文件阶段失败（不静默落到当前目录）。
func TestWriteFileAtomicSynced_MissingDirFails(t *testing.T) {
	path := filepath.Join(t.TempDir(), "missing", "artifact.json")
	if err := writeFileAtomicSynced(path, []byte("x"), 0o644); err == nil {
		t.Fatal("missing parent directory must fail")
	}
}

// 真实调用点：安全事件采集偏移的原子落盘 round-trip（读回 + 无 .tmp 残留）。
func TestSecurityEventsWriteOffset_AtomicRoundTrip(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "audit.offset")
	if err := securityEventsWriteOffset(path, 12345); err != nil {
		t.Fatalf("write offset: %v", err)
	}
	if got, err := securityEventsReadOffset(path); err != nil || got != 12345 {
		t.Fatalf("offset=%d err=%v, want 12345", got, err)
	}
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatalf("read dir: %v", err)
	}
	if len(entries) != 1 || entries[0].Name() != "audit.offset" {
		t.Fatalf("leftover temp files: %v", entries)
	}
}
