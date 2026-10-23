package services

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"lazy-balancer-v2/wafiplist"
)

// 单源原子落盘 helper：写入内容/权限、覆盖既有文件、失败清理。
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

// 真实调用点：IP 名单投影回滚恢复真实文件并清理新增文件，不留临时制品。
func TestRestoreIPListProjections_restoresRealFilesWithoutTempArtifacts(t *testing.T) {
	// Given a snapshot, then a render that rewrites one projection and adds another.
	dir := t.TempDir()
	oldDir := IPListDataDir
	IPListDataDir = dir
	t.Cleanup(func() { IPListDataDir = oldDir })
	existing := filepath.Join(dir, "p1-acl.txt")
	if err := os.WriteFile(existing, []byte("old\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	snapshot := SnapshotIPListProjections()
	if err := os.WriteFile(existing, []byte("new-render\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	added := filepath.Join(dir, "p2-acl.txt")
	if err := os.WriteFile(added, []byte("added\n"), 0o644); err != nil {
		t.Fatal(err)
	}

	// When CLI validation fails and the projection snapshot is restored.
	if err := RestoreIPListProjections(snapshot); err != nil {
		t.Fatalf("restore must report clean rollback: %v", err)
	}

	// Then original bytes return, the new projection disappears, and atomic
	// writes leave no temporary artifacts.
	if raw, err := os.ReadFile(existing); err != nil || string(raw) != "old\n" {
		t.Fatalf("restored content=%q err=%v, want old", raw, err)
	}
	if _, err := os.Stat(added); !os.IsNotExist(err) {
		t.Fatalf("new projection must be removed, stat err=%v", err)
	}
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 1 || entries[0].Name() != "p1-acl.txt" {
		t.Fatalf("restore left unexpected files: %v", entries)
	}
}

// 回滚失败必须可上报（调用方写 error 日志），且被删投影必须同步淘汰
// wafiplist 运行期缓存（与 GC 路径同口径：fail-stale 不得继续服务已删集合）。
func TestRestoreIPListProjections_reportsFailuresAndEvictsCache(t *testing.T) {
	dir := t.TempDir()
	oldDir, oldPrefix := IPListDataDir, wafiplist.AllowedPathPrefix
	IPListDataDir = dir
	wafiplist.AllowedPathPrefix = dir + string(filepath.Separator)
	t.Cleanup(func() { IPListDataDir, wafiplist.AllowedPathPrefix = oldDir, oldPrefix })

	// Given：一个已渲染写入并进入运行期缓存的投影文件
	path := filepath.Join(dir, "p1-acl.txt")
	if err := os.WriteFile(path, []byte("10.0.0.0/8\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := wafiplist.LoadPrefixesFresh(path); err != nil {
		t.Fatalf("warm cache: %v", err)
	}
	// 快照不含该文件（渲染新增→回滚删除），另含一个父目录不存在的路径（回写失败）
	snapshot := IPListProjectionSnapshot{
		filepath.Join(dir, "missing", "p2-acl.txt"): []byte("192.0.2.0/24\n"),
	}

	// When
	err := RestoreIPListProjections(snapshot)

	// Then：失败可上报且指名失败路径
	if err == nil || !strings.Contains(err.Error(), "p2-acl.txt") {
		t.Fatalf("err=%v，回写失败必须返回带路径的错误", err)
	}
	if _, serr := os.Stat(path); !os.IsNotExist(serr) {
		t.Fatalf("渲染新增的投影必须删除, stat err=%v", serr)
	}
	// 缓存已淘汰：解析不再 fail-stale 返回旧集合，而是显式失败（fail-closed）。
	if _, rerr := wafiplist.ResolvePrefixesNormalized(path); rerr == nil {
		t.Fatal("已删投影的运行期缓存未淘汰——fail-stale 会继续用旧集合判定")
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
