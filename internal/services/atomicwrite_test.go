package services

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

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

// 真实调用点：IP 名单投影回滚恢复真实文件并清理本轮渲染新建的文件，不留
// 临时制品。
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
	snapshot, err := SnapshotIPListProjections()
	if err != nil {
		t.Fatalf("snapshot: %v", err)
	}
	if _, err := writeIPListFile("p1-acl", []string{"198.51.100.1"}); err != nil {
		t.Fatalf("render p1: %v", err)
	}
	if _, err := writeIPListFile("p2-acl", []string{"203.0.113.1"}); err != nil {
		t.Fatalf("render p2: %v", err)
	}
	added := filepath.Join(dir, "p2-acl.txt")

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

// 回滚删除只认「本轮渲染新建」清单：快照缺项（瞬时读失败/目录列举失败造成的
// 不完整快照）不得让在役投影被当作渲染新增删除——那样 Caddy 的 @ipListFast
// 会读到文件不存在，allow/deny 名单同时失效。
func TestRestoreIPListProjections_doesNotDeletePreExistingOnIncompleteSnapshot(t *testing.T) {
	dir := t.TempDir()
	oldDir := IPListDataDir
	IPListDataDir = dir
	t.Cleanup(func() { IPListDataDir = oldDir })
	t.Cleanup(EndIPListProjectionPass)
	inService := filepath.Join(dir, "p1-acl.txt")
	if err := os.WriteFile(inService, []byte("10.0.0.0/8\n"), 0o644); err != nil {
		t.Fatal(err)
	}

	// 不完整快照（在役投影缺项、无新建清单）——旧口径会按目录差集删掉 p1。
	incomplete := IPListProjectionSnapshot{
		files:   map[string][]byte{},
		created: map[string]struct{}{},
	}
	if err := RestoreIPListProjections(incomplete); err != nil {
		t.Fatalf("restore: %v", err)
	}
	if raw, err := os.ReadFile(inService); err != nil || string(raw) != "10.0.0.0/8\n" {
		t.Fatalf("在役投影被快照缺项误删: content=%q err=%v", raw, err)
	}

	// 零值快照（调用方忽略快照错误时的形态）同样不得删除任何文件。
	if err := RestoreIPListProjections(IPListProjectionSnapshot{}); err != nil {
		t.Fatalf("restore zero snapshot: %v", err)
	}
	if _, err := os.Stat(inService); err != nil {
		t.Fatalf("零值快照回滚不得删除在役投影: %v", err)
	}
}

// 快照阶段任一投影读失败必须显式返回错误（而不是少一项的快照）：调用方据此
// 拒绝在不可回滚的前提下渲染。
func TestSnapshotIPListProjections_failsOnUnreadableProjection(t *testing.T) {
	dir := t.TempDir()
	oldDir := IPListDataDir
	IPListDataDir = dir
	t.Cleanup(func() { IPListDataDir = oldDir })
	t.Cleanup(EndIPListProjectionPass)
	if err := os.WriteFile(filepath.Join(dir, "p1-acl.txt"), []byte("10.0.0.0/8\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	// 悬空符号链接：目录项存在但读不到（瞬时读失败的确定性替身，不依赖权限）。
	broken := filepath.Join(dir, "p2-acl.txt")
	if err := os.Symlink(filepath.Join(dir, "nowhere"), broken); err != nil {
		t.Skipf("symlink unavailable: %v", err)
	}

	if _, err := SnapshotIPListProjections(); err == nil || !strings.Contains(err.Error(), broken) {
		t.Fatalf("err=%v，投影读失败必须显式返回带路径的错误", err)
	}

	// 目录列举失败同样显式失败（IPListDataDir 指向普通文件=ENOTDIR，不是
	// 「目录尚未创建」的首次保存形态）。
	if err := os.Remove(broken); err != nil {
		t.Fatal(err)
	}
	notADir := filepath.Join(dir, "not-a-dir")
	if err := os.WriteFile(notADir, []byte("x"), 0o644); err != nil {
		t.Fatal(err)
	}
	IPListDataDir = notADir
	if _, err := SnapshotIPListProjections(); err == nil {
		t.Fatal("投影目录不可列举必须显式返回错误")
	}

	// 目录尚不存在＝首次保存：空快照且无错误。
	IPListDataDir = filepath.Join(dir, "missing")
	snapshot, err := SnapshotIPListProjections()
	if err != nil {
		t.Fatalf("首次保存（目录不存在）不得失败: %v", err)
	}
	if len(snapshot.files) != 0 {
		t.Fatalf("空快照 files=%v, want empty", snapshot.files)
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
	// 本轮渲染新建该投影（清单登记→回滚删除），快照另含一个父目录不存在的
	// 路径（回写失败）
	snapshot := IPListProjectionSnapshot{
		files:   map[string][]byte{filepath.Join(dir, "missing", "p2-acl.txt"): []byte("192.0.2.0/24\n")},
		created: map[string]struct{}{path: {}},
	}
	t.Cleanup(EndIPListProjectionPass)

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

// 回滚只重写内容不同的投影：同内容文件不得被触碰（mtime/身份保持），否则
// 失败路径会改写全部投影 inode，运行中 Caddy 的 @ipListFast stat 缓存对全部
// 名单重建（读盘放大 + 统计形态全变）。
func TestRestoreIPListProjections_skipsIdenticalFiles(t *testing.T) {
	dir := t.TempDir()
	oldDir := IPListDataDir
	IPListDataDir = dir
	t.Cleanup(func() { IPListDataDir = oldDir })
	unchanged := filepath.Join(dir, "p1-acl.txt")
	changed := filepath.Join(dir, "p2-acl.txt")
	if err := os.WriteFile(unchanged, []byte("same\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(changed, []byte("old\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	snapshot, err := SnapshotIPListProjections()
	if err != nil {
		t.Fatalf("snapshot: %v", err)
	}
	oldTime := time.Unix(1600000000, 0)
	if err := os.Chtimes(unchanged, oldTime, oldTime); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(changed, []byte("new-render\n"), 0o644); err != nil {
		t.Fatal(err)
	}

	if err := RestoreIPListProjections(snapshot); err != nil {
		t.Fatalf("restore: %v", err)
	}

	info, err := os.Stat(unchanged)
	if err != nil {
		t.Fatal(err)
	}
	if !info.ModTime().Equal(oldTime) {
		t.Fatalf("同内容投影被重写（mtime=%v, want %v）——回滚不得触碰未变文件", info.ModTime(), oldTime)
	}
	if raw, err := os.ReadFile(changed); err != nil || string(raw) != "old\n" {
		t.Fatalf("变化投影未回滚: %q err=%v", raw, err)
	}
}
