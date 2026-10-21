package services

// allow: SIZE_OK — TOFU download-integrity regression tests (历史问题).

import (
	"database/sql"
	"errors"
	"log"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"lazy-balancer-v2/internal/db"
)

// TestRecordDownloadIntegrity_concurrentSourcesNoLostUpdate 验证两个更新调度器
// （CRS / ip2region）同小时并发下载时，共享记录文件的 load-modify-persist 不丢
// 更新、不撕裂文件（历史问题）。
func TestRecordDownloadIntegrity_concurrentSourcesNoLostUpdate(t *testing.T) {
	dir := t.TempDir()
	oldPath := downloadIntegrityPath
	downloadIntegrityPath = filepath.Join(dir, ".download-integrity.json")
	t.Cleanup(func() { downloadIntegrityPath = oldPath })
	artifact := func(name, content string) string {
		p := filepath.Join(dir, name)
		if err := os.WriteFile(p, []byte(content), 0o644); err != nil {
			t.Fatal(err)
		}
		return p
	}
	artifactA := artifact("a.bin", "content-A")
	artifactB := artifact("b.bin", "content-B")

	// When：两个来源并发记录（各自独立下载文件，共享同一记录文件）
	var wg sync.WaitGroup
	for i := 0; i < 8; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			src, path := "https://src/A", artifactA
			if i%2 == 1 {
				src, path = "https://src/B", artifactB
			}
			if err := recordDownloadIntegrity(src, path, "测试资源"); err != nil {
				t.Errorf("record %s: %v", src, err)
			}
		}(i)
	}
	wg.Wait()

	// Then：两条基线都在、文件可解析（无丢失更新、无撕裂）
	records, audits, err := loadDownloadIntegrityRecords()
	if err != nil {
		t.Fatal(err)
	}
	if len(audits) != 0 {
		t.Fatalf("健康记录文件不得产生隔离审计: %#v", audits)
	}
	if len(records) != 2 {
		t.Fatalf("records=%d, want 2 (lost update detected)", len(records))
	}
	for _, src := range []string{"https://src/A", "https://src/B"} {
		if _, ok := records[src]; !ok {
			t.Fatalf("record for %s missing", src)
		}
	}
}

// TestRecordDownloadIntegrity_quarantinesCorruptRecordsFile 验证损坏的记录文件
// 被隔离（.corrupt-* 保留现场）、基线从头重建，而非静默禁用 TOFU 检查（历史问题）。
func TestRecordDownloadIntegrity_quarantinesCorruptRecordsFile(t *testing.T) {
	dir := t.TempDir()
	oldPath := downloadIntegrityPath
	downloadIntegrityPath = filepath.Join(dir, ".download-integrity.json")
	t.Cleanup(func() { downloadIntegrityPath = oldPath })
	// Given：损坏（半写）的记录文件
	if err := os.WriteFile(downloadIntegrityPath, []byte(`{"broken": `), 0o644); err != nil {
		t.Fatal(err)
	}
	artifact := filepath.Join(dir, "x.bin")
	if err := os.WriteFile(artifact, []byte("fresh-data"), 0o644); err != nil {
		t.Fatal(err)
	}

	// When：新下载记录
	if err := recordDownloadIntegrity("https://src/x", artifact, "测试资源"); err != nil {
		t.Fatalf("record: %v", err)
	}

	// Then：损坏文件被隔离、新基线正常落盘
	matches, err := filepath.Glob(downloadIntegrityPath + ".corrupt-*")
	if err != nil || len(matches) != 1 {
		t.Fatalf("corrupt quarantine files=%v err=%v, want exactly 1", matches, err)
	}
	records, audits, err := loadDownloadIntegrityRecords()
	if err != nil {
		t.Fatal(err)
	}
	// 历史问题：隔离告警的审计载荷在 recordDownloadIntegrity 内以 pending 形式
	// 锁外落库；此处再次装载的是已修复的记录文件，不得再生待落审计。
	if len(audits) != 0 {
		t.Fatalf("已修复记录文件不得再产生待落审计, got %#v", audits)
	}
	if len(records) != 1 {
		t.Fatalf("records=%d, want 1 rebuilt baseline", len(records))
	}
	if _, ok := records["https://src/x"]; !ok {
		t.Fatalf("rebuilt baseline missing the new source")
	}
	// And：再次记录同一来源不再触发隔离（记录文件健康）
	if err := recordDownloadIntegrity("https://src/x", artifact, "测试资源"); err != nil {
		t.Fatalf("second record: %v", err)
	}
	more, err := filepath.Glob(downloadIntegrityPath + ".corrupt-*")
	if err != nil || len(more) != 1 {
		t.Fatalf("quarantine files after healthy record=%v, want still 1", more)
	}
}

// 历史问题（历史）：审计库被外部写锁占住（RecordAuditLog 阻塞）时，
// 完整性记录不得持 downloadIntegrityMu 等审计 I/O——另一族更新调度器的
// load-modify-persist 必须立即可进入（历史问题 的同族约定）。
func TestRecordDownloadIntegrity_releasesLockBeforeAuditIO(t *testing.T) {
	dir := t.TempDir()
	oldPath := downloadIntegrityPath
	downloadIntegrityPath = filepath.Join(dir, ".download-integrity.json")
	t.Cleanup(func() { downloadIntegrityPath = oldPath })

	artifact := filepath.Join(dir, "a.bin")
	if err := os.WriteFile(artifact, []byte("v1"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := recordDownloadIntegrity("https://src/m", artifact, "测试资源"); err != nil {
		t.Fatalf("seed baseline: %v", err)
	}

	// Given：审计库被外部事务持有写锁（RecordAuditLog 的 INSERT 将阻塞）
	auditDir := t.TempDir()
	oldAudit := db.AuditDB
	if err := db.InitializeAuditDB(auditDir); err != nil {
		t.Fatalf("init audit db: %v", err)
	}
	auditHandle := db.AuditDB
	t.Cleanup(func() {
		_ = auditHandle.Close()
		db.AuditDB = oldAudit
	})
	locker, err := sql.Open("sqlite", filepath.Join(auditDir, db.AuditDBFilename)+"?_txlock=immediate&_pragma=busy_timeout(30000)")
	if err != nil {
		t.Fatal(err)
	}
	tx, err := locker.Begin()
	if err != nil {
		t.Fatalf("begin locker tx: %v", err)
	}
	if _, err := tx.Exec(`INSERT INTO audit_log (username, action, resource) VALUES ('locker','持有','写锁')`); err != nil {
		t.Fatalf("acquire write lock: %v", err)
	}

	logs := &syncLogBuffer{}
	oldWriter := log.Writer()
	log.SetOutput(logs)
	t.Cleanup(func() { log.SetOutput(oldWriter) })

	// When：内容变化 → mismatch 分支（审计落库会阻塞在写锁上）
	if err := os.WriteFile(artifact, []byte("v2-different"), 0o644); err != nil {
		t.Fatal(err)
	}
	done := make(chan error, 1)
	go func() {
		done <- recordDownloadIntegrity("https://src/m", artifact, "测试资源")
	}()
	t.Cleanup(func() {
		_ = tx.Rollback()
		_ = locker.Close()
	})

	// 等 mismatch 日志出现（判定完成、已解锁、正卡在审计写入）
	deadline := time.Now().Add(2 * time.Second)
	for !strings.Contains(logs.String(), "download integrity mismatch") {
		if time.Now().After(deadline) {
			t.Fatalf("未观察到 mismatch 日志（前置未达成）: %q", logs.String())
		}
		time.Sleep(5 * time.Millisecond)
	}
	time.Sleep(50 * time.Millisecond) // 让写侧推进到被阻塞的审计 INSERT

	// Then：downloadIntegrityMu 必须已释放（另一族调度器可立即进入）
	acquired := make(chan struct{})
	go func() {
		downloadIntegrityMu.Lock()
		downloadIntegrityMu.Unlock()
		close(acquired)
	}()
	select {
	case <-acquired:
	case <-time.After(2 * time.Second):
		t.Fatal("downloadIntegrityMu 在审计库 busy 期间仍被持有（锁内审计 I/O）")
	}

	// And：解除写锁后 mismatch 错误如实返回，旧基线保留
	if err := tx.Rollback(); err != nil {
		t.Fatalf("release audit lock: %v", err)
	}
	select {
	case recordErr := <-done:
		if !errors.Is(recordErr, errDownloadIntegrityMismatch) {
			t.Fatalf("err=%v, want errDownloadIntegrityMismatch", recordErr)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("recordDownloadIntegrity 未返回")
	}
	records, _, err := loadDownloadIntegrityRecords()
	if err != nil {
		t.Fatal(err)
	}
	if got := records["https://src/m"]; got.SHA256 == "" || got.Size != int64(len("v1")) {
		t.Fatalf("mismatch 必须保留旧基线, got %+v", got)
	}
}
