package db

import (
	"os"
	"path/filepath"
	"testing"
)

// metrics 库代际 token 契约：同一个库文件跨重启/重开保持同一代际，隔离重建
// （损坏自愈新库）必须换新代际——摄取侧的 offset 复位判据依赖这两条性质。
func TestMetricsDBGeneration_stableAcrossReopenAndChangesOnRebuild(t *testing.T) {
	dir := t.TempDir()
	closeMetricsDB := func() {
		if MetricsDB != nil {
			_ = MetricsDB.Close()
			MetricsDB = nil
		}
	}
	t.Cleanup(closeMetricsDB)

	if err := InitializeMetricsDB(dir); err != nil {
		t.Fatal(err)
	}
	first := MetricsDBGeneration()
	if first == "" {
		t.Fatal("fresh metrics db must expose a generation token")
	}
	closeMetricsDB()

	// 同一库文件重开（进程重启形态）：代际不变——offset 继续沿用，不得重放。
	if err := InitializeMetricsDB(dir); err != nil {
		t.Fatal(err)
	}
	if got := MetricsDBGeneration(); got != first {
		t.Fatalf("reopen of the same db file changed generation: %q -> %q", first, got)
	}
	closeMetricsDB()

	// 头部损坏 → 隔离重建：新库文件必须拿到新代际（摄取侧据此判定「新库」）。
	dbPath := filepath.Join(dir, MetricsDBFilename)
	if err := os.WriteFile(dbPath, append([]byte(nil), make([]byte, 8192)...), 0600); err != nil {
		t.Fatal(err)
	}
	if err := InitializeMetricsDB(dir); err != nil {
		t.Fatalf("rebuild after quarantine: %v", err)
	}
	if got := MetricsDBGeneration(); got == "" || got == first {
		t.Fatalf("quarantine rebuild must mint a new generation: first=%q now=%q", first, got)
	}
}
