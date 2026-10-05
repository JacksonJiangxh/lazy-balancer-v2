package services

// F-L6-68-02（第 68 轮审计 P4，CRS 侧）：CRS 树交换（swapCRSTreeFromStaging，
// wafFileMu 互斥段内）与 security_crs_version 版本行写入（此前在锁外
// downloadAndInstall 尾段）分离——写相位中段（树已交换、行未写）导出侧
// （BuildWafFileBundle 读相位持同一锁）可打出「文件新/行旧」偏斜 bundle，沿
// lbbak/集群 waf_files 通道扩散。修复=版本行写入移入交换段同一互斥区（DB 单
// 行 UPDATE 毫秒级，与段内树交换 IO 同量级；wafFileMu 保持叶锁，不引入
// CaddyOpLock 嵌套）。prevTag 锁内读出供重载失败回滚（语义不变）。

import (
	"os"
	"path/filepath"
	"testing"
	"time"
)

// Given wafFileMu 被预持（模拟并发的 lbbak 导入文件相位）。
// When CRS 交换段（树交换+版本行写入）执行。
// Then 必须阻塞至锁释放；释放后版本行与文件树同互斥区一致落成。
func TestCRSUpdateManager_swap_writes_version_row_inside_waf_file_lock(t *testing.T) {
	m := newTestCRSManager(t)
	seedCRSVersionRow(t, "v4.14.0", true)
	if err := os.MkdirAll(m.crsDir, 0755); err != nil {
		t.Fatal(err)
	}
	staging := filepath.Join(t.TempDir(), ".staging")
	if err := os.MkdirAll(filepath.Join(staging, "rules"), 0755); err != nil {
		t.Fatal(err)
	}
	os.WriteFile(filepath.Join(staging, "rules", "REQUEST-901-INITIALIZATION.conf"), []byte("SecRule 1"), 0644)
	os.WriteFile(filepath.Join(staging, "crs-setup.conf.example"), []byte("# setup"), 0644)
	setupPath := filepath.Join(m.crsDir, "crs-setup.conf")

	WafFileLock().Lock()
	type swapResult struct {
		prevTag string
		err     error
	}
	done := make(chan swapResult, 1)
	go func() {
		prev, err := m.swapCRSTreeFromStaging(staging, setupPath, nil, "v4.15.0")
		done <- swapResult{prev, err}
	}()
	select {
	case res := <-done:
		WafFileLock().Unlock()
		t.Fatalf("交换段在 wafFileMu 被预持期间完成（树交换/版本行未入锁）, res=%+v", res)
	case <-time.After(300 * time.Millisecond):
	}
	WafFileLock().Unlock()
	var res swapResult
	select {
	case res = <-done:
	case <-time.After(10 * time.Second):
		t.Fatal("锁释放后交换段 10s 内未完成")
	}
	if res.err != nil {
		t.Fatalf("swap: %v", res.err)
	}
	if res.prevTag != "v4.14.0" {
		t.Fatalf("prevTag=%q, want v4.14.0（锁内读出供重载失败回滚）", res.prevTag)
	}
	// 版本行随交换段落库——导出读相位（持同一锁）永远读不到文件新/行旧偏斜。
	if version, _, _, _, _, _, _ := crsVersionRow(t); version != "v4.15.0" {
		t.Fatalf("version row=%q, want v4.15.0（版本行写入必须随交换段同互斥区完成）", version)
	}
}
