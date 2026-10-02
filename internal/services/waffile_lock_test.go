package services

// L6-66-02（第 66 轮审计 P4）：lbbak 导入与三库更新器无写者互斥——CRS 树
// 交换、威胁库 .iplist+.fast 写编译、ip2region xdb 安装段各自为政，交错产生
// 混合/残缺 rules 树（部分防护静默失效）与撕裂 .iplist。修复=包级 wafFileMu
// 串行化四方文件相位。本文件用「预持锁→调用文件相位→必须阻塞至释放」的
// 确定性探针钉住互斥（今日无锁→不阻塞→RED；接线后阻塞→GREEN）。

import (
	"context"
	"testing"
	"time"

	"lazy-balancer-v2/internal/db"
)

// probeBlocksUnderWafFileLock 预持 wafFileMu 运行 probe，断言其在持锁期间
// 不得完成（文件相位必须排队），释放后必须完成。
func probeBlocksUnderWafFileLock(t *testing.T, name string, probe func()) {
	t.Helper()
	WafFileLock().Lock()
	done := make(chan struct{})
	go func() {
		defer close(done)
		probe()
	}()
	select {
	case <-done:
		WafFileLock().Unlock()
		t.Fatalf("%s 在 wafFileMu 被预持期间完成——文件相位未入锁（%s）", name, name)
	case <-time.After(300 * time.Millisecond):
	}
	WafFileLock().Unlock()
	select {
	case <-done:
	case <-time.After(10 * time.Second):
		t.Fatalf("%s 在锁释放后 10s 内未完成", name)
	}
}

// Given wafFileMu 被预持（模拟并发的 lbbak 导入文件相位）。
// When 威胁库更新器的 writeThreatIplist+CompileFromIplistFile 写编译对执行。
// Then 必须阻塞至锁释放（.iplist/.fast 文件相位互斥）。
func TestWafFileWriters_threat_pair_blocks_while_waf_file_lock_held(t *testing.T) {
	dir := t.TempDir()
	restore := OverrideThreatWafDirForTest(dir)
	defer restore()
	oldDB, oldMetricsDB, oldAuditDB := db.DB, db.MetricsDB, db.AuditDB
	if err := db.Initialize(t.TempDir()); err != nil {
		t.Fatalf("initialize test database: %v", err)
	}
	t.Cleanup(func() {
		_ = db.Close()
		db.DB, db.MetricsDB, db.AuditDB = oldDB, oldMetricsDB, oldAuditDB
	})

	probeBlocksUnderWafFileLock(t, "威胁库 .iplist+.fast 写编译对", func() {
		if _, err := writeThreatSystemList("ustc", []string{"1.2.3.4"}); err != nil {
			t.Logf("writeThreatSystemList err=%v（探针只关心阻塞语义，允许业务错误）", err)
		}
	})
}

// Given wafFileMu 被预持。
// When ip2region 更新器 downloadAndInstall 进入安装文件段（备份+rename）。
// Then 必须阻塞至锁释放（下载在锁外——staging 先行，不受锁影响）。
func TestWafFileWriters_ip2region_install_blocks_while_waf_file_lock_held(t *testing.T) {
	m := newTestIP2RegionManager(t)
	m.downloadXDB = fakeIP2RegionDownload(t, true)

	probeBlocksUnderWafFileLock(t, "ip2region xdb 安装段", func() {
		if err := m.downloadAndInstall(context.Background(), "v3.1.0"); err != nil {
			t.Logf("downloadAndInstall err=%v（探针只关心阻塞语义，允许业务错误）", err)
		}
	})
}

// Given wafFileMu 被预持。
// When CRS 更新器 downloadAndInstall 进入树交换段（RemoveAll+moveTree+setup 落盘）。
// Then 必须阻塞至锁释放；网络下载（已桩化）与 Caddy 重载（reloader）在锁外。
func TestWafFileWriters_crs_tree_swap_blocks_while_waf_file_lock_held(t *testing.T) {
	m := newTestCRSManager(t)
	m.downloadTarball = fakeCRSDownload(t, map[string]string{
		"coreruleset-4.15.0/crs-setup.conf.example":     "# new setup",
		"coreruleset-4.15.0/rules/" + crsRulesProbeFile: "# init probe\n",
		"coreruleset-4.15.0/rules/REQUEST-901.conf":     "SecRule a\n",
	})

	probeBlocksUnderWafFileLock(t, "CRS 树交换段", func() {
		if err := m.downloadAndInstall(context.Background(), "v4.15.0"); err != nil {
			t.Logf("downloadAndInstall err=%v（探针只关心阻塞语义，允许业务错误）", err)
		}
	})
}
