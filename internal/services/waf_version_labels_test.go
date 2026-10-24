package services

import (
	"os"
	"path/filepath"
	"testing"

	"lazy-balancer-v2/internal/models"
)

// 「同步开关关闭」告警改走版本标签比对（只读两个小文件），不再为一条告警付
// 整树 tar.gz+sha256；内容级漂移检测仍由 wafFilesRefDiffers 承担。

func TestWafFilesRefVersionLabelsDiffer_labelsOnly(t *testing.T) {
	oldCRS, oldXdb := crsLiveDir, ip2regionLivePath
	dir := t.TempDir()
	crsLiveDir = dir
	ip2regionLivePath = filepath.Join(dir, "ip2region.xdb")
	t.Cleanup(func() { crsLiveDir, ip2regionLivePath = oldCRS, oldXdb })

	if err := os.WriteFile(filepath.Join(dir, "VERSION"), []byte("v4.28.0\n"), 0644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(ip2regionLivePath+".version", []byte("2026.09.24"), 0644); err != nil {
		t.Fatal(err)
	}

	same := &models.ClusterWafFilesRef{CRSVersion: "v4.28.0", IP2RegionTag: "2026.09.24"}
	if wafFilesRefVersionLabelsDiffer(same) {
		t.Fatal("版本标签一致时不得判分叉")
	}

	bumped := &models.ClusterWafFilesRef{CRSVersion: "v4.29.0"}
	if !wafFilesRefVersionLabelsDiffer(bumped) {
		t.Fatal("主节点 CRS 版本变化必须触发告警")
	}

	// 只有哈希字段（旧主端/手工构造）→ 无版本信号：不判分叉（避免哈希回退）。
	hashesOnly := &models.ClusterWafFilesRef{CRSSha256: "deadbeef"}
	if wafFilesRefVersionLabelsDiffer(hashesOnly) {
		t.Fatal("无版本标签时不得误报分叉")
	}
	if wafFilesRefVersionLabelsDiffer(nil) {
		t.Fatal("nil 引用不得判分叉")
	}
}
