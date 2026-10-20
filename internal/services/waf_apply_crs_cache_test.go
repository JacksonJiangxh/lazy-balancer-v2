package services

import (
	"os"
	"path/filepath"
	"testing"
)

// 历史修复6：集群同步与 lbbak 导入共用 ApplyWafFileBundle 落盘 live CRS 树，
// CRS 落盘成功后必须让 /security/crs 的规则数缓存失效（此前仅进程重启或
// 下一次成功更新才收敛）。
func TestApplyWafFileBundle_invalidatesCRSRuleCount(t *testing.T) {
	src := t.TempDir()
	srcRules := filepath.Join(src, "crs", "rules")
	if err := os.MkdirAll(srcRules, 0755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(srcRules, "REQUEST-900.conf"), []byte("SecRule a\n"), 0644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(src, "crs", "VERSION"), []byte("v4.14.0"), 0644); err != nil {
		t.Fatal(err)
	}
	oldLive, oldXdb := crsLiveDir, ip2regionLivePath
	t.Cleanup(func() { crsLiveDir, ip2regionLivePath = oldLive, oldXdb })
	crsLiveDir = filepath.Join(src, "crs")
	ip2regionLivePath = filepath.Join(src, "ip2region.xdb")

	bundle := BuildWafFileBundle()
	if bundle == nil || len(bundle.CRSTarGz) == 0 {
		t.Fatalf("bundle 未携带 CRS 内容: %+v", bundle)
	}

	// 管理器指向独立的空 live 树，先预热缓存（0 条规则）。
	liveDir := filepath.Join(t.TempDir(), "crs")
	if err := os.MkdirAll(filepath.Join(liveDir, "rules"), 0755); err != nil {
		t.Fatal(err)
	}
	m := newCRSUpdateManager(func() error { return nil })
	m.crsDir = liveDir
	oldMgr := crsUpdateManager
	crsUpdateManager = m
	t.Cleanup(func() { crsUpdateManager = oldMgr })
	if got := m.RuleCount(); got != 0 {
		t.Fatalf("预热 RuleCount=%d, want 0", got)
	}

	crsLiveDir = liveDir
	changed, _, _, err := ApplyWafFileBundle(bundle)
	if err != nil || !changed {
		t.Fatalf("apply crsChanged=%v err=%v", changed, err)
	}
	if got := m.RuleCount(); got != 1 {
		t.Fatalf("带外替换后 RuleCount=%d, want 1（缓存未失效）", got)
	}
}
