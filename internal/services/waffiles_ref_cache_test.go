package services

import (
	"os"
	"path/filepath"
	"testing"
	"time"
)

// 文件态引用构建在稳态下被从端每轮 304 同步与主端快照重建反复调用，
// 全量构建需要整树 tar.gz + xdb 全读 + 威胁文件哈希。廉价签名（路径+大小+
// mtime）未变时必须短路，签名变化时才重建。
func TestBuildWafFileRef_cheapSignatureShortCircuitsFullBuild(t *testing.T) {
	oldCrs, oldXdb, oldWaf := crsLiveDir, ip2regionLivePath, wafDir
	defer func() { crsLiveDir, ip2regionLivePath, wafDir = oldCrs, oldXdb, oldWaf }()

	dir := t.TempDir()
	crsLiveDir = filepath.Join(dir, "crs")
	ip2regionLivePath = filepath.Join(dir, "ip2region.xdb")
	wafDir = filepath.Join(dir, "waf")
	rulesDir := filepath.Join(crsLiveDir, "rules")
	if err := os.MkdirAll(rulesDir, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(wafDir, 0o755); err != nil {
		t.Fatal(err)
	}
	rulePath := filepath.Join(rulesDir, "REQUEST-900-EXCLUSION-RULES-BEFORE-CRS.conf")
	if err := os.WriteFile(rulePath, []byte("SecRule ARGS \"@rx foo\" \"id:1,deny\"\n"), 0o644); err != nil {
		t.Fatal(err)
	}

	wafFileRefCache.mu.Lock()
	wafFileRefCache.valid = false
	wafFileRefCache.sig = ""
	wafFileRefCache.ref = nil
	wafFileRefCache.mu.Unlock()
	wafFileRefFullBuilds.Store(0)

	first := BuildWafFileRef()
	if first == nil || first.CRSSha256 == "" {
		t.Fatalf("first ref = %+v, want CRS hash", first)
	}
	if got := wafFileRefFullBuilds.Load(); got != 1 {
		t.Fatalf("full builds after first call = %d, want 1", got)
	}

	// 文件未变：只用 stat 签名，必须命中缓存。
	second := BuildWafFileRef()
	if got := wafFileRefFullBuilds.Load(); got != 1 {
		t.Fatalf("full builds after unchanged call = %d, want 1 (cache hit)", got)
	}
	if second == nil || second.CRSSha256 != first.CRSSha256 {
		t.Fatalf("cached ref = %+v, want same hash %q", second, first.CRSSha256)
	}

	// 内容与 mtime 变化：签名变化必须触发重建并产出新哈希。
	if err := os.WriteFile(rulePath, []byte("SecRule ARGS \"@rx bar\" \"id:1,deny\"\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	changedAt := time.Now().Add(2 * time.Second)
	if err := os.Chtimes(rulePath, changedAt, changedAt); err != nil {
		t.Fatal(err)
	}
	third := BuildWafFileRef()
	if got := wafFileRefFullBuilds.Load(); got != 2 {
		t.Fatalf("full builds after change = %d, want 2", got)
	}
	if third == nil || third.CRSSha256 == first.CRSSha256 {
		t.Fatalf("ref after change = %+v, want different CRS hash", third)
	}
}

func TestWafRefStatSignature_tracksCRSVersionWithoutRules(t *testing.T) {
	oldCrs, oldXdb, oldWaf := crsLiveDir, ip2regionLivePath, wafDir
	t.Cleanup(func() { crsLiveDir, ip2regionLivePath, wafDir = oldCrs, oldXdb, oldWaf })
	root := t.TempDir()
	crsLiveDir = filepath.Join(root, "crs")
	ip2regionLivePath = filepath.Join(root, "missing.xdb")
	wafDir = filepath.Join(root, "waf")
	if err := os.MkdirAll(crsLiveDir, 0o755); err != nil {
		t.Fatal(err)
	}
	versionPath := filepath.Join(crsLiveDir, "VERSION")
	fixed := time.Unix(1700000000, 0)
	writeVersion := func(value string) {
		t.Helper()
		if err := os.WriteFile(versionPath, []byte(value), 0o644); err != nil {
			t.Fatal(err)
		}
		if err := os.Chtimes(versionPath, fixed, fixed); err != nil {
			t.Fatal(err)
		}
	}
	writeVersion("v1")
	first, err := wafRefStatSignature()
	if err != nil {
		t.Fatal(err)
	}
	// Same length and same mtime: the readable VERSION value itself must be signed.
	writeVersion("v2")
	second, err := wafRefStatSignature()
	if err != nil {
		t.Fatal(err)
	}
	if first == second {
		t.Fatal("VERSION content change must change the reference signature without a rules directory")
	}
	if err := os.Remove(versionPath); err != nil {
		t.Fatal(err)
	}
	missing, err := wafRefStatSignature()
	if err != nil {
		t.Fatal(err)
	}
	if missing == second {
		t.Fatal("missing VERSION must have an explicit signature state distinct from a readable value")
	}
}

// .version（ip2region tag）与 CRS VERSION 同口径：内容入签名——tag 参与
// waf_files 节哈希与从端漂移判定，「等长改写且保留 mtime/mode」时命中旧
// 引用会让主从节哈希暂时不对齐（多一轮全量重拉才自愈）。
func TestWafRefStatSignature_tracksIP2RegionVersionContent(t *testing.T) {
	oldCrs, oldXdb, oldWaf := crsLiveDir, ip2regionLivePath, wafDir
	t.Cleanup(func() { crsLiveDir, ip2regionLivePath, wafDir = oldCrs, oldXdb, oldWaf })
	root := t.TempDir()
	crsLiveDir = filepath.Join(root, "crs") // 不创建：rules 缺失形态下 tag 仍须入签名
	ip2regionLivePath = filepath.Join(root, "ip2region.xdb")
	wafDir = filepath.Join(root, "waf")
	if err := os.WriteFile(ip2regionLivePath, []byte("xdb"), 0o644); err != nil {
		t.Fatal(err)
	}
	versionPath := ip2regionLivePath + ".version"
	fixed := time.Unix(1700000000, 0)
	writeTag := func(value string) {
		t.Helper()
		if err := os.WriteFile(versionPath, []byte(value), 0o644); err != nil {
			t.Fatal(err)
		}
		if err := os.Chtimes(versionPath, fixed, fixed); err != nil {
			t.Fatal(err)
		}
	}
	writeTag("v1.0")
	first, err := wafRefStatSignature()
	if err != nil {
		t.Fatal(err)
	}
	// 等长 + 同 mtime/mode：内容变化必须改变签名。
	writeTag("v2.0")
	second, err := wafRefStatSignature()
	if err != nil {
		t.Fatal(err)
	}
	if first == second {
		t.Fatal(".version 等长同 mtime 改写必须改变引用签名")
	}
	if err := os.Remove(versionPath); err != nil {
		t.Fatal(err)
	}
	missing, err := wafRefStatSignature()
	if err != nil {
		t.Fatal(err)
	}
	if missing == second {
		t.Fatal(".version 缺失必须是独立签名状态")
	}
}
