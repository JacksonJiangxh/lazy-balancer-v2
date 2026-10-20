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
