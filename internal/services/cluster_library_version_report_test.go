package services

import (
	"context"
	"testing"
)

// 威胁情报库/爬虫地址库的版本上报必须与前端
// utils/securityLibraries.summarizeLibrarySources 同口径：各源 version 取最近
// （日期与 semver 通用），空源 → 空串。

func TestReportSecurityLibraryVersions_latestAcrossSources(t *testing.T) {
	_, database := newClusterTestService(t)
	ctx := context.Background()

	if _, err := database.Exec(`UPDATE security_threat_sources SET version='2026.09.24' WHERE name='ustc'`); err != nil {
		t.Fatal(err)
	}
	if _, err := database.Exec(`UPDATE security_threat_sources SET version='2026.10.01' WHERE name='firehol_l1'`); err != nil {
		t.Fatal(err)
	}
	if _, err := database.Exec(`UPDATE security_threat_sources SET version='2026.08.15' WHERE name='et_compromised'`); err != nil {
		t.Fatal(err)
	}
	// 爬虫地址库默认无种子行：显式插入两个来源版本。
	if _, err := database.Exec(`INSERT INTO security_crawler_sources (name, display_name, version) VALUES ('googlebot','Googlebot','v2.3.3'), ('gptbot','GPTBot','v2.3.10')`); err != nil {
		t.Fatal(err)
	}

	threat, crawler := reportSecurityLibraryVersions(ctx, database)
	if threat != "2026.10.01" {
		t.Fatalf("threat_version=%q, want 最近日期 2026.10.01", threat)
	}
	if crawler != "v2.3.10" {
		t.Fatalf("crawler_version=%q, want 最近 semver v2.3.10", crawler)
	}
}

func TestReportSecurityLibraryVersions_emptySourcesYieldEmptyString(t *testing.T) {
	_, database := newClusterTestService(t)
	ctx := context.Background()
	if _, err := database.Exec(`UPDATE security_threat_sources SET version=''`); err != nil {
		t.Fatal(err)
	}
	if _, err := database.Exec(`DELETE FROM security_crawler_sources`); err != nil {
		t.Fatal(err)
	}
	threat, crawler := reportSecurityLibraryVersions(ctx, database)
	if threat != "" || crawler != "" {
		t.Fatalf("空源必须为空串（前端显示未更新），got %q/%q", threat, crawler)
	}
}

func TestCompareLibraryVersion_matchesFrontendSemantics(t *testing.T) {
	cases := []struct {
		a, b string
		want int
	}{
		{"2026.09.24", "2026.10.01", -1},
		{"2026.10.01", "2026.09.24", 1},
		{"v2.3.3", "v2.3.10", -1},
		{"2026.09", "2026.09.24", -1},
		{"v1.0.0", "1.0.0", 0},
		{"2026-10-01", "2026-10-02", -1},
	}
	for _, tc := range cases {
		if got := compareLibraryVersion(tc.a, tc.b); got != tc.want {
			t.Errorf("compareLibraryVersion(%q,%q)=%d, want %d", tc.a, tc.b, got, tc.want)
		}
	}
}
