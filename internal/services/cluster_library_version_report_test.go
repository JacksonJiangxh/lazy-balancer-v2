package services

import (
	"context"
	"os"
	"path/filepath"
	"strconv"
	"strings"
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

// 跨栈共享夹具：web/tests/fixtures/version-compare.tsv 同时被前端
// compareVersion 用例读取——两端各自维护一份用例表曾让「缺段 vs 数值 0」
// 的口径分叉（Go 走字符串兜底返回 -1，前端按 0 判等价）而两边都绿。
func TestCompareLibraryVersion_matchesFrontendSemantics(t *testing.T) {
	data, err := os.ReadFile(filepath.Join("..", "..", "web", "tests", "fixtures", "version-compare.tsv"))
	if err != nil {
		t.Fatalf("读取跨栈夹具: %v", err)
	}
	checked := 0
	for lineNo, line := range strings.Split(string(data), "\n") {
		if strings.HasPrefix(line, "#") || strings.TrimSpace(line) == "" {
			continue
		}
		fields := strings.Split(line, "\t")
		if len(fields) != 3 {
			t.Fatalf("夹具第 %d 行字段数=%d, want 3: %q", lineNo+1, len(fields), line)
		}
		want, convErr := strconv.Atoi(strings.TrimSpace(fields[2]))
		if convErr != nil {
			t.Fatalf("夹具第 %d 行期望符号非法: %q", lineNo+1, fields[2])
		}
		if got := compareLibraryVersion(fields[0], fields[1]); got != want {
			t.Errorf("夹具第 %d 行 compareLibraryVersion(%q,%q)=%d, want %d", lineNo+1, fields[0], fields[1], got, want)
		}
		if got := compareLibraryVersion(fields[1], fields[0]); got != -want {
			t.Errorf("夹具第 %d 行反向比较(%q,%q)=%d, want %d", lineNo+1, fields[1], fields[0], got, -want)
		}
		checked++
	}
	if checked == 0 {
		t.Fatal("跨栈夹具为空")
	}
}

// 聚合口径与前端 sort+pop 同序：等值（如 1.2 与 1.2.0）取行序后者，
// 与 API ORDER BY id 的稳定排序一致，避免主节点 hover 与从节点列表
// 对同一条库显示不同形态的「最近版本」。
func TestLatestSourceVersion_tieKeepsLastRowLikeFrontend(t *testing.T) {
	_, database := newClusterTestService(t)
	ctx := context.Background()
	if _, err := database.Exec(`UPDATE security_threat_sources SET version=''`); err != nil {
		t.Fatal(err)
	}
	if _, err := database.Exec(`UPDATE security_threat_sources SET version='1.2.0' WHERE id=(SELECT MIN(id) FROM security_threat_sources)`); err != nil {
		t.Fatal(err)
	}
	if _, err := database.Exec(`UPDATE security_threat_sources SET version='1.2' WHERE id=(SELECT MAX(id) FROM security_threat_sources)`); err != nil {
		t.Fatal(err)
	}
	if got := latestSourceVersion(ctx, database, "security_threat_sources"); got != "1.2" {
		t.Fatalf("latestSourceVersion=%q, want 1.2（等值取行序后者，与前端 sort+pop 一致）", got)
	}
}
