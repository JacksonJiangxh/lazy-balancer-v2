package services

import (
	"path/filepath"
	"strings"
	"testing"
)

// 库缺失描述必须复用同一次探测结果：SecurityLibraryStatus 含 rules 树
// WalkDir + xdb stat，此前描述函数内部重探，单规则路径因此每规则多扫 1~2 轮。
func TestSecurityLibrariesMissingDesc_reportsProbedComponents(t *testing.T) {
	cases := []struct {
		crsOK, ip2regionOK bool
		want               string
	}{
		{true, true, ""},
		{false, true, "CRS 规则库"},
		{true, false, "IP 地址库（IP2Region）"},
		{false, false, "CRS 规则库、IP 地址库（IP2Region）"},
	}
	for _, tc := range cases {
		if got := securityLibrariesMissingDesc(tc.crsOK, tc.ip2regionOK); got != tc.want {
			t.Errorf("securityLibrariesMissingDesc(%v,%v)=%q; want %q", tc.crsOK, tc.ip2regionOK, got, tc.want)
		}
	}
	if !strings.Contains(securityLibrariesMissingDesc(false, false), "、") {
		t.Error("两类库同时缺失时描述必须列出两项")
	}
}

// 索引的键与产物必须同代同源：Version 来自与缓存键同一次版本读数，同代
// 再次调用命中同一实例（分开读会把新代产物挂到旧键上并多一次全量重建）。
func TestGetCRSRuleIndex_versionAndCacheKeyShareGeneration(t *testing.T) {
	root := t.TempDir()
	rules := filepath.Join(root, "rules")
	writeTestFile(t, filepath.Join(rules, "REQUEST-901.conf"), `SecRule REQUEST_URI "@rx probe" "id:900001,phase:1,deny"`+"\n")
	restore := SetSecurityLibsDirsForTest(root, filepath.Join(root, "ip2region.xdb"))
	t.Cleanup(restore)
	resetCRSRuleIndexCacheForHardeningTest(t)

	index := GetCRSRuleIndex()
	if index.Version != crsRuleIndexVersion() {
		t.Fatalf("索引版本(%q)必须与缓存键同源版本读数(%q)一致", index.Version, crsRuleIndexVersion())
	}
	if again := GetCRSRuleIndex(); again != index {
		t.Fatal("同代必须命中同一缓存实例")
	}
	if len(index.Rules) != 1 || index.Rules[0].ID != "900001" {
		t.Fatalf("索引产物异常: %+v", index.Rules)
	}
}
