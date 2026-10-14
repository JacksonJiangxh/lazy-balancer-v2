package services

// 域 G（第 73 轮）：GeoIP 海外国家细化——地域树收集 Countries、缓存修订
// r27、校验并入国名、geoipLocOperator 国名精确匹配、预检渲染国名条目。

import (
	"encoding/json"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"

	"lazy-balancer-v2/internal/models"
)

// TestRegionTreeFromXDB_countriesCollected：海外分支收集国名——美国异体折叠
// 为规范名、Reserved/0/空非国家值不入树、多段同名去重、英文名（ASCII）是
// 本库形态不做 ASCII 过滤（与省列的拼音残片语义不同：国家列在 v3.18.0
// 全部为完整英文国名，探针实证 240 值中 238 个 ASCII 规范名）。
func TestRegionTreeFromXDB_countriesCollected(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "ip2region.xdb")
	writeTestXDB(t, path, []xdbSegment{
		{startIP: 0x01020300, endIP: 0x010203FF, region: "中国|广东省|深圳市|0|CN"},
		{startIP: 0x01020400, endIP: 0x010204FF, region: "美国|0|0|0|US"},
		{startIP: 0x01020500, endIP: 0x010205FF, region: "Reserved|Reserved|Reserved|0|0"},
		{startIP: 0x01020600, endIP: 0x010206FF, region: "0|0|0|0"},
		{startIP: 0x01020700, endIP: 0x010207FF, region: "United States|California|0|0|US"},
		{startIP: 0x01020800, endIP: 0x010208FF, region: "Japan|Tokyo|0|0|JP"},
	})
	tree := regionTreeFromXDB(path)
	if tree == nil {
		t.Fatal("scan returned nil tree")
	}
	want := []string{"Japan", "United States"}
	if len(tree.Countries) != len(want) {
		t.Fatalf("countries=%v; want %v（美国折叠、Reserved/0 过滤、同名去重）", tree.Countries, want)
	}
	for i, c := range want {
		if tree.Countries[i] != c {
			t.Fatalf("countries[%d]=%q; want %q（排序：ASCII 字节序）", i, tree.Countries[i], c)
		}
	}
	// 省份/城市收集不受海外分支影响（回归形状）。
	if len(tree.Provinces) != 2 || tree.Provinces[0] != "广东省" || tree.Provinces[1] != "海外" {
		t.Fatalf("provinces=%v; want [广东省 海外]", tree.Provinces)
	}
	if len(tree.Cities["广东省"]) != 1 || tree.Cities["广东省"][0] != "深圳市" {
		t.Fatalf("cities[广东省]=%v; want [深圳市]", tree.Cities["广东省"])
	}
}

// TestRegionTree_countriesCacheJSON：树缓存（= GetIP2RegionRegions API 的序列
// 化源）携带 countries 字段——json tag 拼写错误会让前端拿不到国名集。
func TestRegionTree_countriesCacheJSON(t *testing.T) {
	dir := t.TempDir()
	live := filepath.Join(dir, "ip2region.xdb")
	writeTestXDB(t, live, []xdbSegment{
		{startIP: 0x01020300, endIP: 0x010203FF, region: "中国|广东省|深圳市|0|CN"},
		{startIP: 0x01020400, endIP: 0x010204FF, region: "美国|0|0|0|US"},
	})
	withIP2RegionPaths(t, live, filepath.Join(dir, "missing.xdb"))
	tree := GetIP2RegionRegionTree()
	if tree == nil {
		t.Fatal("tree nil for live fixture")
	}
	data, err := json.Marshal(tree)
	if err != nil {
		t.Fatal(err)
	}
	var roundTrip map[string]json.RawMessage
	if err := json.Unmarshal(data, &roundTrip); err != nil {
		t.Fatal(err)
	}
	if _, ok := roundTrip["countries"]; !ok {
		t.Fatalf("tree JSON missing countries key: %s", data)
	}
	// 缓存文件同序列化链（writeRegionTreeCache → regions.json）。
	cache, err := os.ReadFile(live + ".regions.json")
	if err == nil {
		if !strings.Contains(string(cache), `"countries"`) {
			t.Fatalf("regions.json cache missing countries key: %s", cache)
		}
	}
}

// TestStaleRegionTreeCache_r27_invalidatesR26Cache：修订号 bump（r26→r27）是
// 旧缓存失效的唯一机制——r26 旧形态（无 countries）缓存必须判过期重建，否则
// 升级部署后选项树静默缺国家集。
func TestStaleRegionTreeCache_r27_invalidatesR26Cache(t *testing.T) {
	dir := t.TempDir()
	live := filepath.Join(dir, "ip2region.xdb")
	cachePath := live + ".regions.json"
	oldShape := `{"revision":"r26","provinces":["广东省","海外"],"cities":{"广东省":["深圳市"]}}`
	if err := os.WriteFile(cachePath, []byte(oldShape), 0o644); err != nil {
		t.Fatal(err)
	}
	withIP2RegionPaths(t, live, filepath.Join(dir, "missing.xdb"))
	if !staleRegionTreeCache(cachePath) {
		t.Fatal("r26 cache must be stale after r27 bump（旧缓存静默缺 countries）")
	}
	// 当前修订号产物（携带 countries）不判过期——回归形状。
	fresh := `{"revision":"` + treeCacheRevision + `","provinces":["广东省","海外"],"cities":{"广东省":["深圳市"]},"countries":["United States"]}`
	if err := os.WriteFile(cachePath, []byte(fresh), 0o644); err != nil {
		t.Fatal(err)
	}
	if staleRegionTreeCache(cachePath) {
		t.Fatal("current-revision cache with countries must not be stale")
	}
	// r27 缓存里的空串国名条目（带外手改形态）判过期——与省/市空串守卫同款。
	tampered := strings.Replace(fresh, `"countries":["United States"]`, `"countries":[""]`, 1)
	if err := os.WriteFile(cachePath, []byte(tampered), 0o644); err != nil {
		t.Fatal(err)
	}
	if !staleRegionTreeCache(cachePath) {
		t.Fatal("cache with empty-string country must be stale")
	}
}

// TestValidateGeoIPCountries_acceptsOverseasCountries：known 集并入树
// Countries——国名条目放行、未知国名仍拒（发射端永不匹配的条目静默削弱
// 地域控制的既有口径）。
func TestValidateGeoIPCountries_acceptsOverseasCountries(t *testing.T) {
	dir := t.TempDir()
	live := filepath.Join(dir, "ip2region.xdb")
	writeTestXDB(t, live, []xdbSegment{
		{startIP: 0x01020300, endIP: 0x010203FF, region: "中国|广东省|深圳市|0|CN"},
		{startIP: 0x01020400, endIP: 0x010204FF, region: "美国|0|0|0|US"},
	})
	withIP2RegionPaths(t, live, filepath.Join(dir, "missing.xdb"))
	oldProvinces := ip2RegionLiveProvincesOverride
	SetIP2RegionLiveProvincesForTest([]string{"广东省", "海外"})
	t.Cleanup(func() { SetIP2RegionLiveProvincesForTest(oldProvinces) })

	if err := ValidateGeoIPCountries(`["United States"]`, "deny"); err != nil {
		t.Fatalf("tree country must validate, got %v", err)
	}
	if err := ValidateGeoIPCountries(`["海外","United States","广东省"]`, "deny"); err != nil {
		t.Fatalf("mixed entries must validate, got %v", err)
	}
	if err := ValidateGeoIPCountries(`["火星国"]`, "deny"); err == nil {
		t.Fatal("unknown country must be rejected")
	}
	// 国名做省/市联值前缀不允许（城市不在任何省的城市集内）。
	if err := ValidateGeoIPCountries(`["United States/California"]`, "deny"); err == nil {
		t.Fatal("country/city compound must be rejected")
	}
}

// TestGeoipLocOperator_countryEntriesExact：国名条目 ∈ Countries 集时精确匹配
// （不加 (?:/.*)? 后缀，与「海外」同款裁定）——caddygeoip 对海外行只发国名
// 单值，精确匹配杜绝未来复合形态误命中；省份条目维持整省后缀语义。
func TestGeoipLocOperator_countryEntriesExact(t *testing.T) {
	exact := map[string]bool{"United States": true}
	deny := geoipLocOperator([]string{"广东省", "United States", "海外"}, false, exact)
	if !strings.Contains(deny, `广东省(?:/.*)?`) {
		t.Fatalf("province entry must keep whole-province suffix: %s", deny)
	}
	if !strings.Contains(deny, `United States`) || strings.Contains(deny, `United States(?:/.*)?`) {
		t.Fatalf("country entry must be exact (no suffix): %s", deny)
	}
	if !strings.Contains(deny, `海外`) || strings.Contains(deny, `海外(?:/.*)?`) {
		t.Fatalf("overseas sentinel must stay exact: %s", deny)
	}
	re, err := regexp.Compile(strings.TrimPrefix(deny, "@rx "))
	if err != nil {
		t.Fatal(err)
	}
	cases := []struct {
		loc  string
		want bool
	}{
		{"United States", true},             // 国名精确命中
		{"United States/California", false}, // 复合形态不得命中（发射端无此形态）
		{"United Statess", false},           // 前缀串不得命中（锚定全值）
		{"广东省", true},                       // 省份回归
		{"广东省/深圳市", true},                   // 省内城市段命中整省条目
		{"海外", true},                        // 哨兵回归
		{"", false},                         // 空串 deny 不误伤
	}
	for _, tc := range cases {
		if got := re.MatchString(tc.loc); got != tc.want {
			t.Fatalf("match(%q)=%v; want %v", tc.loc, got, tc.want)
		}
	}
	// 空集（树缺失/无国名）：国名条目退回后缀形态——对国名单值仍命中
	//（(?:/.*)? 可选），fail-safe 不放大拦截面。
	noSet := geoipLocOperator([]string{"United States"}, false, nil)
	if !strings.Contains(noSet, `United States(?:/.*)?`) {
		t.Fatalf("empty-set fallback must keep suffix form: %s", noSet)
	}
}

// TestBuildIPPrecheckDirectives_geoipCountryEntries（R-10）：真实渲染产物含
// 国名条目策略形状——国名精确/省份后缀/海外哨兵三形态并存，送 coraza
// NewWAF 编译（引擎约束只在编译可见）。
func TestBuildIPPrecheckDirectives_geoipCountryEntries(t *testing.T) {
	dir := t.TempDir()
	live := filepath.Join(dir, "ip2region.xdb")
	writeTestXDB(t, live, []xdbSegment{
		{startIP: 0x01020300, endIP: 0x010203FF, region: "中国|广东省|深圳市|0|CN"},
		{startIP: 0x01020400, endIP: 0x010204FF, region: "美国|0|0|0|US"},
	})
	withIP2RegionPaths(t, live, filepath.Join(dir, "missing.xdb"))
	p := &models.SecurityPolicy{
		ID: 7, Mode: "off", GeoIPMode: "deny",
		GeoIPCountries: json.RawMessage(`["海外","United States","广东省"]`),
	}
	directives := mustDirectives(buildIPPrecheckDirectives([]*models.SecurityPolicy{p}, 0))
	if !strings.Contains(directives, `广东省(?:/.*)?`) {
		t.Fatalf("province entry must keep suffix form:\n%s", directives)
	}
	if !strings.Contains(directives, `United States`) || strings.Contains(directives, `United States(?:/.*)?`) {
		t.Fatalf("country entry must compile exact (tree countries feed the exact set):\n%s", directives)
	}
	compileForEngineGate(t, directives)
}
