package geoipnames

import "testing"

// 共享表内容钉（PLUG-N3，第 72 轮）：四张表从 internal/services 与
// caddygeoip 的镜像双份收敛为单源——钉条目数（防意外截断/漏行）与关键
// 映射（防键值漂移）。条目数基线取自收敛前镜像测试的核验值
// （22/13/45/31，两侧逐条人工比对一致）。
func TestGeoipNamesTables_pinnedCountsAndSpotMappings(t *testing.T) {
	// Given/When/Then：条目数钉
	counts := []struct {
		name string
		got  int
		want int
	}{
		{"ProvinceAliases", len(ProvinceAliases), 22},
		{"TaiwanCities", len(TaiwanCities), 13},
		{"CityPinyinFixes", len(CityPinyinFixes), 45},
		{"AutonomousPrefectures", len(AutonomousPrefectures), 31},
	}
	for _, c := range counts {
		if c.got != c.want {
			t.Errorf("%s entries=%d; want %d (表内容变动须显式更新本钉——漂移曾致城市级地域规则静默恒不命中)", c.name, c.got, c.want)
		}
	}

	// And：关键映射抽查（每表至少一对键值/成员）
	if got := ProvinceAliases["广西"]; got != "广西壮族自治区" {
		t.Errorf("ProvinceAliases[广西]=%q; want 广西壮族自治区", got)
	}
	if got := ProvinceAliases["UEruemqi"]; got != "新疆维吾尔自治区" {
		t.Errorf("ProvinceAliases[UEruemqi]=%q; want 新疆维吾尔自治区（乱码段回收）", got)
	}
	if !TaiwanCities["台中市"] {
		t.Error("TaiwanCities must contain 台中市（误入省列的台湾城市）")
	}
	if got := CityPinyinFixes["Wulumuqi"]; got != "乌鲁木齐市" {
		t.Errorf("CityPinyinFixes[Wulumuqi]=%q; want 乌鲁木齐市", got)
	}
	if got := AutonomousPrefectures["大理"]; got != "大理白族自治州" {
		t.Errorf("AutonomousPrefectures[大理]=%q; want 大理白族自治州（不可盲加市字）", got)
	}
	if _, ok := AutonomousPrefectures["九龙"]; ok {
		t.Error("九龙是地区名非城市，不得入 AutonomousPrefectures（保持原值）")
	}
}

// 域 G（第 73 轮）：海外国家名归一表 + NormalizeCountry 行为钉。表内容数据
// 驱动——dev 容器 v3.18.0 xdb 全量扫描（240 个国家列值）：238 个英文规范名
// 原样通过、中文异体「美国」（美国国防部段）折叠为规范名、非国家值
// 「Reserved」（文档/保留段）映射空串（按海外兜底，不入树、不发国名）。
func TestGeoipNames_overseasCountriesTableAndNormalize(t *testing.T) {
	if len(OverseasCountries) != 2 {
		t.Errorf("OverseasCountries entries=%d; want 2（表内容变动须显式更新本钉）", len(OverseasCountries))
	}
	if got := OverseasCountries["美国"]; got != "United States" {
		t.Errorf("OverseasCountries[美国]=%q; want United States（中文异体折叠）", got)
	}
	if got := OverseasCountries["Reserved"]; got != "" {
		t.Errorf("OverseasCountries[Reserved]=%q; want 空串（保留段非国家，兜底海外）", got)
	}
	cases := []struct{ raw, want string }{
		{"", ""},                           // 空值
		{"0", ""},                          // xdb 无效占位
		{"  0  ", ""},                      // 带空白占位
		{"美国", "United States"},            // 异体折叠
		{"Reserved", ""},                   // 非国家 → 兜底
		{"United States", "United States"}, // 规范名原样通过
		{"Japan", "Japan"},                 // 未列入表的规范名原样通过（纯白名单过滤）
	}
	for _, tc := range cases {
		if got := NormalizeCountry(tc.raw); got != tc.want {
			t.Errorf("NormalizeCountry(%q)=%q; want %q", tc.raw, got, tc.want)
		}
	}
}
