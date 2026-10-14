package geoipnames

import "testing"

// 共享表内容钉（PLUG-N3，历史）：四张表从 internal/services 与
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

// 海外国家中文名表（v2.3.7 修正，用户反馈：GeoIP 选择器与归属地海外行裸显
// 英文国名）——CountryNamesCN 键集与 v3.18.0 xdb 国家列归一后的 238 个规范
// 英文国名逐一对应（探针全量扫描实证集，dev 容器 regions.json 缓存对齐）；
// 中文译名取 ISO 3166 常用中文简称。「中国」行走国内分支、「Reserved」行走
// 保留地址分支，均不进本表；CountryChinese 对未收录名回退原名（未来 xdb
// 新增国名优雅降级英文，不产生死条目）。
func TestGeoipNames_countryChineseTableAndFallback(t *testing.T) {
	if len(CountryNamesCN) != 238 {
		t.Errorf("CountryNamesCN entries=%d; want 238（v3.18.0 xdb 国家列全集；表内容变动须显式更新本钉）", len(CountryNamesCN))
	}
	// 代表性映射钉（大/常客国家 + 非 ASCII 特殊字符键必须原样收录）
	cases := []struct{ en, zh string }{
		{"United States", "美国"},
		{"Japan", "日本"},
		{"Russia", "俄罗斯"},
		{"United Kingdom", "英国"},
		{"Germany", "德国"},
		{"France", "法国"},
		{"South Korea", "韩国"},
		{"Singapore", "新加坡"},
		{"Côte d'Ivoire", "科特迪瓦"},
		{"Curaçao", "库拉索"},
		{"Réunion", "留尼汪"},
		{"Türkiye", "土耳其"},
		{"Åland", "奥兰"},
	}
	for _, tc := range cases {
		if got := CountryNamesCN[tc.en]; got != tc.zh {
			t.Errorf("CountryNamesCN[%q]=%q; want %q", tc.en, got, tc.zh)
		}
		if got := CountryChinese(tc.en); got != tc.zh {
			t.Errorf("CountryChinese(%q)=%q; want %q", tc.en, got, tc.zh)
		}
	}
	// 无映射回退原名（导出语义：永不空串、永不改动未收录名）
	for _, name := range []string{"China", "Reserved", "火星国", ""} {
		if got := CountryChinese(name); got != name {
			t.Errorf("CountryChinese(%q)=%q; want 原名回退", name, got)
		}
	}
	// 键集卫生：本表只收规范英文国名——中文异体由 NormalizeCountry 前置折叠、
	// 空串非国家，键集不得混入（含 CJK 字符的键即表被污染）。
	for en := range CountryNamesCN {
		if en == "" {
			t.Error("CountryNamesCN must not contain empty key")
			continue
		}
		for _, r := range en {
			if r >= 0x4E00 && r <= 0x9FFF {
				t.Errorf("CountryNamesCN key %q contains CJK（中文异体属 NormalizeCountry 职责，本表只收规范英文名）", en)
				break
			}
		}
	}
}

// 域 G（历史）：海外国家名归一表 + NormalizeCountry 行为钉。表内容数据
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
