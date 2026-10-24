package geoipnames

import "testing"

// 共享表内容钉：四张表从 internal/services 与
// caddygeoip 的镜像双份收敛为单源——钉条目数（防意外截断/漏行）与关键
// 映射（防键值漂移）。条目数基线取自收敛前镜像测试的核验值
// （22/13/45/31，两侧逐条人工比对一致）；自此 provinceAliases
// 剔除 11 条恒等别名（key==value 死条目，未命中即原样返回不影响输出），
// 基线 22→11，并加零恒等钉防回潮。补 Taichung County→台中市（仓库夹具
// 独有段），cityPinyinFixes 基线 45→46，服务层以仓库 xdb 全段扫描同步
// 验收。映射值钉现行行政区划：邯山区（非含山区）、临邑县（非临沂县）、
// 虢镇（非郭镇）、丰原区/台中市（2010 年台中县市合并后名）。
func TestGeoipNamesTables_pinnedCountsAndSpotMappings(t *testing.T) {
	// Given/When/Then：条目数钉
	counts := []struct {
		name string
		got  int
		want int
	}{
		{"provinceAliases", len(provinceAliases), 11},
		{"TaiwanCities", len(TaiwanCities), 13},
		{"cityPinyinFixes", len(cityPinyinFixes), 46},
		{"autonomousPrefectures", len(autonomousPrefectures), 31},
	}
	for _, c := range counts {
		if c.got != c.want {
			t.Errorf("%s entries=%d; want %d (表内容变动须显式更新本钉——漂移曾致城市级地域规则静默恒不命中)", c.name, c.got, c.want)
		}
	}

	// And：零恒等映射钉（恒等别名是死条目，canonical* 未命中
	// 本就原样返回）
	for name, table := range map[string]map[string]string{
		"provinceAliases":       provinceAliases,
		"cityPinyinFixes":       cityPinyinFixes,
		"autonomousPrefectures": autonomousPrefectures,
		"overseasCountries":     overseasCountries,
	} {
		for k, v := range table {
			if k == v {
				t.Errorf("%s 含恒等映射 %q（死条目，删除）", name, k)
			}
		}
	}

	// And：关键映射抽查（每表至少一对键值/成员）
	if got := provinceAliases["广西"]; got != "广西壮族自治区" {
		t.Errorf("provinceAliases[广西]=%q; want 广西壮族自治区", got)
	}
	if got := provinceAliases["UEruemqi"]; got != "新疆维吾尔自治区" {
		t.Errorf("provinceAliases[UEruemqi]=%q; want 新疆维吾尔自治区（乱码段回收）", got)
	}
	if !TaiwanCities["台中市"] {
		t.Error("TaiwanCities must contain 台中市（误入省列的台湾城市）")
	}
	if got := cityPinyinFixes["Wulumuqi"]; got != "乌鲁木齐市" {
		t.Errorf("cityPinyinFixes[Wulumuqi]=%q; want 乌鲁木齐市", got)
	}
	if got := cityPinyinFixes["Taichung County"]; got != "台中市" {
		t.Errorf("cityPinyinFixes[Taichung County]=%q; want 台中市（2010 年县市合并）", got)
	}
	// And：现行行政区划纠错钉（v3.17.0 生产库段属列逐条核对：
	// 河北省邯山区/山东省临邑县/陕西省虢镇/台湾省丰原区）
	for key, want := range map[string]string{
		"Hanshan Qu": "邯山区",
		"Linyi Xian": "临邑县",
		"Guozhen":    "虢镇",
		"Fengyuan":   "丰原区",
	} {
		if got := cityPinyinFixes[key]; got != want {
			t.Errorf("cityPinyinFixes[%s]=%q; want %s", key, got, want)
		}
	}
	if got := autonomousPrefectures["大理"]; got != "大理白族自治州" {
		t.Errorf("autonomousPrefectures[大理]=%q; want 大理白族自治州（不可盲加市字）", got)
	}
	if _, ok := autonomousPrefectures["九龙"]; ok {
		t.Error("九龙是地区名非城市，不得入 autonomousPrefectures（保持原值）")
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

// 域 G：海外国家名归一表 + NormalizeCountry 行为钉。表内容数据
// 驱动——dev 容器 v3.18.0 xdb 全量扫描（240 个国家列值）：238 个英文规范名
// 原样通过、中文异体「美国」（美国国防部段）折叠为规范名、非国家值
// 「Reserved」（文档/保留段）映射空串（按海外兜底，不入树、不发国名）。
func TestGeoipNames_overseasCountriesTableAndNormalize(t *testing.T) {
	if len(overseasCountries) != 2 {
		t.Errorf("overseasCountries entries=%d; want 2（表内容变动须显式更新本钉）", len(overseasCountries))
	}
	if got := overseasCountries["美国"]; got != "United States" {
		t.Errorf("overseasCountries[美国]=%q; want United States（中文异体折叠）", got)
	}
	if got := overseasCountries["Reserved"]; got != "" {
		t.Errorf("overseasCountries[Reserved]=%q; want 空串（保留段非国家，兜底海外）", got)
	}
	cases := []struct{ raw, want string }{
		{"", ""},                           // 空值
		{"0", ""},                          // xdb 无效占位
		{"  0  ", ""},                      // 带空白占位
		{"美国", "United States"},            // 异体折叠
		{"Reserved", ""},                   // 非国家 → 兜底
		{"United States", "United States"}, // 规范名原样通过
		{"Japan", "Japan"},                 // 未列入表的规范名原样通过（纯白名单过滤）
		// 「中国」走国内分支非海外国——显式归一空串（不入树、
		// 不发国名，发射侧回落海外哨兵判定由国内分支接管）；含空白形态一并
		// 归一（TrimSpace 对称——树侧判定本就 Trim，发射侧此前裸比较）。
		{"中国", ""},
		{" 中国 ", ""},
	}
	for _, tc := range cases {
		if got := NormalizeCountry(tc.raw); got != tc.want {
			t.Errorf("NormalizeCountry(%q)=%q; want %q", tc.raw, got, tc.want)
		}
	}
}
