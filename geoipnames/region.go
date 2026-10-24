package geoipnames

import "strings"

// 省/市列规范化的单一实现。此前 internal/services 与
// caddygeoip 各持一份手工镜像函数（normalizeIP2Province/normalizeProvince、
// normalizeIP2City/normalizeCity），语义分叉靠调用点补偿——正是单源
// 要消灭的「双端漂移 → 城市级规则静默恒不命中」形态，只是从表挪到了函数。
//
// 本文件收敛表驱动 core，两端只保留**显式声明的策略差异**：
//   - Tree（选项树，internal/services）：过滤无效值（空/"0"）与未映射 ASCII
//     （不可靠音译，宁缺勿乱）；
//   - Emit（CEL 发射，caddygeoip）：过滤无效值；台湾城市误置省列时补「台湾省」
//     （树侧该段归入台湾省城市集）；未映射 ASCII 原样发射（恒不命中，与
//     不可识别省同语义）。
//
// 新增映射只改本包表；两端不得各自加归一分支——策略差异必须落在本文件。

// invalidRegionValue 无效值（空/0）判定（xdb 无效占位；TrimSpace 已由调用方
// 完成）。
func invalidRegionValue(trimmed string) bool {
	return trimmed == "" || trimmed == "0"
}

// canonicalProvince 表驱动省列归一：别名命中返回规范名（known=true）；
// 台湾城市误置省列返回 ("", taiwanCity=true)；其余原样返回 trimmed
// （known=false，由调用方按 tree/emit 策略处理）。
func canonicalProvince(trimmed string) (name string, taiwanCity, known bool) {
	if canonical, ok := provinceAliases[trimmed]; ok {
		return canonical, false, true
	}
	if TaiwanCities[trimmed] {
		return "", true, true
	}
	return trimmed, false, false
}

// canonicalCity 表驱动城市列归一：拼音映射/自治州全称命中返回规范名
// （known=true）；其余原样返回 trimmed。
func canonicalCity(trimmed string) (name string, known bool) {
	if fixed, ok := cityPinyinFixes[trimmed]; ok {
		return fixed, true
	}
	// 少数民族自治州简称 → 全称。
	if full, ok := autonomousPrefectures[trimmed]; ok {
		return full, true
	}
	return trimmed, false
}

// ProvinceForTree 选项树侧省列规范化：无效值/未映射 ASCII → 空串；台湾城市
// （误置省列）→ 空串（由调用方归入台湾省城市集）；其余返回表归一结果。
func ProvinceForTree(raw string) string {
	trimmed := strings.TrimSpace(raw)
	if invalidRegionValue(trimmed) {
		return ""
	}
	name, taiwanCity, known := canonicalProvince(trimmed)
	if taiwanCity {
		return ""
	}
	// ASCII 省名是乱码/拼音残片（如 UEruemqi），xdb 中文省列恒为多字节——
	// 未命中别名的 ASCII 过滤（命中别名者已回收为规范中文）。
	if !known && trimmed[0] < 0x80 {
		return ""
	}
	return name
}

// ProvinceForEmit 发射侧（CEL 变量/响应头）省列规范化：无效值 → 空串；
// 台湾城市误置省列 → 「台湾省」；其余返回表归一结果（未映射 ASCII 原样，
// 策略树不提供该值，恒不命中）。
func ProvinceForEmit(raw string) string {
	trimmed := strings.TrimSpace(raw)
	if invalidRegionValue(trimmed) {
		return ""
	}
	name, taiwanCity, _ := canonicalProvince(trimmed)
	if taiwanCity {
		return "台湾省"
	}
	return name
}

// CityForTree 选项树侧城市列规范化：无效值/未映射 ASCII → 空串；其余返回
// 表归一结果（拼音/自治州已映射为规范中文）。
func CityForTree(raw string) string {
	trimmed := strings.TrimSpace(raw)
	if invalidRegionValue(trimmed) {
		return ""
	}
	name, known := canonicalCity(trimmed)
	if !known && trimmed[0] < 0x80 {
		return ""
	}
	return name
}

// CityForEmit 发射侧城市列规范化：无效值 → 空串；其余返回表归一结果
// （未映射 ASCII 原样——选项树已过滤、策略不会配置，发射原值恒不命中）。
func CityForEmit(raw string) string {
	trimmed := strings.TrimSpace(raw)
	if invalidRegionValue(trimmed) {
		return ""
	}
	name, _ := canonicalCity(trimmed)
	return name
}
