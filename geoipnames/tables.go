// Package geoipnames 承载 ip2region 地理规范化的四张共享表——单一数据源
// （历史修复，历史）。消费方两侧：
//
//   - internal/services（选项树构建 regionTreeFromXDB → GetIP2RegionRegions）
//   - caddygeoip（发射 X-LB-GeoIP-Loc 匹配键，normalizeCity/normalizeProvince）
//
// 此前四张表两侧手工镜像（叶子 Caddy 模块不可 import internal 包），靠
// geoip_mirror_tables_test.go 解析对侧源文本绊线防漂移——本包取代镜像：
// 中立叶模块，根 go.mod 与 caddygeoip/go.mod 各经 replace 引用（与
// wafiplist 叶模块同接线：Dockerfile xcaddy --with + COPY，backend 阶段
// go.mod 先拷）。漂移失效形态（选项树提供某省/市而发射变量发另一形态 →
// 城市级地域规则静默恒不命中）由单源根治，修改只改本包一处。
//
// 所有导出表均为进程级**只读**全局数据：消费方只读取，禁止修改（写入会同时
// 污染选项树与发射两端；新增映射请改表本身并同步 tables_test 钉值）。
package geoipnames

import "strings"

// ProvinceAliases 省列别名规范化（历史问题）：xdb 原始省列存在双形态
// （上海/上海市、广西/广西壮族自治区）、台湾城市误入省列（台中市等）与个别
// 乱码（UEruemqi）。选项树与 CEL 发射变量统一用规范名，两边一致才能命中。
// 只收**非恒等**映射（历史修复）：canonicalProvince 未命中即原样返回，
// 恒等别名（如「上海市」→「上海市」）不改变任何输出，属死条目。
// 只读：禁止修改（全局单份）。
var ProvinceAliases = map[string]string{
	// v3.17.0 段 (UEruemqi, Wulumuqi)：省列是城市名 Ürümqi 的乱码转写、城市列
	// 拼音已可映射——别名把该段回收为 新疆维吾尔自治区/乌鲁木齐市（此前整段
	// 被丢弃，树缺这对省市）。
	"UEruemqi": "新疆维吾尔自治区",
	"北京":       "北京市", "上海": "上海市", "天津": "天津市", "重庆": "重庆市",
	"广西": "广西壮族自治区", "内蒙古": "内蒙古自治区",
	"西藏": "西藏自治区", "宁夏": "宁夏回族自治区",
	"新疆": "新疆维吾尔自治区", "台湾": "台湾省",
}

// TaiwanCities 台湾地区在 xdb 中误置于省列的城市——归入台湾省城市集。
// 只读：禁止修改（全局单份）。
var TaiwanCities = map[string]bool{
	"台北市": true, "新北市": true, "台中市": true, "台南市": true, "高雄市": true,
	"基隆市": true, "新竹市": true, "嘉义市": true, "新竹县": true, "彰化县": true,
	"桃园市": true, "云林县": true, "苗栗县": true,
}

// CityPinyinFixes xdb 部分段的城市列为拼音/英文形态（v3.17.0 实测 45 条，
// 如 Guangzhou Shi/Shanghai/Taipei City）——映射为规范中文名；不在此表的
// ASCII 城市由选项树侧过滤（宁缺勿乱，无法可靠音译）、发射侧原样通过
// （恒不命中，与不可识别省同语义）。历史问题起发射侧同步映射——
// 城市级 CEL 规则对拼音段可命中。
// 只读：禁止修改（全局单份）。
var CityPinyinFixes = map[string]string{
	"Wulumuqi": "乌鲁木齐市", "Shanghai": "上海市", "Beijing": "北京市",
	"Fengyuan": "丰原市", "Taipei City": "台北市", "Taichung County": "台中县", "Zhongli District": "中坜区",
	"Changchun Shi": "长春市", "Chengdu Shi": "成都市", "Tianjin": "天津市",
	"Fuyang Shi": "阜阳市", "Hefei Shi": "合肥市", "Heze Shi": "菏泽市",
	"Jining Shi": "济宁市", "Linyi Xian": "临沂县", "Weifang Shi": "潍坊市",
	"Dongguan Shi": "东莞市", "Foshan Shi": "佛山市", "Guangzhou Shi": "广州市",
	"Maoming Shi": "茂名市", "Shenzhen": "深圳市", "Zhuhai Shi": "珠海市",
	"Nanning Shi": "南宁市", "Nanjing Shi": "南京市", "Nantong Shi": "南通市",
	"Tongshan": "铜山区", "Yancheng Shi": "盐城市", "Ganzhou Shi": "赣州市",
	"Baoding Shi": "保定市", "Hanshan Qu": "含山区", "Langfang Shi": "廊坊市",
	"Shijiazhuang Shi": "石家庄市", "Nanyang Shi": "南阳市", "Zhengzhou Shi": "郑州市",
	"Zhoukou Shi": "周口市", "Zhumadian Shi": "驻马店市", "Ningbo Shi": "宁波市",
	"Wuhan Shi": "武汉市", "Xiangyang": "襄阳市", "Changsha Shi": "长沙市",
	"Hengyang Xian": "衡阳县", "Shenyang Shi": "沈阳市", "Chongqing": "重庆市",
	"Guozhen": "郭镇", "Xi'an Shi": "西安市", "Kowloon": "九龙",
}

// AutonomousPrefectures（历史问题，用户反馈：「大理/怒江/凉山缺市字」——
// 实为少数民族自治州的简称）xdb 对自治州存简称、对普通地级市存全称
// （如「呼和浩特市」），选项树里「大理」与「呼和浩特市」并列显得缺字。
// 简称 → 全称 映射。
// 注意不可盲加「市」：「大理市」是另一个县级市，全称是「大理白族自治州」。
// 港澳的「九龙/将军澳/新界/香港岛/澳门」是地区名非城市，不在此表（保持原值）。
// 只读：禁止修改（全局单份）。
var AutonomousPrefectures = map[string]string{
	// 云南（8 个自治州）
	"大理": "大理白族自治州", "怒江": "怒江傈僳族自治州", "楚雄": "楚雄彝族自治州",
	"红河": "红河哈尼族彝族自治州", "文山": "文山壮族苗族自治州", "西双版纳": "西双版纳傣族自治州",
	"德宏": "德宏傣族景颇族自治州", "迪庆": "迪庆藏族自治州",
	// 四川（3）
	"凉山": "凉山彝族自治州", "甘孜": "甘孜藏族自治州", "阿坝": "阿坝藏族羌族自治州",
	// 贵州（3）
	"黔东南": "黔东南苗族侗族自治州", "黔南": "黔南布依族苗族自治州", "黔西南": "黔西南布依族苗族自治州",
	// 湖南/湖北/吉林（3）
	"湘西": "湘西土家族苗族自治州", "恩施": "恩施土家族苗族自治州", "延边": "延边朝鲜族自治州",
	// 新疆（5）
	"伊犁": "伊犁哈萨克自治州", "昌吉": "昌吉回族自治州", "巴音郭楞": "巴音郭楞蒙古自治州",
	"克孜勒苏": "克孜勒苏柯尔克孜自治州", "博尔塔拉": "博尔塔拉蒙古自治州",
	// 青海（6）
	"海西": "海西蒙古族藏族自治州", "海北": "海北藏族自治州", "黄南": "黄南藏族自治州",
	"海南": "海南藏族自治州", "果洛": "果洛藏族自治州", "玉树": "玉树藏族自治州",
	// 甘肃（2）
	"临夏": "临夏回族自治州", "甘南": "甘南藏族自治州",
	// 地区（1：xdb 缺「地区」后缀）
	"大兴安岭": "大兴安岭地区",
}

// OverseasCountries 海外国家名归一表（域 G，历史）。xdb 国家列（region
// 第 1 列）非「中国」的行发射国名：v3.18.0 实测形态为完整英文国名（240 个
// 国家列值中 238 个 ASCII 规范名，探针全量扫描），与省列的「ASCII=拼音残片」
// 语义不同——国名列 ASCII 是规范形态，不做 ASCII 过滤。本表只处理已知异体：
//
//   - 「美国」：v3.18.0 存在唯一中文段（美国国防部）与 2 万余英文段并存，
//     折叠为规范名 United States，选项树与发射变量同归一才能命中；
//   - 「Reserved」：文档/保留段（RFC 5737 等）不是国家，映射空串——树不入
//     该条目、发射回落「海外」哨兵（fail-closed 兜底）。
//
// 未列入表的值原样通过（纯白名单过滤）：选项树收集与 CEL/头发射两侧共用
// NormalizeCountry，同进同出，不存在「树提供某国而发射变量发另一形态」的
// 漂移面（历史修复 单源立场）。
// 只读：禁止修改（全局单份）。
var OverseasCountries = map[string]string{
	"美国":       "United States",
	"Reserved": "",
}

// NormalizeCountry 规范 xdb 国家列原始值：空白/「0」占位/「中国」（国内分支
// 值，历史修复——含空白异形，与树侧 TrimSpace 判定对称）与归一表映射空串的
// 值（非国家）返回空串（调用方据此兜底「海外」哨兵/不入树）；其余原样或按
// 归一表折叠返回。
func NormalizeCountry(raw string) string {
	trimmed := strings.TrimSpace(raw)
	if trimmed == "" || trimmed == "0" || trimmed == "中国" {
		return ""
	}
	if canonical, ok := OverseasCountries[trimmed]; ok {
		return canonical
	}
	return trimmed
}

// CountryNamesCN 海外国家规范英文名 → 中文简称表（v2.3.7 修正，用户反馈：
// GeoIP 选择器与事件归属地海外行裸显英文国名）。键集与 v3.18.0 xdb 国家列
// 归一后的 238 个规范英文国名逐一对应（探针全量扫描实证，即地域树
// Countries 的全集）；中文取 ISO 3166 常用中文简称。消费方：
//
//   - internal/handlers（formatIP2RegionLocation 海外分支首段翻译——事件
//     列表/弹框归属地中文显示；X-LB-GeoIP-Loc 发射链零改动）
//   - /security/ip2region/regions 响应 country_names_cn 字段（前端级联
//     「海外国家」子节点中文标签）
//
// 「中国」行走国内分支、「Reserved」行在展示层走保留地址分支，均不进本表；
// 未收录名经 CountryChinese 回退原名（未来 xdb 新增国名优雅降级英文）。
// 只读：禁止修改（全局单份；本表直接进 API 响应，就地修改即污染响应）。
var CountryNamesCN = map[string]string{
	// A
	"Afghanistan": "阿富汗", "Albania": "阿尔巴尼亚", "Algeria": "阿尔及利亚",
	"American Samoa": "美属萨摩亚", "Andorra": "安道尔", "Angola": "安哥拉",
	"Anguilla": "安圭拉", "Antarctica": "南极洲", "Antigua and Barbuda": "安提瓜和巴布达",
	"Argentina": "阿根廷", "Armenia": "亚美尼亚", "Aruba": "阿鲁巴",
	"Australia": "澳大利亚", "Austria": "奥地利", "Azerbaijan": "阿塞拜疆",
	// B
	"Bahamas": "巴哈马", "Bahrain": "巴林", "Bangladesh": "孟加拉国",
	"Barbados": "巴巴多斯", "Belarus": "白俄罗斯", "Belgium": "比利时",
	"Belize": "伯利兹", "Benin": "贝宁", "Bermuda": "百慕大", "Bhutan": "不丹",
	"Bolivia": "玻利维亚", "Bosnia and Herzegovina": "波黑", "Botswana": "博茨瓦纳",
	"Brazil": "巴西", "British Indian Ocean Territory": "英属印度洋领地",
	"British Virgin Islands": "英属维尔京群岛", "Brunei Darussalam": "文莱",
	"Bulgaria": "保加利亚", "Burkina Faso": "布基纳法索", "Burundi": "布隆迪",
	// C
	"Cabo Verde": "佛得角", "Cambodia": "柬埔寨", "Cameroon": "喀麦隆",
	"Canada": "加拿大", "Caribbean Netherlands": "荷属加勒比区",
	"Cayman Islands": "开曼群岛", "Central African Republic": "中非",
	"Chad": "乍得", "Chile": "智利", "Colombia": "哥伦比亚", "Comoros": "科摩罗",
	"Congo": "刚果（布）", "Cook Islands": "库克群岛", "Costa Rica": "哥斯达黎加",
	"Croatia": "克罗地亚", "Cuba": "古巴", "Curaçao": "库拉索",
	"Cyprus": "塞浦路斯", "Czechia": "捷克", "Côte d'Ivoire": "科特迪瓦",
	// D
	"DR Congo": "刚果（金）", "Denmark": "丹麦", "Djibouti": "吉布提",
	"Dominica": "多米尼克", "Dominican Republic": "多米尼加",
	// E
	"Ecuador": "厄瓜多尔", "Egypt": "埃及", "El Salvador": "萨尔瓦多",
	"Equatorial Guinea": "赤道几内亚", "Eritrea": "厄立特里亚",
	"Estonia": "爱沙尼亚", "Eswatini": "斯威士兰", "Ethiopia": "埃塞俄比亚",
	// F
	"Falkland Islands": "福克兰群岛", "Faroe Islands": "法罗群岛",
	"Fiji": "斐济", "Finland": "芬兰", "France": "法国",
	"French Guiana": "法属圭亚那", "French Polynesia": "法属波利尼西亚",
	// G
	"Gabon": "加蓬", "Gambia": "冈比亚", "Georgia": "格鲁吉亚",
	"Germany": "德国", "Ghana": "加纳", "Gibraltar": "直布罗陀",
	"Greece": "希腊", "Greenland": "格陵兰", "Grenada": "格林纳达",
	"Guadeloupe": "瓜德罗普", "Guam": "关岛", "Guatemala": "危地马拉",
	"Guernsey": "根西岛", "Guinea": "几内亚", "Guinea-Bissau": "几内亚比绍",
	"Guyana": "圭亚那",
	// H
	"Haiti": "海地", "Holy See": "梵蒂冈", "Honduras": "洪都拉斯",
	"Hungary": "匈牙利",
	// I
	"Iceland": "冰岛", "India": "印度", "Indonesia": "印度尼西亚",
	"Iran": "伊朗", "Iraq": "伊拉克", "Ireland": "爱尔兰",
	"Isle of Man": "马恩岛", "Israel": "以色列", "Italy": "意大利",
	// J
	"Jamaica": "牙买加", "Japan": "日本", "Jersey": "泽西岛", "Jordan": "约旦",
	// K
	"Kazakhstan": "哈萨克斯坦", "Kenya": "肯尼亚", "Kiribati": "基里巴斯",
	"Kosovo": "科索沃", "Kuwait": "科威特", "Kyrgyzstan": "吉尔吉斯斯坦",
	// L
	"Laos": "老挝", "Latvia": "拉脱维亚", "Lebanon": "黎巴嫩",
	"Lesotho": "莱索托", "Liberia": "利比里亚", "Libya": "利比亚",
	"Liechtenstein": "列支敦士登", "Lithuania": "立陶宛", "Luxembourg": "卢森堡",
	// M
	"Madagascar": "马达加斯加", "Malawi": "马拉维", "Malaysia": "马来西亚",
	"Maldives": "马尔代夫", "Mali": "马里", "Malta": "马耳他",
	"Marshall Islands": "马绍尔群岛", "Martinique": "马提尼克",
	"Mauritania": "毛里塔尼亚", "Mauritius": "毛里求斯", "Mayotte": "马约特",
	"Mexico": "墨西哥", "Micronesia": "密克罗尼西亚", "Moldova": "摩尔多瓦",
	"Monaco": "摩纳哥", "Mongolia": "蒙古", "Montenegro": "黑山",
	"Montserrat": "蒙特塞拉特", "Morocco": "摩洛哥", "Mozambique": "莫桑比克",
	"Myanmar": "缅甸",
	// N
	"Namibia": "纳米比亚", "Nauru": "瑙鲁", "Nepal": "尼泊尔",
	"Netherlands": "荷兰", "New Caledonia": "新喀里多尼亚",
	"New Zealand": "新西兰", "Nicaragua": "尼加拉瓜", "Niger": "尼日尔",
	"Nigeria": "尼日利亚", "Niue": "纽埃", "Norfolk Island": "诺福克岛",
	"North Korea": "朝鲜", "North Macedonia": "北马其顿",
	"Northern Mariana Islands": "北马里亚纳群岛", "Norway": "挪威",
	// O
	"Oman": "阿曼",
	// P
	"Pakistan": "巴基斯坦", "Palau": "帕劳", "Palestine": "巴勒斯坦",
	"Panama": "巴拿马", "Papua New Guinea": "巴布亚新几内亚",
	"Paraguay": "巴拉圭", "Peru": "秘鲁", "Philippines": "菲律宾",
	"Pitcairn": "皮特凯恩群岛", "Poland": "波兰", "Portugal": "葡萄牙",
	"Puerto Rico": "波多黎各",
	// Q
	"Qatar": "卡塔尔",
	// R
	"Romania": "罗马尼亚", "Russia": "俄罗斯", "Rwanda": "卢旺达",
	"Réunion": "留尼汪",
	// S
	"Saint Barthélemy": "圣巴泰勒米", "Saint Helena": "圣赫勒拿",
	"Saint Kitts and Nevis": "圣基茨和尼维斯", "Saint Lucia": "圣卢西亚",
	"Saint Martin": "法属圣马丁", "Saint Pierre and Miquelon": "圣皮埃尔和密克隆",
	"Saint Vincent and the Grenadines": "圣文森特和格林纳丁斯", "Samoa": "萨摩亚",
	"San Marino": "圣马力诺", "Sao Tome and Principe": "圣多美和普林西比",
	"Saudi Arabia": "沙特阿拉伯", "Senegal": "塞内加尔", "Serbia": "塞尔维亚",
	"Seychelles": "塞舌尔", "Sierra Leone": "塞拉利昂", "Singapore": "新加坡",
	"Sint Maarten": "荷属圣马丁", "Slovakia": "斯洛伐克", "Slovenia": "斯洛文尼亚",
	"Solomon Islands": "所罗门群岛", "Somalia": "索马里", "South Africa": "南非",
	"South Korea": "韩国", "South Sudan": "南苏丹", "Spain": "西班牙",
	"Sri Lanka": "斯里兰卡", "Sudan": "苏丹", "Suriname": "苏里南",
	"Svalbard and Jan Mayen": "斯瓦尔巴和扬马延", "Sweden": "瑞典",
	"Switzerland": "瑞士", "Syria": "叙利亚",
	// T
	"Tajikistan": "塔吉克斯坦", "Tanzania": "坦桑尼亚", "Thailand": "泰国",
	"Timor-Leste": "东帝汶", "Togo": "多哥", "Tokelau": "托克劳",
	"Tonga": "汤加", "Trinidad and Tobago": "特立尼达和多巴哥",
	"Tunisia": "突尼斯", "Turkmenistan": "土库曼斯坦",
	"Turks and Caicos Islands": "特克斯和凯科斯群岛", "Tuvalu": "图瓦卢",
	"Türkiye": "土耳其",
	// U
	"Uganda": "乌干达", "Ukraine": "乌克兰", "United Arab Emirates": "阿联酋",
	"United Kingdom": "英国", "United States": "美国",
	"United States Virgin Islands": "美属维尔京群岛", "Uruguay": "乌拉圭",
	"Uzbekistan": "乌兹别克斯坦",
	// V
	"Vanuatu": "瓦努阿图", "Venezuela": "委内瑞拉", "Viet Nam": "越南",
	// W
	"Wallis and Futuna": "瓦利斯和富图纳",
	// Y
	"Yemen": "也门",
	// Z
	"Zambia": "赞比亚", "Zimbabwe": "津巴布韦",
	// Å（非 ASCII 键原样收录）
	"Åland": "奥兰",
}

// CountryChinese 返回海外国家名的中文简称：表内命中返回中文，未收录回退
// 原名（含空串原样返回——调用方无需判空）。展示层专用，不参与匹配链。
func CountryChinese(name string) string {
	if zh, ok := CountryNamesCN[name]; ok {
		return zh
	}
	return name
}
