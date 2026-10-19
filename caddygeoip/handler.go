// Package caddygeoip provides a Caddy HTTP handler module that resolves the
// client IP against an ip2region xdb database and publishes the resulting
// country as placeholders for downstream handlers and matchers, mirrored as
// X-LB-GeoIP-* request headers for downstream coraza SecRules (v2.2.0 GeoIP
// 区域拦截匹配目标；同名客户端头在入口剥离，防伪造）。
package caddygeoip

import (
	"net"
	"net/http"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/caddyserver/caddy/v2"
	"github.com/caddyserver/caddy/v2/modules/caddyhttp"
	"github.com/lionsoul2014/ip2region/binding/golang/service"
	"go.uber.org/zap"
	"lazy-balancer-v2/geoipnames"
)

func init() {
	caddy.RegisterModule(GeoIPHandler{})
}

// GeoIPHandler looks up the client IP in the ip2region database and sets the
// geoip.country_name/region/province/city placeholders on the request
// replacer. Blocking decisions belong to downstream matchers; this handler
// always passes the request through.
type GeoIPHandler struct {
	// XdbPath is the path to the ip2region xdb database. When empty it
	// defaults to /app/data/ip2region.xdb.
	XdbPath string `json:"xdb_path,omitempty"`

	// CrawlerExempt 由渲染侧按绑定策略输出（任一策略 GeoIPCrawlerExempt）。
	// 历史问题：false 时只剥离客户端伪造的验证头、不做 PTR/DNS 验证（无豁免
	// 规则消费结论，验证纯属浪费；旧实现无法关闭验证）。未配置按 false。
	CrawlerExempt bool `json:"crawler_exempt,omitempty"`

	searcher *service.Ip2Region
}

// CaddyModule returns the Caddy module information.
func (GeoIPHandler) CaddyModule() caddy.ModuleInfo {
	return caddy.ModuleInfo{
		ID:  "http.handlers.geoip2region",
		New: func() caddy.Module { return new(GeoIPHandler) },
	}
}

// Provision opens the ip2region database. A missing or unreadable database
// disables lookups (the handler degrades to a pass-through) instead of
// failing the Caddy configuration load.
func (h *GeoIPHandler) Provision(ctx caddy.Context) error {
	if h.XdbPath == "" {
		h.XdbPath = "/app/data/ip2region.xdb"
	}
	searcher, err := sharedGeoIPSearcher(h.XdbPath)
	if err != nil {
		ctx.Logger().Warn("geoip2region: ip2region database unavailable, geoip disabled",
			zap.String("xdb_path", h.XdbPath), zap.Error(err))
		return nil
	}
	h.searcher = searcher
	return nil
}

// geoipSharedSearcher（审计 M2）：按 XdbPath 进程级共享的 Ip2Region 单例条目。
// 每条 GeoIP 规则各建一份 NewIp2RegionWithPath（内部 NewV4Config(VIndexCache,
// path, 20)——20 个 searcher 各持 1 个 xdb fd + vIndex 缓冲），50 条规则≈1000 fd
// 逼近 soft limit，重载期新旧实例并存再翻倍；fd 耗尽 → Provision 降级
// pass-through → 全客户端判「海外」→ 含海外 deny 的策略全量误拦。SearcherPool
// 内部 channel 借还本就并发安全，同路径跨 handler 共享一份即可。modTime/size
// 记录建库时的文件形态：xdb 更新流程 rename 换库后 Caddy 随 reloader 重载，
// 纯路径键缓存会让新配置继续持有旧 inode 的 fd、更新静默失效（ip2regionupdate.go
// 依赖「Caddy 侧 geoip 随 reloader 收敛」），文件形态变化即重建。
type geoipSharedSearcher struct {
	searcher *service.Ip2Region
	modTime  time.Time
	size     int64
}

var (
	geoipSharedMu        sync.Mutex
	geoipSharedSearchers = map[string]*geoipSharedSearcher{}
)

// geoipOldInstanceCloseDelay 换库重建后旧实例的延迟关闭窗口：重载窗口内旧
// 配置的 handler 仍可能持旧实例在途查询（BorrowSearcher 落空会判「海外」
// 误拦——恰是 M2 要修的问题），故不立即关闭；但旧实例也不再「保留至进程
// 退出」（每次 xdb 更新遗留 20 个 fd + vIndex 缓冲），延迟窗口过后 Close
// 收敛。测试可缩短。
var geoipOldInstanceCloseDelay = 60 * time.Second

// sharedGeoIPSearcher 返回按路径共享的单例：文件形态未变时命中缓存，变化时重建。
// 被替换的旧实例经 geoipOldInstanceCloseDelay 延迟关闭——新实例先接管（下方
// 缓存替换完成后 Provision 返回，新配置随之重载），旧实例在窗口内继续服务
// 在途查询，窗口过后由定时器 Close（Ip2Region.Close 等待借出的 searcher
// 归还，在途查询不受截断）。
func sharedGeoIPSearcher(path string) (*service.Ip2Region, error) {
	st, err := os.Stat(path)
	if err != nil {
		// PLUG-N2（历史）：stat 失败（xdb 更新 rename 窗口/文件被删）且
		// 缓存持有该路径条目时驱逐之——旧实例走既有 AfterFunc 延迟关闭
		// （在途查询保护与换库路径一致）。不驱逐则旧 inode 实例永久占据
		// 缓存槽：文件以「同 modtime+size」形态恢复（rsync -a 保时间戳重铺）
		// 时缓存命中判定通过，被删 inode 的旧库被无限期当有效数据服务。
		geoipSharedMu.Lock()
		if cached, ok := geoipSharedSearchers[path]; ok {
			old := cached.searcher
			delete(geoipSharedSearchers, path)
			time.AfterFunc(geoipOldInstanceCloseDelay, func() { old.Close() })
		}
		geoipSharedMu.Unlock()
		return nil, err
	}
	geoipSharedMu.Lock()
	defer geoipSharedMu.Unlock()
	if cached, ok := geoipSharedSearchers[path]; ok &&
		cached.modTime.Equal(st.ModTime()) && cached.size == st.Size() {
		return cached.searcher, nil
	}
	searcher, err := service.NewIp2RegionWithPath(path, "")
	if err != nil {
		// E81-历史问题：重建失败（带外损坏的 xdb 等）不回退缓存旧实例，则
		// Provision 收到 error → handler 降级 pass-through → 全部客户端判
		// 「海外」→ deny 海外策略全量误拦（与 wafiplist 的 fail-stale 不对称）。
		// 正常更新走 rename（文件形态变化即命中成功重建），失败分支只可能是
		// 带外损坏：保留旧实例继续服务（fail-stale），文件修复后的下一次
		// Provision/reload 再重建。缓存条目保持旧形态，不驱逐。
		if cached, ok := geoipSharedSearchers[path]; ok {
			caddy.Log().Named("geoip2region").Warn("ip2region rebuild failed, serving the previous database instance",
				zap.String("xdb_path", path), zap.Error(err))
			return cached.searcher, nil
		}
		return nil, err
	}
	if replaced, ok := geoipSharedSearchers[path]; ok {
		old := replaced.searcher
		time.AfterFunc(geoipOldInstanceCloseDelay, func() { old.Close() })
	}
	geoipSharedSearchers[path] = &geoipSharedSearcher{searcher: searcher, modTime: st.ModTime(), size: st.Size()}
	return searcher, nil
}

// geoipCorazaHeaders lists the request headers this module owns. v2.2.0 地域
// 拦截改走 coraza（BuildCorazaDirectives 的 GeoIP SecRule 在 phase:1 读取
// X-LB-GeoIP-Loc），这些头是 geoip.* 变量的镜像；客户端伪造的同名头在
// ServeHTTP 入口无条件删除（先删后设，防伪造绕过/误伤）。
var geoipCorazaHeaders = []string{
	"X-LB-GeoIP-Country", "X-LB-GeoIP-Country-Code", "X-LB-GeoIP-Region",
	"X-LB-GeoIP-Province", "X-LB-GeoIP-City", "X-LB-GeoIP-Loc",
}

// ServeHTTP publishes the client country and always delegates to the next
// handler in the chain.
func (h *GeoIPHandler) ServeHTTP(w http.ResponseWriter, r *http.Request, next caddyhttp.Handler) error {
	// 无论 xdb 是否可用都先剥掉客户端伪造的 X-LB-GeoIP-* 头：xdb 缺失时
	// setGeoIPPlaceholders 不执行，伪造头若残留会直接喂给下游 coraza 的
	// 地域规则（伪造 X-LB-GeoIP-Loc=某 allow 名单省份即可绕过 allow 模式拦截）。
	for _, name := range geoipCorazaHeaders {
		r.Header.Del(name)
	}
	// v2.3.8 爬虫豁免：客户端伪造的验证头一并剥除（与 GeoIP 头同防御边界），
	// 随后 UA 命中引擎时做 PTR 双跳验证并注入结论头（coraza 豁免规则消费）。
	r.Header.Del(crawlerVerifiedHeader)
	r.Header.Del(crawlerSpoofHeader)
	if h.searcher != nil {
		h.setGeoIPPlaceholders(r)
	} else {
		// xdb 缺失/损坏（Provision 降级 pass-through）：coraza 的地域规则读
		// REQUEST_HEADERS:X-LB-GeoIP-Loc，缺失变量在 coraza 连取反算子都不产生
		// 匹配（rule.go evaluate 按值循环）——不置哨兵则 deny/allow 两模式的
		// id:8 恒不命中，地域拦截静默 fail-open。与查询失败同口径发「海外」，
		// 恢复文档化 fail-closed 语义。
		r.Header.Set("X-LB-GeoIP-Loc", "海外")
	}
	h.applyCrawlerVerification(r)
	return next.ServeHTTP(w, r)
}

// 爬虫验证结论头（服务端注入；客户端携带的同名头已在上游剥除）。
const (
	crawlerVerifiedHeader = "X-LB-Crawler-Verified"
	crawlerSpoofHeader    = "X-LB-Crawler-Spoof"
)

// applyCrawlerVerification UA 命中引擎 → PTR 双跳验证：通过置 Verified=引擎 ID
// （下游豁免规则 @streq 消费）；未通过置 Spoof=引擎 ID（伪装事件规则消费——
// 渲染侧按策略已选引擎集合 @rx^(?:engine|…)$ 匹配，见 buildIPPrecheckDirectives。
// PL历史问题：旧注释写 Spoof=1 与实际发射的引擎 ID 矛盾，按旧注释把规则改回
// @eq 1 会让伪装事件族静默永不命中）。
// 非爬虫 UA 不做 DNS/PTR，但 MatchCrawlerEngine 仍需顺序扫描引擎正则表；
// 未命中时承担全表预编译正则成本，命中时每个 UA 只匹配一次。
func (h *GeoIPHandler) applyCrawlerVerification(r *http.Request) {
	// 历史问题：渲染门控字段 false（无爬虫豁免策略）时零 DNS/PTR 开销；
	// 客户端伪造头已在 ServeHTTP 入口剥离，因此「只剥不验」是安全形态。
	if !h.CrawlerExempt {
		return
	}
	// 历史问题（并入 历史问题）：UA 只匹配一次（旧实现对同一 UA 调两次
	// MatchCrawlerEngine，2000/s 正常流量下多付一次全表正则）。
	engine := geoipnames.MatchCrawlerEngine(r.Header.Get("User-Agent"))
	if engine == "" {
		return
	}
	ip := clientIPForVerify(r)
	if ip != "" && VerifyCrawler(ip, engine) {
		r.Header.Set(crawlerVerifiedHeader, engine)
	} else {
		// 历史问题：值携带引擎 ID（与 Verified 对称）——coraza 伪装规则按
		// 策略已选引擎集合匹配，不再全局 @eq 1。
		r.Header.Set(crawlerSpoofHeader, engine)
	}
}

// clientIPForVerify 取验证用客户端 IP（历史问题）：复用 realClientIP 单源——
// 优先 Caddy client_ip 变量（受信代理还原后的真实客户端），而非 socket
// RemoteAddr。旧注释「RemoteAddr 已是真实客户端地址」在 CDN/受信代理部署下
// 不成立：socket 对端是 CDN 回源 IP，PTR 验证必然失败（真爬虫被判伪装）。
// 变量缺席时 realClientIP 回退 RemoteAddr 并做 ParseIP 校验（fail-closed）。
func clientIPForVerify(r *http.Request) string {
	return realClientIP(r)
}

// Cleanup 不关闭也不置空共享 searcher：单例按 XdbPath 进程级共享，换库由
// geoipOldInstanceCloseDelay 延迟回收。保留旧 handler 的指针可让 Caddy 重载
// 窗口内的在途请求继续查库，并消除 Cleanup 与 ServeHTTP 之间的数据竞争。
func (h *GeoIPHandler) Cleanup() error {
	return nil
}

// setGeoIPPlaceholders resolves the client IP against the database and
// publishes the country fields on the request replacer. v2.2.0 起同值镜像为
// X-LB-GeoIP-* 请求头（含 fail-closed 空串哨兵），供下游 coraza 的 GeoIP
// SecRule 匹配；X-LB-GeoIP-Loc 是地域规则匹配键：国名/省/省-市，海外为
// 解析失败与非国家值的兜底（详见下方）。
func (h *GeoIPHandler) setGeoIPPlaceholders(r *http.Request) {
	ctx := r.Context()
	// 历史问题 二十六次 D1（裁决：fail-closed 哨兵）：不可解析客户端（全部 IPv6 流量、
	// 查询失败、残缺 region）此前不发任何变量 → geoip CEL 对未设置变量求值出
	// 错 → match=false → deny 模式地域拦截对 IPv6 静默零强制。现恒发全部变量，
	// 空串哨兵下：海外项 country_name != "中国" 对空串成立（IPv6 按海外处理，
	// 与 历史问题 fail-closed 立场一致）；省/市项对空串恒不匹配（不误伤）。
	// 头镜像同语义：X-LB-GeoIP-Loc 先置「海外」哨兵（承载 fail-closed 海外裁决
	// ——不可解析客户端保此值）；已解析行随后覆盖为国名（海外）或省/省-市（国内，
	// 域 G 历史）。省/市空串对 coraza 锚定正则（^(?:...)$）恒不匹配。
	caddyhttp.SetVar(ctx, "geoip.country_name", "")
	caddyhttp.SetVar(ctx, "geoip.region", "")
	caddyhttp.SetVar(ctx, "geoip.province", "")
	caddyhttp.SetVar(ctx, "geoip.city", "")
	r.Header.Set("X-LB-GeoIP-Country", "")
	r.Header.Set("X-LB-GeoIP-Region", "")
	r.Header.Set("X-LB-GeoIP-Province", "")
	r.Header.Set("X-LB-GeoIP-City", "")
	r.Header.Set("X-LB-GeoIP-Loc", "海外")
	province, city := "", ""
	ip := realClientIP(r)
	if ip == "" {
		return
	}
	region, err := h.searcher.Search(ip)
	if err != nil || region == "" {
		return
	}
	emitted, ok := parseGeoIPRegion(region)
	if !ok {
		return
	}
	province, city = emitted.Province, emitted.City
	caddyhttp.SetVar(ctx, "geoip.country_name", emitted.Country)
	caddyhttp.SetVar(ctx, "geoip.region", emitted.Region)
	r.Header.Set("X-LB-GeoIP-Country", emitted.Country)
	r.Header.Set("X-LB-GeoIP-Region", emitted.Region)
	caddyhttp.SetVar(ctx, "geoip.province", province)
	r.Header.Set("X-LB-GeoIP-Province", province)
	caddyhttp.SetVar(ctx, "geoip.city", city)
	r.Header.Set("X-LB-GeoIP-City", city)
	// X-LB-GeoIP-Loc：地域规则匹配键（coraza SecRule 的锚定正则全值目标）。
	r.Header.Set("X-LB-GeoIP-Loc", emitted.Loc)
}

// geoIPRegionFields 是 xdb region 行的发射侧投影：变量、X-LB-GeoIP-* 头与
// 流量统计桶全部消费同一份归一值，避免多路径各自取原始列造成口径漂移。
type geoIPRegionFields struct {
	Country  string // xdb 国家列（TrimSpace 归一）
	Region   string // xdb 原始 region 串（region 变量/头沿用）
	Province string // 省列规范化值
	City     string // 城市列规范化值
	Loc      string // 地域规则匹配键
}

// parseGeoIPRegion 把 xdb region 行解析为发射字段（E83-历史问题）。
// 国家列统一 TrimSpace——E83-历史问题 前变量/头发射原始列，而 geoipLocFor 与
// geoipnames.NormalizeCountry 都 TrimSpace：空白异形行（" 中国"）会出现
// Loc=广东省 但 country_name=" 中国" 的自相矛盾取值，统计桶也建成脏键。
func parseGeoIPRegion(region string) (geoIPRegionFields, bool) {
	fields := strings.Split(region, "|")
	if len(fields) < 5 {
		return geoIPRegionFields{}, false
	}
	out := geoIPRegionFields{Country: strings.TrimSpace(fields[0]), Region: region}
	// 历史问题(历史):上方 len(fields)>=5 已保证,原两处 len>=3 守卫
	// 恒真,直接执行块内逻辑。
	if raw := fields[1]; raw != "" && raw != "0" {
		// 历史问题 二十三次：省列规范化——xdb 存在双形态（上海/上海市）与
		// 台湾城市误入省列；规范表已单源收敛进 geoipnames 包（选项树侧
		// ProvinceForTree / 发射侧 ProvinceForEmit 同表驱动，见 region.go），
		// 发射变量与选项树同规范化后 CEL 等值匹配才成立。
		out.Province = normalizeProvince(raw)
	}
	// 历史问题 二十三次：市级粒度——region 第 3 列为城市；无效值（空/0）置空串，
	// 使 CEL {http.vars.geoip.city} == X 对无城市段恒不命中。
	// 历史问题 二十五次：城市列经 normalizeCity 规范化——xdb 部分段城市列为拼音/
	// 英文（Guangzhou Shi/Taipei City），策略树侧已映射为中文，发射侧不映射
	// 会导致「广东省/广州市」类城市级规则对这些段恒不命中。
	// 台湾城市误入省列的段：城市名在省列（城市列是该段的乱码罗马化值）——
	// 城市变量改发省列值，与树侧归并语义一致，使「台湾省/台中市」可命中。
	if rawProv := strings.TrimSpace(fields[1]); geoipnames.TaiwanCities[rawProv] {
		out.City = rawProv
	} else if c := strings.TrimSpace(fields[2]); c != "" && c != "0" {
		out.City = normalizeCity(c)
	}
	// geoipLocFor 承载三态判定（X4 历史抽出可钉）。
	out.Loc = geoipLocFor(fields[0], out.Province, out.City)
	return out, true
}

// geoipLocFor 由 xdb 国家列与规范化省/市列计算 X-LB-GeoIP-Loc 值：
// 国内（国家列 TrimSpace 后为「中国」——X4 历史 TrimSpace 对称，树侧
// 收集判定同口径）→ 省 或 省/市；海外 → 归一化国名（域 G，历史——已
// 解析海外行细化到国家，与选项树 Countries 同源同归一）；国家列不可解析为
// 国名（空/0/Reserved/中国空白异形经 NormalizeCountry 折叠空串）→「海外」
// 哨兵，与 D1 fail-closed 哨兵同口径（deny+海外仍拦此类客户端）。
func geoipLocFor(rawCountry, province, city string) string {
	if strings.TrimSpace(rawCountry) == "中国" {
		if city != "" {
			return province + "/" + city
		}
		return province
	}
	if country := geoipnames.NormalizeCountry(rawCountry); country != "" {
		return country
	}
	return "海外"
}

// realClientIP 取真实客户端 IP：优先 Caddy client_ip 变量（v2.3.x）——
// trusted_proxies 启用时它经「回源网段 + 有序请求头」校验，伪造头不改变
// 判定；X-Forwarded-For 仅在 Caddy 配置 trusted_proxies 时被采信（此
// handler 运行在边缘，未经 Caddy 受信代理判定的头不可信）。变量缺席
// （非 Caddy 上下文）回退 RemoteAddr 解析——直连部署行为不变。
func realClientIP(r *http.Request) string {
	if ip, ok := caddyhttp.GetVar(r.Context(), caddyhttp.ClientIPVarKey).(string); ok && ip != "" {
		return ip
	}
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		if net.ParseIP(r.RemoteAddr) != nil {
			return r.RemoteAddr
		}
		return ""
	}
	return host
}

// 规范化四张表（省别名/台湾城市/拼音城市/自治州）单源在
// lazy-balancer-v2/geoipnames（PLUG-N3 历史收敛——此前与
// internal/services 手工镜像双份，靠解析对侧源文本的镜像测试防漂移；
// 中立叶模块经根/caddygeoip 双 replace 接线，与 wafiplist 同模式）。

// normalizeProvince 发射侧省列规范化——单源 geoipnames.ProvinceForEmit
// （历史问题 历史下沉：此前与 internal/services.normalizeIP2Province 是
// 两份手工镜像，语义分叉靠调用点补偿）。台湾城市误入省列时省变量按台湾省
// 发射、城市变量改发省列值（见 setGeoIPPlaceholders——该类段的城市列是
// 乱码值）；无效值（空/"0"）→ 空串；别名归一；不可识别（乱码）原样返回
// （不出现在选项树中，策略不会配置）。
func normalizeProvince(raw string) string {
	return geoipnames.ProvinceForEmit(raw)
}

// normalizeCity 发射侧城市列规范化——单源 geoipnames.CityForEmit：表映射
// 命中返回规范中文；无效值（空/"0"）→ 空串；未映射的 ASCII 城市原样返回
// （选项树侧会过滤、策略不会配置，发射原值恒不命中——与 normalizeProvince
// 的不可识别语义一致）；中文城市原样通过。
func normalizeCity(raw string) string {
	return geoipnames.CityForEmit(raw)
}
