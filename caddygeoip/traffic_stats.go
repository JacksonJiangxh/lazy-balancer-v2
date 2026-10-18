package caddygeoip

// 全请求实时流量计数（大屏「无 accesslog 光流」数据源，Plan B）：
//   - per-country 双计数器（attack=安全拦截 isSecurityBlock 同口径；normal=
//     非 安全中断 的已处理请求）——进程级常驻内存，国名桶硬上限 512（满员
//     只丢新键，已有键继续计数），随进程生命周期，无文件/无 goroutine。
//   - 暴露：SecurityBlockedCounter 实现 caddy.AdminRouter——GET /lb/traffic-stats
//     请求到达时序列化当前快照（无常驻写者/无激活信号；页面异常关闭零残留）。
//   - QPS 保险丝：单秒请求计数超过 fuseQPSPerSecond 时进入 1/N 抽样（N=8，
//     每 N 个请求计 1 次×N 还原），翻秒且上一秒计数低于阈值 1/4 时回落 N=1。
//     误差口径披露：抽样期估计量=真值±N/2（整秒口径无偏），瞬时分布有量化
//     误差——大屏光流为密度示意，可接受。
//   - 国名口径：geoip2region 写入的 Caddy 变量 geoip.country_name（xdb 英文
//     名/「中国」），由 app 代理端点翻译为中文（app 单源 geoipnames）；
//     客户端请求头不参与计数，本模块不加依赖。
//   - 统计边界：计数由链尾 lb_security_blocked_counter 执行；国名只来自
//     geoip2region 的服务端变量。未启用地域能力的规则没有该变量，因此不产生
//     国名桶；大屏流量卡不是全站请求总量。
//   - 注册语义：admin 路由进程级注册一次（reload 期新旧实例并存，同路径
//     二次注册会 panic；路由无实例状态——读全局计数器，实例无关）。

import (
	"net/http"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/caddyserver/caddy/v2"
)

type trafficEntry struct {
	attack atomic.Uint64
	normal atomic.Uint64
}

var (
	trafficMu        sync.RWMutex
	trafficCountries = map[string]*trafficEntry{}

	// trafficSecondState 惰性翻秒 + 当前秒计数的打包原子态：
	// (unixSec<<32)|hits。历史问题（历史）：旧实现 second 与 hits 是
	// 两个独立原子——翻秒路径 Swap(sec) 与并发 Add(1) 之间无配对，跨秒瞬间
	// 的命中会落在被随后 Swap(0) 丢弃的计数里（翻秒丢计）。打包 CAS 把
	// 「读当前秒 + 自增」变成单一线性化操作。
	trafficSecondState atomic.Uint64
	trafficSampleN     atomic.Uint32 // 抽样因子 N（1=全量）
)

// trafficCountryLimit 限定常驻国名桶数量；实际 xdb 国家数远低于此值。
const trafficCountryLimit = 512

// trafficSecondState 的打包布局。
const trafficHitsMask = 0xffffffff

// trafficBumpSecond 在当前秒计数 +1 并返回 (新 hits, 上一秒 hits, 是否翻秒)。
func trafficBumpSecond(nowSec uint64) (hits, prevHits uint32, rolled bool) {
	for {
		old := trafficSecondState.Load()
		oldSec := old >> 32
		oldHits := uint32(old & trafficHitsMask)
		if oldSec == nowSec && oldHits < trafficHitsMask {
			if trafficSecondState.CompareAndSwap(old, (nowSec<<32)|uint64(oldHits+1)) {
				return oldHits + 1, oldHits, false
			}
			continue
		}
		if oldSec != nowSec {
			// 翻秒（含时钟回拨）：新秒从 1 起算，上一秒计数完整交还调用方。
			if trafficSecondState.CompareAndSwap(old, (nowSec<<32)|1) {
				return 1, oldHits, true
			}
			continue
		}
		// hits 饱和（理论不可达：1e9 QPS）：保持当前秒不再自增。
		return oldHits, oldHits, false
	}
}

const (
	fuseQPSPerSecond = 4000 // 单秒请求计数超过此值 → 进入 1/8 抽样
	fuseSampleN      = 8
	// 抽样期单秒计数低于此值 → 回落全量：×8 估计真值 <8000，与进入阈值
	// 4000 构成 4000–8000 的滞回带（历史问题：旧注释「真值≈×8 < fuseQPS」
	// 与数值不符——1000×8=8000 > 4000）。
	fuseFallbackPerSecond = 1000
)

// trafficCountryKeyValid 判定国名键是否为可展示的国家值：xdb 对私网/保留
// 网段行的国家列常为 "0"/"Reserved"，不可解析行为空串。与事件聚合端点
// （internal/handlers/security_threat_screen.go 的 ""/"0"/"Reserved" 过滤）
// 同口径——E81-历史问题：大屏只为真实国家画弧/建桶。
func trafficCountryKeyValid(country string) bool {
	switch strings.TrimSpace(country) {
	case "", "0", "Reserved":
		return false
	}
	return true
}

func trafficEntryFor(country string) *trafficEntry {
	trafficMu.RLock()
	e := trafficCountries[country]
	trafficMu.RUnlock()
	if e != nil {
		return e
	}
	trafficMu.Lock()
	defer trafficMu.Unlock()
	if e = trafficCountries[country]; e == nil {
		// 硬上限兜底：即使未来新增其他调用源，也不能让国家键无界增长。
		// 满员只丢新键，已有国家继续精确计数。
		if len(trafficCountries) >= trafficCountryLimit {
			return nil
		}
		e = &trafficEntry{}
		trafficCountries[country] = e
	}
	return e
}

// trafficRecord 记一次请求（country 非国家值=未解析/私网保留段——跳过；
// 抽样期按 1/N 计数并 ×N 还原）。
func trafficRecord(country string, attack bool) {
	if !trafficCountryKeyValid(country) {
		return
	}
	// 惰性翻秒 + 保险丝状态机（全量→1/8 抽样→全量，滞回防抖动）。
	// 历史问题：翻秒与自增是单个 CAS（打包秒戳+计数），并发 Add 不会被
	// 随后清零的上一秒计数吞掉。
	hits, prevHits, rolled := trafficBumpSecond(uint64(time.Now().Unix()))
	if rolled && prevHits < fuseFallbackPerSecond {
		trafficSampleN.Store(1)
	}
	trafficSampleN.CompareAndSwap(0, 1)
	if hits == fuseQPSPerSecond+1 {
		trafficSampleN.Store(fuseSampleN)
	}
	n := trafficSampleN.Load()
	if n > 1 && hits%uint32(n) != 0 {
		return // 抽样：仅计每 N 个请求（×N 还原）
	}
	if n == 0 {
		n = 1
	}
	e := trafficEntryFor(country)
	if e == nil {
		return
	}
	if attack {
		e.attack.Add(uint64(n))
	} else {
		e.normal.Add(uint64(n))
	}
}

// trafficSnapshotJSON 序列化当前快照：{"countries":{...},"sample_n":N}——
// countries 键=原始国名（app 侧翻译中文），值=累计计数（自进程启动）。
func trafficSnapshotJSON() []byte {
	trafficMu.RLock()
	defer trafficMu.RUnlock()
	b := []byte(`{"enabled":` + strconv.FormatBool(trafficCollectorActive()) + `,"countries":{`)
	first := true
	for country, e := range trafficCountries {
		if first {
			first = false
		} else {
			b = append(b, ',')
		}
		b = append(b, '"')
		b = appendJSONString(b, country)
		b = append(b, '"')
		b = append(b, ':')
		b = append(b, '{')
		b = append(b, `"attack":`...)
		b = appendUint(b, e.attack.Load())
		b = append(b, `,"normal":`...)
		b = appendUint(b, e.normal.Load())
		b = append(b, '}')
	}
	b = append(b, `},"sample_n":`...)
	b = appendUint(b, uint64(trafficSampleN.Load()))
	b = append(b, '}')
	return b
}

// appendJSONString 极简 JSON 字符串转义（国名为 xdb 国家名——仅转义引号/
// 反斜杠/控制字符，避免 encoding/json 反射开销）。
func appendJSONString(dst []byte, s string) []byte {
	for i := 0; i < len(s); i++ {
		ch := s[i]
		if ch == '"' || ch == '\\' {
			dst = append(dst, '\\')
		}
		if ch < 0x20 {
			dst = append(dst, ' ')
			continue
		}
		dst = append(dst, ch)
	}
	return dst
}

func appendUint(dst []byte, v uint64) []byte {
	if v == 0 {
		return append(dst, '0')
	}
	var buf [20]byte
	i := len(buf)
	for v > 0 {
		i--
		buf[i] = byte('0' + v%10)
		v /= 10
	}
	return append(dst, buf[i:]...)
}

// serveTrafficStats admin 端点处理器（只读快照；AdminHandler 签名）。
func serveTrafficStats(w http.ResponseWriter, r *http.Request) error {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	_, _ = w.Write(trafficSnapshotJSON())
	return nil
}

// TrafficStatsAdmin admin.api 模块：把 /lb/traffic-stats 注册进 Caddy admin
// API（无鉴权面=admin 端点本体，Caddy 自行按 admin 配置限制来源）。admin
// 服务每次（重）启动重建 mux 并实例化全部 admin.api 模块——同路径重复注册
// 不经此模块实例（无实例状态，读全局计数器），无 reload 重复注册问题。
type TrafficStatsAdmin struct{}

// CaddyModule returns the Caddy module information.
func (TrafficStatsAdmin) CaddyModule() caddy.ModuleInfo {
	return caddy.ModuleInfo{
		ID:  "admin.api.lb_traffic_stats",
		New: func() caddy.Module { return new(TrafficStatsAdmin) },
	}
}

// Routes registers the read-only traffic snapshot endpoint.
func (TrafficStatsAdmin) Routes() []caddy.AdminRoute {
	return []caddy.AdminRoute{
		{
			Pattern: "/lb/traffic-stats",
			Handler: caddy.AdminHandlerFunc(serveTrafficStats),
		},
		{
			Pattern: "/lb/traffic-collector",
			Handler: caddy.AdminHandlerFunc(serveTrafficCollector),
		},
		{
			Pattern: "/lb/traffic-events",
			Handler: caddy.AdminHandlerFunc(serveTrafficEvents),
		},
	}
}

// Interface guards(编译期契约)。
var (
	_ caddy.AdminRouter = (*TrafficStatsAdmin)(nil)
)
