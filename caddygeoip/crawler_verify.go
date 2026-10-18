// Package caddygeoip —— 搜索引擎爬虫验证器（v2.3.8 地域拦截爬虫豁免，方案 B：
// UA + PTR 双跳验证，2026-10-17 用户裁定）。
//
// 验证算法（geoipnames.CrawlerEnginePTRMatch 同源语义）：
//  1. UA 命中引擎（geoipnames.MatchCrawlerEngine）
//  2. PTR 反查客户端 IP，域名后缀属该引擎官方域（机房 PTR 如
//     *.bc.googleusercontent.com 不匹配——伪装墙 1）
//  3. 正向回验：PTR 域名解析结果包含客户端 IP（防自配 PTR——伪装墙 2/3）
//
// 性能（2000/s 正常 + 100/s 攻击基准）：非爬虫 UA 不做 DNS/PTR，但需顺序
// 扫描引擎预编译正则表（未命中=全表成本）；验证按 IP 缓存（正 1h/确定性负
// 10min，瞬态失败不缓存）；在途 DNS 信号量 32 非阻塞（满员立即 fail-closed，
// 无 goroutine 堆积）；单查询 500ms 超时。
package caddygeoip

import (
	"context"
	"encoding/json"
	"net"
	"net/netip"
	"os"
	"sync"
	"time"

	"lazy-balancer-v2/geoipnames"
)

// crawlerDNSResolver 解析器接口（测试替身注入点）。
type crawlerDNSResolver interface {
	LookupAddr(ctx context.Context, addr string) ([]string, error)
	LookupHost(ctx context.Context, host string) ([]string, error)
}

// crawlerVerifyResolver 可注入解析器（测试替身）；缺省 net 包。
var crawlerVerifyResolver crawlerDNSResolver = &netResolver{}

type netResolver struct{}

func (n *netResolver) LookupAddr(ctx context.Context, addr string) ([]string, error) {
	return net.DefaultResolver.LookupAddr(ctx, addr)
}

func (n *netResolver) LookupHost(ctx context.Context, host string) ([]string, error) {
	return net.DefaultResolver.LookupHost(ctx, host)
}

// crawlerVerifyCache 验证结论缓存条目。
type crawlerVerifyCache struct {
	ok      bool
	expires time.Time
}

const (
	crawlerCachePositiveTTL = time.Hour
	crawlerCacheNegativeTTL = 10 * time.Minute
	crawlerDNSQueryTimeout  = 500 * time.Millisecond
	// crawlerVerifySlots 在途 DNS 并发上限（非阻塞获取：满员 fail-closed）
	crawlerVerifySlots = 32
)

var (
	crawlerCacheMu sync.Mutex
	crawlerCache   = map[string]crawlerVerifyCache{}
	// crawlerVerifySem 非阻塞信号量（cap 32；关账本式释放）
	crawlerVerifySem = make(chan struct{}, crawlerVerifySlots)
	// crawlerCacheMax 容量护栏：到上限先删过期条目；仍满员则跳过新键缓存，
	// 保留未过期的正/负结论（已存在键可原位更新，不增加条目数）。
	crawlerCacheMax = 200_000
)

// VerifyCrawler 验证客户端 IP 是否为该引擎官方爬虫出口（带缓存）。
// 返回 false = 当前请求未通过（fail-closed）。只有确定性验证结论进入缓存；
// 信号量饱和、DNS 错误和超时仅作用于本次请求，不写 10 分钟负缓存。
func VerifyCrawler(ip, engineID string) bool {
	key := ip + "|" + engineID
	now := time.Now()
	crawlerCacheMu.Lock()
	if entry, hit := crawlerCache[key]; hit && now.Before(entry.expires) {
		crawlerCacheMu.Unlock()
		return entry.ok
	}
	crawlerCacheMu.Unlock()

	ok, cacheable := false, true
	if geoipnames.CrawlerEngineVerifyMethod(engineID) == geoipnames.CrawlerVerifyIPRange {
		// 官方声明不支持 nslookup 的厂商（360）：官方 IP 段验证（名单表=
		// 定时更新任务的快照，更新即生效，无需重载）
		ok = verifyCrawlerIPRangeFromList(ip, engineID)
	} else {
		if !acquireCrawlerSlot() {
			return false // 瞬态资源饱和：本次 fail-closed，但不形成持久结论。
		}
		ok, cacheable = verifyCrawlerDNS(ip, engineID)
		releaseCrawlerSlot()
	}
	if !cacheable {
		return ok
	}
	ttl := crawlerCacheNegativeTTL
	if ok {
		ttl = crawlerCachePositiveTTL
	}
	crawlerCacheMu.Lock()
	if len(crawlerCache) >= crawlerCacheMax {
		// 先回收过期条目；仍满员时宁可不缓存新键，也不清空已验证爬虫。
		for cachedKey, entry := range crawlerCache {
			if !now.Before(entry.expires) {
				delete(crawlerCache, cachedKey)
			}
		}
	}
	_, keyExists := crawlerCache[key]
	if len(crawlerCache) < crawlerCacheMax || keyExists {
		crawlerCache[key] = crawlerVerifyCache{ok: ok, expires: now.Add(ttl)}
	}
	crawlerCacheMu.Unlock()
	return ok
}

// verifyCrawlerDNS 双跳验证本体（无缓存、需已持信号量）。第二个返回值表示
// 结论是否可缓存：PTR/正向回验的确定性否定为 true，任何解析错误/超时为 false。
func verifyCrawlerDNS(ip, engineID string) (bool, bool) {
	ctx, cancel := context.WithTimeout(context.Background(), crawlerDNSQueryTimeout)
	defer cancel()
	names, err := crawlerVerifyResolver.LookupAddr(ctx, ip)
	if err != nil {
		return false, false
	}
	transientFailure := false
	for _, name := range names {
		// LookupAddr 返回 FQDN 尾点；PTR 后缀锚定前剥除
		host := name
		if n := len(host); n > 0 && host[n-1] == '.' {
			host = host[:n-1]
		}
		if !geoipnames.CrawlerEnginePTRMatch(engineID, host) {
			continue
		}
		// 正向回验：PTR 域名解析须包含原 IP（防伪造 PTR 指向官方域）
		addrs, err := crawlerVerifyResolver.LookupHost(ctx, host)
		if err != nil {
			transientFailure = true
			continue
		}
		for _, a := range addrs {
			if a == ip {
				return true, true
			}
		}
	}
	if transientFailure || ctx.Err() != nil {
		return false, false
	}
	return false, true
}

func acquireCrawlerSlot() bool {
	select {
	case crawlerVerifySem <- struct{}{}:
		return true
	default:
		return false // 满员：立即 fail-closed（不排队）
	}
}

func releaseCrawlerSlot() {
	select {
	case <-crawlerVerifySem:
	default:
	}
}

// ResetCrawlerVerifyCacheForTest 清缓存+换 resolver（测试专用；非测试路径禁用）。
func ResetCrawlerVerifyCacheForTest(r crawlerDNSResolver) {
	crawlerCacheMu.Lock()
	crawlerCache = make(map[string]crawlerVerifyCache)
	crawlerCacheMu.Unlock()
	if r != nil {
		crawlerVerifyResolver = r
	} else {
		crawlerVerifyResolver = &netResolver{}
	}
}

// crawlerIPListFile 厂商 IP 段名单快照文件（root 服务写、插件读——模块边界：
// caddygeoip 独立模块不 import 根模块，快照经共享文件交换）。
var crawlerIPListFile = "/app/data/crawler-ip-lists.json"

// crawlerIPRangeSnapshot 预编译快照：引擎 ID → 已解析前缀列表。加载时一次性
// ParsePrefix（历史问题），判定热路径零解析/零分配。
type crawlerIPRangeSnapshot struct {
	prefixes map[string][]netip.Prefix
	loadedAt time.Time
}

var (
	crawlerFileCacheMu   sync.Mutex
	crawlerFileCacheSnap *crawlerIPRangeSnapshot
)

const crawlerIPListReloadInterval = 10 * time.Minute

// loadCrawlerIPRangeSnapshot 返回当前快照（超过 10min 重读）。读盘与解析在
// 锁外完成（双检 + 原子快照替换）：文件大/磁盘慢时不再阻塞并发判定。读取/
// JSON/解析失败同样写入节流时间戳并返回空快照（fail-closed + 失败也节流，
// 旧实现失败路径不写时间戳，缺失文件时每次判定都尝试读盘）。
func loadCrawlerIPRangeSnapshot() *crawlerIPRangeSnapshot {
	now := time.Now()
	crawlerFileCacheMu.Lock()
	snap := crawlerFileCacheSnap
	if snap != nil && now.Sub(snap.loadedAt) <= crawlerIPListReloadInterval {
		crawlerFileCacheMu.Unlock()
		return snap
	}
	crawlerFileCacheMu.Unlock()

	next := &crawlerIPRangeSnapshot{prefixes: map[string][]netip.Prefix{}, loadedAt: now}
	if data, err := os.ReadFile(crawlerIPListFile); err == nil {
		var all map[string][]string
		if err := json.Unmarshal(data, &all); err == nil {
			for engine, cidrs := range all {
				prefixes := make([]netip.Prefix, 0, len(cidrs))
				for _, cidr := range cidrs {
					if p, err := netip.ParsePrefix(cidr); err == nil {
						prefixes = append(prefixes, p)
					}
				}
				next.prefixes[engine] = prefixes
			}
		}
	}
	crawlerFileCacheMu.Lock()
	crawlerFileCacheSnap = next
	crawlerFileCacheMu.Unlock()
	return next
}

// verifyCrawlerIPRangeFromList 从共享快照文件验证 IP 段命中（缺失/为空=fail-closed；
// 快照每 10 分钟定时重读，不依赖 mtime/stat 触发）。
func verifyCrawlerIPRangeFromList(ipStr, engineID string) bool {
	snap := loadCrawlerIPRangeSnapshot()
	entries := snap.prefixes[engineID]
	if len(entries) == 0 {
		return false
	}
	// 历史问题：畸形地址不得 panic（MustParseAddr 旧实现可直接崩进程）——
	// 解析失败即 fail-closed。
	ip, err := netip.ParseAddr(ipStr)
	if err != nil {
		return false
	}
	for _, prefix := range entries {
		if prefix.Contains(ip) {
			return true
		}
	}
	return false
}
