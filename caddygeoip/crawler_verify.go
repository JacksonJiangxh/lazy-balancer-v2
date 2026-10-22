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
	"io"
	"net"
	"net/netip"

	"lazy-balancer-v2/wafiplist"
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
	// crawlerCachePruneProbeLimit 限制单次新键插入时的过期回收工作量，
	// 避免满员后对 200k map 做全表扫描。map 遍历顺序不作保证；未探到的
	// 过期条目由后续插入继续回收，满员时维持既有的「不缓存新键」降级。
	crawlerCachePruneProbeLimit = 64
)

var (
	crawlerCacheMu sync.Mutex
	crawlerCache   = map[string]crawlerVerifyCache{}
	// crawlerCachePruneVisitsForTest 记录满员回收实际检查的条目数；由
	// crawlerCacheMu 保护，供容量路径的有界工作量钉测读取。
	crawlerCachePruneVisitsForTest int
	// crawlerVerifySem 非阻塞信号量（cap 32；关账本式释放）
	crawlerVerifySem = make(chan struct{}, crawlerVerifySlots)
	// crawlerCacheMax 容量护栏：到上限按固定探针数回收过期条目；仍满员则跳过新键缓存，
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
		// 定时更新任务的快照，更新即生效，无需重载）。O(log n) 查找本身很便宜，
		// 不缓存正向结论——否则 CIDR 被官方移除后仍可豁免至多 1h
		//
		ok = verifyCrawlerIPRangeFromList(ip, engineID)
		cacheable = false
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
		// 固定探针数内回收过期条目；仍满员时宁可不缓存新键，也不清空
		// 已验证爬虫，且绝不因一个新键扫描整张 200k 缓存。
		probed := 0
		for cachedKey, entry := range crawlerCache {
			probed++
			crawlerCachePruneVisitsForTest++
			if !now.Before(entry.expires) {
				delete(crawlerCache, cachedKey)
			}
			if probed >= crawlerCachePruneProbeLimit || len(crawlerCache) < crawlerCacheMax {
				break
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
	// 地址归一化比较——netip 解析 + Unmap。客户端 IP 可能是
	// 4in6 映射形态（::ffff:a.b.c.d），而 DNS 正向应答恒为 v4 规范串，
	// 字符串比较会恒不命中把真爬虫误杀；带 zone/不可解析输入 fail-closed
	// （确定性否定，可缓存）。
	want, perr := netip.ParseAddr(ip)
	if perr != nil || want.Zone() != "" {
		return false, true
	}
	want = want.Unmap()
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
			got, gerr := netip.ParseAddr(a)
			if gerr != nil || got.Zone() != "" {
				continue // 非法回验地址不计命中（fail-closed）
			}
			if got.Unmap() == want {
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
	crawlerCachePruneVisitsForTest = 0
	crawlerCacheMu.Unlock()
	if r != nil {
		crawlerVerifyResolver = r
	} else {
		crawlerVerifyResolver = &netResolver{}
	}
}

// crawlerIPListFile 厂商 IP 段名单快照文件（root 服务写、插件读——模块边界：
// caddygeoip 独立模块不 import 根模块，快照经共享文件交换）。
// defaultCrawlerIPListFile 与根服务容器默认逐字节一致（插件侧
// 兜底；根服务自定义 data_dir 时渲染侧经 crawler_ip_list_file 配置键下发
// 派生路径，由 GeoIPHandler.Provision 应用）。
const defaultCrawlerIPListFile = "/app/data/crawler-ip-lists.json"

var (
	// crawlerIPListFileMu 保护 crawlerIPListFile：Provision（配置重载）写、
	// 判定热路径经 crawlerIPListFilePath 读，重载窗口内可并发。
	crawlerIPListFileMu sync.Mutex
	crawlerIPListFile   = defaultCrawlerIPListFile
)

// crawlerIPListFilePath 返回当前快照交换文件路径。
func crawlerIPListFilePath() string {
	crawlerIPListFileMu.Lock()
	defer crawlerIPListFileMu.Unlock()
	return crawlerIPListFile
}

// setCrawlerIPListFilePath 应用配置路径（GeoIPHandler.Provision；空值忽略）。
// 路径变化时重置快照缓存——否则旧路径的成功快照在其 TTL（≤10min）内继续
// 服役，把上一部署形态的名单带进新形态。fail-closed 语义与失败重试间隔
// （crawlerIPListRetryInterval，默认 10s）不变。
func setCrawlerIPListFilePath(path string) {
	if path == "" {
		return
	}
	crawlerIPListFileMu.Lock()
	changed := crawlerIPListFile != path
	if changed {
		crawlerIPListFile = path
	}
	crawlerIPListFileMu.Unlock()
	if changed {
		crawlerFileCacheMu.Lock()
		crawlerFileCacheSnap = nil
		crawlerFileCacheMu.Unlock()
	}
}

// crawlerIPRangeSnapshot 预编译快照：引擎 ID → 已解析前缀列表。加载时一次性
// ParsePrefix，判定热路径零解析/零分配。ok=false 表示读取/解析失败
// 的空快照——只按短重试间隔节流，成功快照按完整重载间隔缓存。
type crawlerIPRangeSnapshot struct {
	prefixes map[string][]netip.Prefix
	// filePath 标识本次读取所属的路径代际；配置切换后在途旧路径读取不得
	// 写入新路径缓存。
	filePath string
	// loadedAt 是本快照开始读取的时刻（TTL 基准）。
	loadedAt time.Time
	ok       bool
	// modTime/size 是读取时打开 inode 的 stat 形态（内容代际）：写侧经
	// rename 换文件，慢读者可能读到 rename 前的旧 inode 并在新快照落定后
	// 才提交——以代际较旧者判定丢弃（与 wafiplist 同型）。
	modTime time.Time
	size    int64
	// committedAt 是落定时刻：失败读取与并发成功快照的先后判定依据。
	committedAt time.Time
}

var (
	crawlerFileCacheMu   sync.Mutex
	crawlerFileCacheSnap *crawlerIPRangeSnapshot
)

const crawlerIPListReloadInterval = 10 * time.Minute

// crawlerIPListRetryInterval 是失败/坏快照的重试间隔：Caddy 可能先于根服务
// 生成快照文件做首次爬虫校验（首启/冷装窗口）。旧实现把失败也缓存满 10min，
// 360 引擎豁免会 fail-closed 最长 10 分钟（伪装判定）；10s 既避免每次判定
// 读盘，又让文件出现后迅速收敛。var 供测试收窄。
var crawlerIPListRetryInterval = 10 * time.Second

// loadCrawlerIPRangeSnapshot 返回当前快照（成功快照超过 10min、失败快照超过
// 重试间隔时重读）。读盘与解析在锁外完成（双检 + 原子快照替换 + 内容代际
// 守卫）：文件大/磁盘慢时不再阻塞并发判定，慢读者也不会把 rename 前的旧
// 内容写回新快照（见 commitCrawlerIPRangeSnapshot）。读取/JSON/
// 解析失败同样写入节流时间戳并返回空快照（fail-closed + 失败也节流，旧实现
// 失败路径不写时间戳，缺失文件时每次判定都尝试读盘）。
func loadCrawlerIPRangeSnapshot() *crawlerIPRangeSnapshot {
	now := time.Now()
	crawlerFileCacheMu.Lock()
	snap := crawlerFileCacheSnap
	if snap != nil {
		ttl := crawlerIPListRetryInterval
		if snap.ok {
			ttl = crawlerIPListReloadInterval
		}
		if now.Sub(snap.loadedAt) <= ttl {
			crawlerFileCacheMu.Unlock()
			return snap
		}
	}
	crawlerFileCacheMu.Unlock()

	next := &crawlerIPRangeSnapshot{prefixes: map[string][]netip.Prefix{}, loadedAt: now, filePath: crawlerIPListFilePath()}
	if file, err := os.Open(next.filePath); err == nil {
		// stat 与读取针对同一已打开 inode：rename 换文件后旧 fd 读到的仍是
		// 旧代际内容，st 因此如实标识所读内容（不能读后按路径再 stat）。
		if st, statErr := file.Stat(); statErr == nil {
			data, readErr := io.ReadAll(file)
			if readErr == nil {
				var all map[string][]string
				if err := json.Unmarshal(data, &all); err == nil {
					next.ok = true
					next.modTime, next.size = st.ModTime(), st.Size()
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
		}
		_ = file.Close()
	}
	return commitCrawlerIPRangeSnapshot(next)
}

// commitCrawlerIPRangeSnapshot 在锁内落定快照，并拒绝旧代际/陈旧失败覆盖：
//   - 路径代际不同：配置切换前发起的读取不得写入新路径缓存；若新路径尚无
//     快照，本调用 fail-closed。
//   - 成功 vs 成功：当前快照的内容代际（mtime+size）更新时，旧代际读取结果
//     丢弃（并发慢读者不得把 rename 前的旧内容写回）。
//   - 失败 vs 成功：成功快照在本失败读取开始之后才落定 → 保留成功快照
//     （瞬时读错不得把刚刷新的名单降级成空集 fail-closed）。
//
// 其余形态（TTL 到期后的失败读取、无当前快照、同代际）照常覆盖。
func commitCrawlerIPRangeSnapshot(next *crawlerIPRangeSnapshot) *crawlerIPRangeSnapshot {
	crawlerFileCacheMu.Lock()
	defer crawlerFileCacheMu.Unlock()
	currentPath := crawlerIPListFilePath()
	current := crawlerFileCacheSnap
	if next.filePath != "" && next.filePath != currentPath {
		if current != nil {
			return current
		}
		// 路径切换已清空缓存时，旧路径在途读只对本调用 fail-closed，
		// 不落定任何缓存；下一次读取会按新路径重新加载。
		return &crawlerIPRangeSnapshot{prefixes: map[string][]netip.Prefix{}, loadedAt: next.loadedAt, filePath: currentPath}
	}
	if current != nil {
		// 代际/失败守卫与名单文件加载器共用单源判定（wafiplist.SnapshotGeneration）。
		currentGen := wafiplist.SnapshotGeneration{ModTime: current.modTime, Size: current.size, CommittedAt: current.committedAt}
		nextGen := wafiplist.SnapshotGeneration{ModTime: next.modTime, Size: next.size}
		if current.ok && next.ok && wafiplist.StaleSnapshotGeneration(nextGen, currentGen) {
			return current
		}
		if current.ok && !next.ok && wafiplist.StaleFailureDowngrade(currentGen, next.loadedAt) {
			return current
		}
	}
	next.committedAt = time.Now()
	crawlerFileCacheSnap = next
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
	// 畸形地址不得 panic（MustParseAddr 旧实现可直接崩进程）——
	// 解析失败即 fail-closed。
	// 带 zone 拒绝 + 4in6 映射形态 Unmap 归一——netip 的 v4
	// 前缀不含 4in6 地址，不归一则映射形态的真爬虫恒不命中（误判为伪装）。
	ip, err := netip.ParseAddr(ipStr)
	if err != nil || ip.Zone() != "" {
		return false
	}
	ip = ip.Unmap()
	for _, prefix := range entries {
		if prefix.Contains(ip) {
			return true
		}
	}
	return false
}
