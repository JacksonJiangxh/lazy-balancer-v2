package handlers

// 威胁大屏「活跃攻击源」计数缓存：近 10 分钟原始事件表按 client_ip 去重
// （GROUP BY 全窗口扫描 + 逐行私网排除），大屏 30s 轮询下是重复的重查询。
// 同窗口锚点（分钟）+ ≤10s TTL 复用结果；键含 since 锚点——窗口前移即新键，
// 不会把旧窗口计数当当前窗口。失败不缓存（错误显式上抛由大屏整卡 500）。

import (
	"database/sql"
	"sync"
	"time"

	"lazy-balancer-v2/internal/services"
)

// threatActiveSourcesCacheTTL 缓存有效期（≤10s：与活跃窗口的 10 分钟粒度相比
// 陈旧上界可忽略；var 供测试缩短）。
var threatActiveSourcesCacheTTL = 10 * time.Second

type threatActiveSourcesKey struct {
	metrics *sql.DB
	since   string // 活跃窗口起点锚点（分钟串）
}

type threatActiveSourcesEntry struct {
	count     int
	expiresAt time.Time
}

var (
	threatActiveSourcesMu    sync.Mutex
	threatActiveSourcesCache = map[threatActiveSourcesKey]threatActiveSourcesEntry{}
)

// resetThreatActiveSourcesCacheForTest 测试缝：清空缓存（生产不调用）。
func resetThreatActiveSourcesCacheForTest() {
	threatActiveSourcesMu.Lock()
	threatActiveSourcesCache = map[threatActiveSourcesKey]threatActiveSourcesEntry{}
	threatActiveSourcesMu.Unlock()
}

// threatActiveSourcesCount 返回窗口内非保留地址的去重源 IP 数（命中缓存时
// 零查询）。activeSince 为窗口起点（UTC 墙钟串）。
func threatActiveSourcesCount(metricsDB *sql.DB, activeSince string, now time.Time) (int, error) {
	anchor := activeSince
	if len(anchor) > 16 {
		anchor = anchor[:16] // 分钟锚点（键与查询窗口同粒度语义）
	}
	key := threatActiveSourcesKey{metrics: metricsDB, since: anchor}
	if threatActiveSourcesCacheTTL > 0 {
		threatActiveSourcesMu.Lock()
		if entry, ok := threatActiveSourcesCache[key]; ok && now.Before(entry.expiresAt) {
			count := entry.count
			threatActiveSourcesMu.Unlock()
			return count, nil
		}
		threatActiveSourcesMu.Unlock()
	}

	rows, err := metricsDB.Query(`SELECT client_ip FROM security_events WHERE event_time >= ? AND `+services.AttackEventSQLPredicate("rule_triggered", "action")+` GROUP BY client_ip`, activeSince)
	if err != nil {
		return 0, err
	}
	defer rows.Close()
	count := 0
	for rows.Next() {
		var ip string
		if err := rows.Scan(&ip); err != nil {
			return 0, err
		}
		if !isReservedIP(ip) {
			count++
		}
	}
	if err := rows.Err(); err != nil {
		return 0, err
	}

	if threatActiveSourcesCacheTTL > 0 {
		threatActiveSourcesMu.Lock()
		if len(threatActiveSourcesCache) > 4 {
			threatActiveSourcesCache = map[threatActiveSourcesKey]threatActiveSourcesEntry{}
		}
		threatActiveSourcesCache[key] = threatActiveSourcesEntry{
			count:     count,
			expiresAt: now.Add(threatActiveSourcesCacheTTL),
		}
		threatActiveSourcesMu.Unlock()
	}
	return count, nil
}

// —— 归属地富化缓存（事件列表/大屏 feed/toast/光流逐行富化共用）——

// enrichIPLocationLookup 归属地查询缝（services.LookupRegion）——var 供
// 测试观测调用次数（富化缓存钉测）。
var enrichIPLocationLookup = services.LookupRegion

// enrichLocationCacheMax 归属地富化缓存条目上限（超限整体重置——有界
// 增长优先于精确 LRU 逐出，攻击源 IP 集洪峰下内存封顶）。
const enrichLocationCacheMax = 8192

type enrichLocationCacheEntry struct {
	location   string
	generation int64
}

var enrichLocationCache = struct {
	sync.Mutex
	entries map[string]enrichLocationCacheEntry
}{entries: make(map[string]enrichLocationCacheEntry)}

// enrichIPLocation 返回 IP 的归属地展示文本；xdb 未安装或查询失败返回 ""（前端
// 隐藏归属地标签），永不报错。
//
// 大屏 feed/toast/光流逐行富化同一批攻击源 IP——xdb 查询 O(log n) 便宜，
// 成本在字符串分配与格式化（200 行/30s、1200 行/toast 量级）。进程内缓存
// 键含 xdb 代际（GeoIPDataGeneration），库热换后旧值自然失效；容量有界
// （超限整体重置，与本文件活跃源缓存同形态）。
func enrichIPLocation(ip string) string {
	if ip == "" {
		return ""
	}
	// 保留地址前置拦截:xdb 仅 IPv4(NewV4Config),IPv6 回环/链路本地等
	// 查库返回空串会裸显示 IP;私网/回环/链路本地/未指定一律「保留地址」。
	if isReservedIP(ip) {
		return "保留地址"
	}
	return enrichIPLocationCached(ip)
}

// enrichIPLocationCached 缓存版实现：键含 GeoIP 数据代际，代际变更整体失效。
func enrichIPLocationCached(ip string) string {
	gen := services.GeoIPDataGeneration()
	enrichLocationCache.Lock()
	if e, ok := enrichLocationCache.entries[ip]; ok && e.generation == gen {
		location := e.location
		enrichLocationCache.Unlock()
		return location
	}
	enrichLocationCache.Unlock()
	location := formatIP2RegionLocation(enrichIPLocationLookup(ip))
	enrichLocationCache.Lock()
	if len(enrichLocationCache.entries) >= enrichLocationCacheMax {
		enrichLocationCache.entries = make(map[string]enrichLocationCacheEntry)
	}
	enrichLocationCache.entries[ip] = enrichLocationCacheEntry{location: location, generation: gen}
	enrichLocationCache.Unlock()
	return location
}
