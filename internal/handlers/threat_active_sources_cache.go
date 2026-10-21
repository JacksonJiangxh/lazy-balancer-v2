package handlers

// 威胁大屏「活跃攻击源」计数缓存：近 10 分钟原始事件表按 client_ip 去重
// （GROUP BY 全窗口扫描 + 逐行私网排除），大屏 30s 轮询下是重复的重查询。
// 同窗口锚点（分钟）+ ≤10s TTL 复用结果；键含 since 锚点——窗口前移即新键，
// 不会把旧窗口计数当当前窗口。失败不缓存（错误显式上抛由大屏整卡 500）。

import (
	"database/sql"
	"sync"
	"time"
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

	rows, err := metricsDB.Query(`SELECT client_ip FROM security_events WHERE event_time >= ? GROUP BY client_ip`, activeSince)
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
