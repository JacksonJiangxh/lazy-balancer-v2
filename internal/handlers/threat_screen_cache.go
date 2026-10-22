package handlers

import (
	"database/sql"
	"errors"
	"sort"
	"sync"
	"time"

	"github.com/gin-gonic/gin"
	"golang.org/x/sync/singleflight"

	"lazy-balancer-v2/internal/db"
)

// 威胁大屏进程内缓存与请求合并——大屏 30s（聚合）/1-2s（流量）轮询下的
// 原始表扫描与 admin 代理出口收敛。所有缓存带 TTL 且失败不缓存（降级响应
// 下一轮重试自愈）。

// ---- top_targets（被攻击目标 Top3）缓存：TTL 5 分钟 ----

// threatTopTarget 大屏「被攻击目标 Top3」条目（JSON 契约：name/domain/value）。
type threatTopTarget struct {
	Name   string `json:"name"`
	Domain string `json:"domain"`
	Value  int    `json:"value"`
}

// topTargetsCacheTTL top_targets 进程内缓存有效期——同一窗口锚点内（1 分钟）
// 合并重复查询；锚点（sinceMinute）变化即换键，卡片窗口与同屏其余维度一致
// （旧键只有 hours，命中时会把 5 分钟前的旧窗口结果当当前窗口）。
const topTargetsCacheTTL = time.Minute

// topTargetsCacheKey 缓存键含 *sql.DB 指针与窗口锚点 sinceMinute——
// 测试换库/换窗口即失效，不串库不串窗口；窗口每分钟前移即新键，不会返回
// 含窗口外事件的过期聚合。窗口粒度只由 sinceMinute 编码
// 此前键上还带无消费方的 hours，形成第二事实源——查询只按 sinceMinute 过滤，
// 键上的 hours 会让后续改动窗口语义时误判已有隔离）。
type topTargetsCacheKey struct {
	metrics     *sql.DB // security_event_target_rollup 所在库
	main        *sql.DB // lb_rules 所在库
	sinceMinute string
}

type topTargetsCacheEntry struct {
	targets   []threatTopTarget
	expiresAt time.Time
}

var (
	topTargetsCacheMu sync.Mutex
	topTargetsCache   = map[topTargetsCacheKey]topTargetsCacheEntry{}
)

// threatTopTargets 窗口内目标维度 rollup（security_event_target_rollup，
// rule_caddy_id 分组）计数前 3 → 主库 lb_rules 取 name/domain。
//
//	读分钟 rollup 而非原始事件表——原始表受保留期/行帽
//	  裁剪，旁路会让「TOP 被攻击站点」与同屏其余卡片窗口分裂；
//	保留/私网地址在固化期已排除（与其余维度同口径）；
//	先批量解析现存规则，再按计数顺序取前 3 条**现存**目标——已
//	  删除规则不得挤掉后续真实站点；
//	- 查询失败不缓存、错误上抛（调用方整卡 500，与现有错误口径一致）。
func threatTopTargets(sinceMinute string) ([]threatTopTarget, error) {
	if db.MetricsDB == nil || db.DB == nil {
		return nil, errors.New("database unavailable")
	}
	key := topTargetsCacheKey{metrics: db.MetricsDB, main: db.DB, sinceMinute: sinceMinute}
	now := time.Now()
	topTargetsCacheMu.Lock()
	if entry, ok := topTargetsCache[key]; ok && now.Before(entry.expiresAt) {
		targets := entry.targets
		topTargetsCacheMu.Unlock()
		return targets, nil
	}
	topTargetsCacheMu.Unlock()

	rows, err := db.MetricsDB.Query(`SELECT rule_caddy_id, SUM(count) FROM security_event_target_rollup WHERE minute >= ? GROUP BY rule_caddy_id`, sinceMinute)
	if err != nil {
		return nil, err
	}
	counts := map[string]int{}
	for rows.Next() {
		var id string
		var n int
		if err := rows.Scan(&id, &n); err != nil {
			rows.Close()
			return nil, err
		}
		if id == "" {
			continue
		}
		counts[id] = n
	}
	if err := rows.Err(); err != nil {
		rows.Close()
		return nil, err
	}
	rows.Close()

	ids := make([]string, 0, len(counts))
	for id := range counts {
		ids = append(ids, id)
	}
	// 计数降序；同计数按 id 升序（确定性输出，大屏轮询重渲染名次不抖动）
	sort.Slice(ids, func(i, j int) bool {
		if counts[ids[i]] != counts[ids[j]] {
			return counts[ids[i]] > counts[ids[j]]
		}
		return ids[i] < ids[j]
	})

	// 批量解析现存规则（分块 IN，避免逐目标查询的主库往返）。
	type ruleInfo struct{ name, domain string }
	existing := make(map[string]ruleInfo, len(ids))
	const chunk = 500
	for start := 0; start < len(ids); start += chunk {
		end := start + chunk
		if end > len(ids) {
			end = len(ids)
		}
		chunkIDs := ids[start:end]
		placeholders := ""
		args := make([]any, 0, len(chunkIDs))
		for i, id := range chunkIDs {
			if i > 0 {
				placeholders += ","
			}
			placeholders += "?"
			args = append(args, id)
		}
		rrows, rerr := db.DB.Query(`SELECT caddy_id, name, COALESCE(domain,'') FROM lb_rules WHERE caddy_id IN (`+placeholders+`)`, args...)
		if rerr != nil {
			return nil, rerr
		}
		for rrows.Next() {
			var id string
			var info ruleInfo
			if err := rrows.Scan(&id, &info.name, &info.domain); err != nil {
				rrows.Close()
				return nil, err
			}
			existing[id] = info
		}
		if err := rrows.Err(); err != nil {
			rrows.Close()
			return nil, err
		}
		rrows.Close()
	}

	const topTargetCount = 3
	targets := make([]threatTopTarget, 0, topTargetCount)
	for _, id := range ids {
		if len(targets) == topTargetCount {
			break
		}
		info, ok := existing[id]
		if !ok {
			continue // 规则已删除：跳过，继续补足现存前 3
		}
		targets = append(targets, threatTopTarget{Name: info.name, Domain: info.domain, Value: counts[id]})
	}

	topTargetsCacheMu.Lock()
	// 键含窗口锚点后每分钟产生新键——插入时顺带清过期项，防止 map 无限增长
	//（旧键 TTL 到期后不再被命中）。
	for k, entry := range topTargetsCache {
		if !now.Before(entry.expiresAt) {
			delete(topTargetsCache, k)
		}
	}
	topTargetsCache[key] = topTargetsCacheEntry{targets: targets, expiresAt: now.Add(topTargetsCacheTTL)}
	topTargetsCacheMu.Unlock()
	return targets, nil
}

// ---- traffic 代理缓存：TTL 1s + singleflight（key=admin URL）----

// threatTrafficCacheTTL traffic 快照缓存有效期（测试缝：可缩短验证过期重抓）。
var threatTrafficCacheTTL = time.Second

// threatTrafficGroup 同 admin URL 并发请求合并为一趟上游抓取（大屏多客户端
// 同开时不对 Caddy admin 放大请求）。
var threatTrafficGroup singleflight.Group

type threatTrafficCacheEntry struct {
	data      gin.H
	expiresAt time.Time
}

var threatTrafficCache sync.Map // key: admin URL（去尾斜杠）

var errThreatTrafficFetch = errors.New("threat traffic fetch failed")

// threatTrafficSnapshot 带缓存地取流量快照：TTL 命中直返；miss 经 singleflight
// 合并并发后抓取；抓取失败不缓存（ok=false，调用方走降级响应）。
func threatTrafficSnapshot(adminURL string) (gin.H, bool) {
	if v, ok := threatTrafficCache.Load(adminURL); ok {
		if entry, ok := v.(threatTrafficCacheEntry); ok && time.Now().Before(entry.expiresAt) {
			return entry.data, true
		}
	}
	result, err, _ := threatTrafficGroup.Do(adminURL, func() (any, error) {
		// 航班内二次检查：合并进来的并发请求直接复用首个成功结果。
		if v, ok := threatTrafficCache.Load(adminURL); ok {
			if entry, ok := v.(threatTrafficCacheEntry); ok && time.Now().Before(entry.expiresAt) {
				return entry.data, nil
			}
		}
		data, ok := fetchThreatTrafficSnapshot(adminURL)
		if !ok {
			return nil, errThreatTrafficFetch
		}
		threatTrafficCache.Store(adminURL, threatTrafficCacheEntry{data: data, expiresAt: time.Now().Add(threatTrafficCacheTTL)})
		return data, nil
	})
	if err != nil {
		return nil, false
	}
	data, ok := result.(gin.H)
	return data, ok
}

// resetThreatScreenCachesForTest 测试缝：清空大屏进程内缓存（生产不调用）。
func resetThreatScreenCachesForTest() {
	topTargetsCacheMu.Lock()
	topTargetsCache = map[topTargetsCacheKey]topTargetsCacheEntry{}
	topTargetsCacheMu.Unlock()
	threatTrafficCache.Range(func(key, _ any) bool {
		threatTrafficCache.Delete(key)
		return true
	})
}
