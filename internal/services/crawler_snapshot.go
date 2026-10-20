package services

import (
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"os"

	"lazy-balancer-v2/geoipnames"
	"lazy-balancer-v2/internal/db"
	"lazy-balancer-v2/internal/models"
)

// crawlerIPListFile 快照交换文件（root 服务与插件的唯一交换面）。
// 包级变量以便测试覆盖到临时目录；生产默认容器内 /app/data 不变。
var crawlerIPListFile = "/app/data/crawler-ip-lists.json"

// SetCrawlerIPListFileForTest 重定向快照交换文件路径，仅供测试隔离使用（返回还原函数）。
func SetCrawlerIPListFileForTest(path string) func() {
	old := crawlerIPListFile
	crawlerIPListFile = path
	return func() { crawlerIPListFile = old }
}

// crawlerBuiltinSnapshot 新实例内置首版（单一事实源见
// geoipnames.BuiltinCrawlerIPLists：官方源快照随 geoipnames 包嵌入，镜像内
// /app/waf.dist 的同名文件由 Dockerfile 从同一路径 COPY）。历史修复（历史）
// 删除了此处的第二份手写副本——它曾与镜像种子分叉（gptbot 3 条 vs 18 条，
// 且含官方已不发布的 20.191.0.0/16 超网）。消费点仅剩「收缩门基线」
// （crawler_update.go 的 crawlerSnapshotShrinkGuard），运行期名单恒以 DB 为
// 唯一真相。
var crawlerBuiltinSnapshot = geoipnames.BuiltinCrawlerIPLists()

// crawlerDistSeedFile 镜像内置首版（JSON map[engine][]CIDR）。运行期快照
// crawlerIPListFile 同形，均为按引擎隔离的 JSON 对象。
var crawlerDistSeedFile = "/app/waf.dist/crawler-ip-lists.seed.json"

// loadCrawlerIPListsFromDB 以 DB 为唯一真相读取全部爬虫名单，按内部引擎 ID
// 返回；用户可见名单名只用于定位，不写进运行快照。
func loadCrawlerIPListsFromDB() (map[string][]string, error) {
	all := map[string][]string{}
	for _, src := range crawlerBotSources {
		var raw string
		err := db.DB.QueryRow(`SELECT COALESCE(entries,'') FROM security_ip_lists WHERE name=? AND system=1`, CrawlerIPListName(src.Name)).Scan(&raw)
		if errors.Is(err, sql.ErrNoRows) {
			continue
		}
		if err != nil {
			return nil, err
		}
		if raw == "" {
			continue
		}
		var values []string
		var objects []models.IPListEntry
		if err := json.Unmarshal([]byte(raw), &objects); err == nil {
			for _, entry := range objects {
				values = append(values, entry.Value)
			}
		} else {
			// 兼容早期字符串数组形态；下次 upsert 自动归一为对象数组。
			if err := json.Unmarshal([]byte(raw), &values); err != nil {
				return nil, fmt.Errorf("名单 %s 条目解析失败: %w", CrawlerIPListName(src.Name), err)
			}
		}
		if len(values) > 0 {
			all[src.Name] = values
		}
	}
	return all, nil
}

// loadCrawlerBundledSeed 读镜像内置首版；文件缺失/损坏时回退到嵌入二进制的
// 同一份数据（geoipnames.BuiltinCrawlerIPLists），保证离线新实例也不产生空名单。
// 两条路径内容同源（Dockerfile 从嵌入路径 COPY），不存在「两份数据分叉」。
func loadCrawlerBundledSeed() map[string][]string {
	if data, err := os.ReadFile(crawlerDistSeedFile); err == nil {
		var seed map[string][]string
		if err := json.Unmarshal(data, &seed); err == nil && len(seed) > 0 {
			return seed
		}
	}
	return geoipnames.BuiltinCrawlerIPLists()
}

// Prime 启动预载：DB 为空时优先使用镜像内置种子，随后以 DB 为唯一真相
// 重建运行快照（root 服务与插件的唯一交换面）。
func (m *CrawlerUpdateManager) Prime() error {
	if err := ensureCrawlerSources(); err != nil {
		return err
	}
	if err := migrateCrawlerIPListNames(); err != nil {
		return err
	}
	// 历史问题-05：启动期把内置源的 canonical url/format 刷新到存量行（用户开关/
	// 状态/排程保持不变），修复「URL/格式修正只对新库生效」的升级盲区。
	if err := refreshCrawlerSources(); err != nil {
		return err
	}
	all, err := loadCrawlerIPListsFromDB()
	if err != nil {
		return err
	}
	if len(all) == 0 {
		all = loadCrawlerBundledSeed()
	}
	for engineID, entries := range all {
		if err := upsertCrawlerIPList(engineID, entries); err != nil {
			return err
		}
	}
	return writeCrawlerIPListSnapshotAll(all)
}

// RebuildCrawlerIPListSnapshot 以当前 DB 名单为唯一真相重建运行交换文件。
// 与 Prime 不同，不播种、不回写名单；适用于备份替换后的无副作用收敛。
func RebuildCrawlerIPListSnapshot() error {
	all, err := loadCrawlerIPListsFromDB()
	if err != nil {
		return err
	}
	return writeCrawlerIPListSnapshotAll(all)
}

// upsertCrawlerIPList 名单行原子快照（内容变化才更新）；失败/空集不写（保留
// 上次快照）。changed 语义见 upsertCrawlerIPListChanged。
func upsertCrawlerIPList(engineID string, entries []string) error {
	_, err := upsertCrawlerIPListChanged(engineID, entries)
	return err
}

// upsertCrawlerIPListChanged 名单行原子快照：内容变化才更新（entries JSON、
// updated_at、entry_count）；失败/空集不写（保留上次快照）。
// 返回 changed=DB/快照内容真实变化（调用方据此决定投影收敛，历史问题）。
// 同步推送插件内存态（模块边界友好：caddygeoip 独立模块不能 import 根 DB）。
func upsertCrawlerIPListChanged(engineID string, entries []string) (bool, error) {
	if len(entries) == 0 {
		return false, errors.New("空 IP 段列表（解析无产出）")
	}
	payload := make([]models.IPListEntry, 0, len(entries))
	for _, value := range entries {
		payload = append(payload, models.IPListEntry{Value: value})
	}
	encoded, err := json.Marshal(payload)
	if err != nil {
		return false, err
	}
	if err := migrateCrawlerIPListNames(); err != nil {
		return false, err
	}
	name := CrawlerIPListName(engineID)
	var existing string
	scanErr := db.DB.QueryRow(`SELECT COALESCE(entries,'') FROM security_ip_lists WHERE name=? AND system=1`, name).Scan(&existing)
	if scanErr != nil && !errors.Is(scanErr, sql.ErrNoRows) {
		return false, scanErr
	}
	if scanErr == nil && crawlerEntriesUnchanged(existing, entries) {
		// 历史修复（历史）：判定改为内容（多重集）比较而非顺序敏感
		// 字节比较——源站同集合换序曾每轮误判 changed=true（写放大+「更新成功」
		// 噪声）。DB 展示顺序保持不变（未变化不重写）。
		// 未变化仍须校验**快照内容**（历史问题）：不能只看文件存在/DB 值——
		// 文件缺失/坏 JSON/陈旧内容（首轮快照写失败、升级遗留）都要从 DB/entries
		// 重建；writeCrawlerIPListSnapshot 从 DB 全量重建并覆盖本引擎，其他引擎
		// 分片保留。
		if crawlerSnapshotMatchesEngine(engineID, entries) {
			return false, nil
		}
		return true, writeCrawlerIPListSnapshot(engineID, entries)
	}
	exists := 0
	if scanErr == nil {
		exists = 1
	}
	if exists == 0 {
		_, err = db.DB.Exec(`INSERT INTO security_ip_lists (name, description, category, entries, system, created_at, updated_at)
			VALUES (?, ?, '搜索引擎爬虫', ?, 1, datetime('now'), datetime('now'))`, name, crawlerDisplayName(engineID), string(encoded))
	} else {
		_, err = db.DB.Exec(`UPDATE security_ip_lists SET entries=?, updated_at=datetime('now') WHERE name=? AND system=1`, string(encoded), name)
	}
	if err != nil {
		return false, err
	}
	// DB 与运行快照是同一更新事务语义：快照写失败不得继续标记源成功。
	return true, writeCrawlerIPListSnapshot(engineID, entries)
}

// crawlerSnapshotMatchesEngine 快照文件可解析且本引擎条目集合与期望一致。
func crawlerSnapshotMatchesEngine(engineID string, entries []string) bool {
	data, err := os.ReadFile(crawlerIPListFile)
	if err != nil {
		return false
	}
	var all map[string][]string
	if err := json.Unmarshal(data, &all); err != nil {
		return false
	}
	got, ok := all[engineID]
	if !ok || len(got) != len(entries) {
		return false
	}
	seen := make(map[string]struct{}, len(got))
	for _, v := range got {
		seen[v] = struct{}{}
	}
	for _, v := range entries {
		if _, ok := seen[v]; !ok {
			return false
		}
	}
	return true
}

// crawlerEntriesUnchanged 报告已存 entries JSON 与本次解析条目是否同值多重集
// （顺序无关的内容比较；解析失败按「已变化」处理→走完整写入路径
// 重建畸形行）。DB 展示顺序保持原状（未变化不重写）。
func crawlerEntriesUnchanged(existingJSON string, entries []string) bool {
	var stored []models.IPListEntry
	if err := json.Unmarshal([]byte(existingJSON), &stored); err != nil {
		return false
	}
	if len(stored) != len(entries) {
		return false
	}
	counts := make(map[string]int, len(entries))
	for _, e := range entries {
		counts[e]++
	}
	for _, e := range stored {
		if counts[e.Value] == 0 {
			return false
		}
		counts[e.Value]--
	}
	return true
}

// writeCrawlerIPListSnapshotAll 全量快照：写 map[engine][]string JSON
// （与 caddygeoip.crawler_verify.go 的读取契约一致，按引擎隔离命中）。
func writeCrawlerIPListSnapshotAll(all map[string][]string) error {
	encoded, err := json.Marshal(all)
	if err != nil {
		return err
	}
	// 复用「持久化原子落盘」单源实现——此前是第 4 份
	// 手写 CreateTemp+Sync+Rename（缺 chmod，默认 0600；同目录其它投影/快照
	// 类文件均为 0644），单源修复无法一处生效。
	return writeFileAtomicSynced(crawlerIPListFile, encoded, 0o644)
}

// writeCrawlerIPListSnapshot 单引擎更新后从 DB 重建全量运行快照。
// 运行文件为 map[engine][]string JSON（旧纯文本实现会被插件误读且丢失引擎边界）。
func writeCrawlerIPListSnapshot(engineID string, entries []string) error {
	all, err := loadCrawlerIPListsFromDB()
	if err != nil {
		return err
	}
	all[engineID] = entries
	return writeCrawlerIPListSnapshotAll(all)
}
