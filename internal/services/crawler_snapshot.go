package services

import (
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"

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

// crawlerBuiltinSnapshot 新实例内置首版（v2.3.8：官方源已核实的快照子集，
// 新实例启动即用，无需等待首轮下载；后续由更新任务覆盖为最新官方数据）。
var crawlerBuiltinSnapshot = map[string][]string{
	"googlebot": {
		"66.249.66.0/24", "66.249.67.0/24", "66.249.68.0/24", "66.249.69.0/24",
	},
	"gptbot": {
		"23.98.142.0/24", "23.98.143.0/24", "20.191.0.0/16",
	},
	"bingbot": {
		"157.55.39.0/24", "207.46.13.0/24", "40.77.167.0/24", "13.66.139.0/24",
		"13.66.144.0/24", "52.167.144.0/24", "13.67.10.16/28", "13.69.66.240/28",
		"13.71.172.224/28", "139.217.52.0/28", "191.233.204.0/24",
	},
	"so360spider": {
		"42.236.8.0/21", "42.236.17.0/24", "42.236.101.0/24", "180.153.236.0/24", "180.163.220.0/24",
	},
}

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

// loadCrawlerBundledSeed 读镜像内置首版；文件缺失/损坏时保留 Go 内置最小
// 回退，保证离线新实例也不产生空名单。
func loadCrawlerBundledSeed() map[string][]string {
	if data, err := os.ReadFile(crawlerDistSeedFile); err == nil {
		var seed map[string][]string
		if err := json.Unmarshal(data, &seed); err == nil && len(seed) > 0 {
			return seed
		}
	}
	return crawlerBuiltinSnapshot
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
	if scanErr == nil && existing == string(encoded) {
		// 历史问题：快速路径必须校验**快照内容**（本引擎条目 == DB 条目），
		// 不能只看文件存在——文件缺失/坏 JSON/陈旧内容（首轮快照写失败、
		// 升级遗留）都要从 DB/entries 重建；writeCrawlerIPListSnapshot 从 DB
		// 全量重建并覆盖本引擎，其他引擎分片保留。
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

// writeCrawlerIPListSnapshotAll 全量快照：写 map[engine][]string JSON
// （与 caddygeoip.crawler_verify.go 的读取契约一致，按引擎隔离命中）。
func writeCrawlerIPListSnapshotAll(all map[string][]string) error {
	encoded, err := json.Marshal(all)
	if err != nil {
		return err
	}
	tmp, err := os.CreateTemp(filepath.Dir(crawlerIPListFile), ".crawler-ip-lists-*.tmp")
	if err != nil {
		return err
	}
	tmpPath := tmp.Name()
	defer os.Remove(tmpPath)
	if _, err := tmp.Write(encoded); err != nil {
		_ = tmp.Close()
		return err
	}
	if err := tmp.Sync(); err != nil {
		_ = tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	if err := os.Rename(tmpPath, crawlerIPListFile); err != nil {
		return err
	}
	return syncParentDir(crawlerIPListFile)
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
