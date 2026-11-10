package services

import "errors"

// 测试专用名单写入入口（同包测试可访问未导出符号）。产品路径不经过这里：
// 更新任务走 upsertCrawlerIPListChangedInner（RunUpdate 单轮迁移一次），启动
// 预载走 upsertCrawlerIPListChangedInnerNoSnapshot（Prime 逐引擎只落库、末尾
// 单次全量快照）。保留下方「带迁移的单行 upsert」形态供测试种数据与验证
// 幂等/快照语义；若生产调用面出现同名需求，应显式接入上述两条真实入口，
// 不要把它当作主写入路径。

// upsertCrawlerIPList 名单行写入（内容变化才更新，空集/失败不写）。
func upsertCrawlerIPList(engineID string, entries []string) error {
	_, err := upsertCrawlerIPListChanged(engineID, entries)
	return err
}

// upsertCrawlerIPListChanged 名单行写入并返回 changed；先跑一次名单名迁移
// （独立调用方形态），随后走与生产一致的 inner 实现（DB 行 + 运行快照）。
func upsertCrawlerIPListChanged(engineID string, entries []string) (bool, error) {
	if len(entries) == 0 {
		return false, errors.New("空 IP 段列表（解析无产出）")
	}
	if err := crawlerIPListMigrate(); err != nil {
		return false, err
	}
	return upsertCrawlerIPListChangedInner(engineID, entries)
}
