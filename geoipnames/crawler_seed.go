package geoipnames

import (
	_ "embed"
	"encoding/json"
	"fmt"
)

// crawlerIPListSeedJSON 爬虫地址库内置首版：各厂商官方 JSON/表格快照的规范化
// 副本（Google common-crawlers.json、OpenAI gptbot.json、Bing bingbot.json、
// 360 官方 IP 表；2026-10-19 与官方源逐条核对一致）。文件随本包嵌入二进制，
// 镜像内 /app/waf.dist/crawler-ip-lists.seed.json 由 Dockerfile 从**同一路径**
// COPY——同一份字节同时服务「镜像资产」与「离线回退」两个消费面。
//
// 此前该数据在 config/ 下作为镜像资产，而 internal/services
// 另存一份手写 Go 表；两份逐渐分叉（手写表 gptbot 仅 3 条且含官方已不发布的
// 20.191.0.0/16 超网——若 gptbot 改 iprange 验证即为 fail-open）。手写表已删除，
// services 的回退直接取 BuiltinCrawlerIPLists，结构上不可能再分叉。
//
//go:embed crawler-ip-lists.seed.json
var crawlerIPListSeedJSON []byte

// builtinCrawlerIPLists 解析结果（包初始化即校验：数据随二进制编译进来，
// 解析失败属构建缺陷，启动期 panic 比运行期静默空名单更安全）。
var builtinCrawlerIPLists = mustParseCrawlerIPLists(crawlerIPListSeedJSON)

func mustParseCrawlerIPLists(data []byte) map[string][]string {
	var parsed map[string][]string
	if err := json.Unmarshal(data, &parsed); err != nil {
		panic(fmt.Sprintf("geoipnames: 内置爬虫 IP 段种子解析失败: %v", err))
	}
	if len(parsed) == 0 {
		panic("geoipnames: 内置爬虫 IP 段种子为空")
	}
	return parsed
}

// BuiltinCrawlerIPLists 返回内置首版的深拷贝（map 与每个切片都重新分配，
// 调用方修改不会写穿包级数据）。key=引擎 ID（与 CrawlerEngine.ID 同域）。
func BuiltinCrawlerIPLists() map[string][]string {
	out := make(map[string][]string, len(builtinCrawlerIPLists))
	for engineID, entries := range builtinCrawlerIPLists {
		out[engineID] = append([]string(nil), entries...)
	}
	return out
}
