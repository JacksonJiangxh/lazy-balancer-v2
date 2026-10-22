package services

import (
	"fmt"
	"strings"

	"lazy-balancer-v2/wafiplist"
)

// NormalizeCIDRs 逐条规范化（trim + 统一前缀形态）并去重——重复条目在匹配
// 语义上等价，去重后库内条数与审计 delta 的「N 条」同源（此前重复 CIDR 会
// 以多条落库，审计口径与用户直觉不符）。顺序保持（配置列表语义）。
func NormalizeCIDRs(values []string) ([]string, error) {
	normalized := make([]string, 0, len(values))
	seen := make(map[string]struct{}, len(values))
	for _, value := range values {
		value = strings.TrimSpace(value)
		prefix, err := wafiplist.ParseIPEntry(value)
		if err != nil {
			return nil, fmt.Errorf("%q 不是有效 CIDR", value)
		}
		canonical := prefix.String()
		if _, dup := seen[canonical]; dup {
			continue
		}
		seen[canonical] = struct{}{}
		normalized = append(normalized, canonical)
	}
	return normalized, nil
}

// aggregateIPEntries 委托 wafiplist.AggregateIPEntries（v2.3.x 单一实现——
// 渲染层与 @ipListFast 算子共享同一聚合/检索形态）：去重、兄弟归并、覆盖
// 剔除、排序；不可解析条目透传在末尾。不变量：合并前后匹配集合逐点相等。
func aggregateIPEntries(entries []string) []string {
	return wafiplist.AggregateIPEntries(entries)
}
