package services

import (
	"strconv"
	"strings"
	"testing"
)

// 旧实现把任何覆盖官方段的超网（0.0.0.0/0、10.0.0.0/8）或仅含一条官方段内 IP
// 的错误页判为合法，可整体替换豁免名单（GeoIP/伪装检测 fail-open 或合法爬虫
// 失去豁免）。

// so360spider 官方五段全覆盖的最小合法集合（每段一条 ⊆ 条目）。
var crawlerAudit86FullCoverage = []string{
	"42.236.10.0/24", "42.236.17.0/24", "42.236.101.0/24",
	"180.153.236.0/24", "180.163.220.0/24",
}

func TestValidateCrawlerEntriesSanity_supernetRejected(t *testing.T) {
	// 超网形状：覆盖官方段的更大段不得保留（旧交集判定放行）。
	for _, entry := range []string{"0.0.0.0/0", "10.0.0.0/8", "42.236.8.0/20", "42.236.0.0/16"} {
		if _, err := validateCrawlerEntriesSanity("so360spider", []string{entry}); err == nil {
			t.Fatalf("超网条目 %s 必须拒绝（交集口径下被放行=豁免名单整体 fail-open）", entry)
		}
	}
}

func TestValidateCrawlerEntriesSanity_subsetAndCoverage(t *testing.T) {
	// 目标形状：每条 ⊆ 官方段且五段全覆盖 → 放行。
	got, err := validateCrawlerEntriesSanity("so360spider", append([]string(nil), crawlerAudit86FullCoverage...))
	if err != nil {
		t.Fatalf("全覆盖子集必须放行: %v", err)
	}
	if len(got) != len(crawlerAudit86FullCoverage) {
		t.Fatalf("filtered=%v, want 全部保留", got)
	}

	// 截断页形状：仅一条官方段内 IP（旧实现放行并整体替换名单）→ 覆盖门拒绝。
	if _, err := validateCrawlerEntriesSanity("so360spider", []string{"42.236.10.0/24"}); err == nil {
		t.Fatal("单条官方段内 IP 不得通过覆盖门（错误页单条替换整份名单形态）")
	}

	// 畸形形状：与官方段无关的条目被滤除；滤后为空 → 整体拒绝。
	if _, err := validateCrawlerEntriesSanity("so360spider", []string{"203.0.113.0/24"}); err == nil {
		t.Fatal("与官方段无关的解析结果必须拒绝")
	}
	// 混合形状：无关条目滤除、官方子集保留但缺段 → 覆盖门拒绝。
	mixed := append([]string{"203.0.113.0/24"}, crawlerAudit86FullCoverage[:4]...)
	if _, err := validateCrawlerEntriesSanity("so360spider", mixed); err == nil {
		t.Fatal("缺一段官方覆盖的名单必须拒绝")
	}
}

// JSON 源同样套用一致性门（旧实现 format=json 直接跳过全部校验）——
// 官方段已声明的引擎不分格式；结构化字段白名单仍由 parseCrawlerCIDRsForFormat 承担。
func TestValidateCrawlerEntriesSanity_jsonSourceAlsoGated(t *testing.T) {
	if _, err := validateCrawlerEntriesSanity("so360spider", []string{"42.236.8.0/20"}); err == nil {
		t.Fatal("JSON 源的超网条目同样必须拒绝")
	}
	if _, err := validateCrawlerEntriesSanity("so360spider", append([]string(nil), crawlerAudit86FullCoverage...)); err != nil {
		t.Fatalf("JSON 源的合法子集必须放行: %v", err)
	}
}

// 收缩门：新名单条数较当前快照（DB 行；无行回退内置首版）收缩超过一半时
// 拒绝写入、保留上次快照（真实 SQLite）。
func TestCrawlerSnapshotShrinkGuard(t *testing.T) {
	_, database := newClusterTestService(t)

	// 无 DB 行 → 基线=内置首版（so360spider 5 条）：2 条（<5/2）拒绝，3 条放行。
	if err := crawlerSnapshotShrinkGuard("so360spider", 2); err == nil {
		t.Fatal("较内置基线收缩过半必须拒绝")
	}
	if err := crawlerSnapshotShrinkGuard("so360spider", 3); err != nil {
		t.Fatalf("收缩未过半必须放行: %v", err)
	}

	// DB 行存在 → 基线=DB 当前条数（10 条）：4 条拒绝，5 条放行。
	var sb strings.Builder
	sb.WriteString("[")
	for i := range 10 {
		if i > 0 {
			sb.WriteString(",")
		}
		sb.WriteString(`{"value":"42.236.10.`)
		sb.WriteString(strconv.Itoa(i))
		sb.WriteString(`/32"}`)
	}
	sb.WriteString("]")
	if _, err := database.Exec(`INSERT INTO security_ip_lists (name, description, category, entries, system, created_at, updated_at)
		VALUES (?, '', '搜索引擎爬虫', ?, 1, datetime('now'), datetime('now'))`, CrawlerIPListName("so360spider"), sb.String()); err != nil {
		t.Fatalf("seed crawler list: %v", err)
	}
	if err := crawlerSnapshotShrinkGuard("so360spider", 4); err == nil {
		t.Fatal("较 DB 快照收缩过半必须拒绝")
	}
	if err := crawlerSnapshotShrinkGuard("so360spider", 5); err != nil {
		t.Fatalf("恰好半数必须放行: %v", err)
	}

	// 未知引擎（无内置基线、无 DB 行）→ 无对照口径，放行。
	if err := crawlerSnapshotShrinkGuard("unknown-engine", 1); err != nil {
		t.Fatalf("无基线引擎不得误拦: %v", err)
	}
}
