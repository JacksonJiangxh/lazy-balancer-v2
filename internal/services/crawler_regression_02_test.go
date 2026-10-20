package services

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strconv"
	"strings"
	"testing"

	"lazy-balancer-v2/internal/taskengine"
)

// 旧实现把任何覆盖官方段的超网（0.0.0.0/0、10.0.0.0/8）或仅含一条官方段内 IP
// 的错误页判为合法，可整体替换豁免名单（GeoIP/伪装检测 历史修复 或合法爬虫
// 失去豁免）。

// so360spider 官方五段全覆盖的最小合法集合（每段至少 1/8 地址空间，
// 与官方页发布粒度一致：官方 /21 摘要段内官方页只公布两个 /24）。
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

// 覆盖门必须按地址空间覆盖率判定。旧实现「任一更
// 具体条目命中即算官方段已覆盖」：页面只要给出每段一个单 IP（5×/32）就能整体
// 替换 5 个官方 /24 的豁免名单（收缩门 5*2<5 不命中）。
// 阈值=官方段的 1/8 地址空间（官方页在 /21 摘要段内只公布 1/4，故不能取半数；
// 单 IP 对 /24 仅 1/256，远低于阈值）。
func TestValidateCrawlerEntriesSanity_singleIPCannotCoverPrefix(t *testing.T) {
	// 五段各一个单 IP：旧实现在此放行（豁免范围由 /24 收窄为 /32）。
	singleIPs := []string{
		"42.236.10.5/32", "42.236.17.7/32", "42.236.101.9/32",
		"180.153.236.1/32", "180.163.220.2/32",
	}
	if _, err := validateCrawlerEntriesSanity("so360spider", singleIPs); err == nil {
		t.Fatal("单 IP 覆盖官方段必须拒绝（/32 对 /24 仅 1/256 地址空间）")
	}

	// 官方页真实形状（/21 摘要段内一个 /24 = 恰好 1/8）+ 其余四段全覆盖 → 放行。
	if _, err := validateCrawlerEntriesSanity("so360spider", append([]string(nil), crawlerAudit86FullCoverage...)); err != nil {
		t.Fatalf("每段 ≥1/8 地址空间（官方页粒度）必须放行: %v", err)
	}

	// 低于 1/8：/21 内只给 /25（1/128）→ 拒绝：部分名单不得整体替换。
	below := append([]string(nil), crawlerAudit86FullCoverage...)
	below[0] = "42.236.10.0/25"
	if _, err := validateCrawlerEntriesSanity("so360spider", below); err == nil {
		t.Fatal("官方 /21 的 1/128 地址覆盖不得通过覆盖门（部分名单）")
	}

	// 并集口径：两条 /24 = /21 的 1/4 → 放行；两条 /28 = 1/128 → 拒绝
	// （按并集地址空间累计，不是单条判定）。
	unionPass := append([]string{"42.236.8.0/24", "42.236.9.0/24"}, crawlerAudit86FullCoverage[1:]...)
	if _, err := validateCrawlerEntriesSanity("so360spider", unionPass); err != nil {
		t.Fatalf("并集覆盖 /21 的 1/4 必须放行: %v", err)
	}
	unionFail := append([]string{"42.236.8.0/28", "42.236.8.16/28"}, crawlerAudit86FullCoverage[1:]...)
	if _, err := validateCrawlerEntriesSanity("so360spider", unionFail); err == nil {
		t.Fatal("并集仅覆盖 /21 的 1/128 必须拒绝")
	}

	// 阈值含等号：/24 官方段内单条 /27（=1/8）放行，/28（=1/16）拒绝。
	atThreshold := append([]string(nil), crawlerAudit86FullCoverage...)
	atThreshold[1] = "42.236.17.0/27"
	if _, err := validateCrawlerEntriesSanity("so360spider", atThreshold); err != nil {
		t.Fatalf("恰好 1/8 覆盖必须放行: %v", err)
	}
	underThreshold := append([]string(nil), crawlerAudit86FullCoverage...)
	underThreshold[1] = "42.236.17.0/28"
	if _, err := validateCrawlerEntriesSanity("so360spider", underThreshold); err == nil {
		t.Fatal("/24 官方段内仅 /28（1/16）必须拒绝")
	}
}

// 系统名单写入必须有扩张上限。源响应上限 16MB，
// 解析后可达数十万条；此前只有收缩门（防塌缩），无任何增长限制，
// 会直接放大 DB 行、历史修复.json、插件每 10min 重载的前缀表
// 与渲染期内存，并绕过产品 2000 条口径。
func TestCrawlerSnapshotGrowthGuard(t *testing.T) {
	_, database := newClusterTestService(t)

	if CrawlerIPListEntryCap != 2000 {
		t.Fatalf("CrawlerIPListEntryCap=%d, want 2000（与 handlers ipListMaxEntries 同口径）", CrawlerIPListEntryCap)
	}

	// 相对门：内置基线 googlebot=170 条 → 341 条（>2×）拒绝，340 条放行。
	if err := crawlerSnapshotGrowthGuard("googlebot", 341); err == nil {
		t.Fatal("较内置基线膨胀一倍以上必须拒绝")
	}
	if err := crawlerSnapshotGrowthGuard("googlebot", 340); err != nil {
		t.Fatalf("膨胀未超一倍必须放行: %v", err)
	}
	// 绝对门：无对照基线的引擎同样受 2000 条上限约束。
	if err := crawlerSnapshotGrowthGuard("unknown-engine", CrawlerIPListEntryCap+1); err == nil {
		t.Fatal("超过 2000 条绝对上限必须拒绝（无基线不是豁免理由）")
	}
	if err := crawlerSnapshotGrowthGuard("unknown-engine", CrawlerIPListEntryCap); err != nil {
		t.Fatalf("恰好 2000 条必须放行: %v", err)
	}

	// DB 行优先作为相对门基线（1000 条）：2001 条同时撞绝对门，2000 条仅
	// 在绝对门内（相对门 2000=2×1000 放行）。
	var sb strings.Builder
	sb.WriteString("[")
	for i := range 1000 {
		if i > 0 {
			sb.WriteString(",")
		}
		sb.WriteString(`{"value":"10.`)
		sb.WriteString(strconv.Itoa(i / 256))
		sb.WriteString(".")
		sb.WriteString(strconv.Itoa(i % 256))
		sb.WriteString(`.0/24"}`)
	}
	sb.WriteString("]")
	if _, err := database.Exec(`INSERT INTO security_ip_lists (name, description, category, entries, system, created_at, updated_at)
		VALUES (?, '', '搜索引擎爬虫', ?, 1, datetime('now'), datetime('now'))`, CrawlerIPListName("googlebot"), sb.String()); err != nil {
		t.Fatalf("seed crawler list: %v", err)
	}
	if err := crawlerSnapshotGrowthGuard("googlebot", CrawlerIPListEntryCap+1); err == nil {
		t.Fatal("DB 基线 1000 条时 2001 条必须拒绝（绝对上限）")
	}
	if err := crawlerSnapshotGrowthGuard("googlebot", CrawlerIPListEntryCap); err != nil {
		t.Fatalf("DB 基线 1000 条时 2000 条（恰 2×）必须放行: %v", err)
	}
	if err := crawlerSnapshotGrowthGuard("googlebot", 1001); err != nil {
		t.Fatalf("未超 2× 基线必须放行: %v", err)
	}
}

// 历史修复 集成：源返回 2001 条（> 产品 2000 条上限）时整源失败并保留上次
// 快照——旧实现照单全收，豁免名单被一次性放大到源可返回的最大规模。
func TestCrawlerRunUpdate_inflatedSourceKeepsPreviousSnapshot(t *testing.T) {
	_, database := newClusterTestService(t)
	newTaskLogDir(t)
	oldFile := crawlerIPListFile
	crawlerIPListFile = filepath.Join(t.TempDir(), "crawler-ip-lists.json")
	t.Cleanup(func() { crawlerIPListFile = oldFile })

	// 源响应：2001 条合法前缀（googlebot 无官方段声明，子集/覆盖门不参与）。
	var body strings.Builder
	body.WriteString(`{"prefixes":[`)
	for i := 0; i <= CrawlerIPListEntryCap; i++ {
		if i > 0 {
			body.WriteString(",")
		}
		fmt.Fprintf(&body, `{"ipv4Prefix":"10.%d.%d.0/24"}`, i/256, i%256)
	}
	body.WriteString(`]}`)
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(body.String()))
	}))
	t.Cleanup(ts.Close)

	if err := ensureCrawlerSources(); err != nil {
		t.Fatalf("seed sources: %v", err)
	}
	if _, err := database.Exec(`UPDATE security_crawler_sources SET update_enabled=0;
		UPDATE security_crawler_sources SET update_enabled=1,url=? WHERE name='googlebot'`, ts.URL); err != nil {
		t.Fatalf("wire source: %v", err)
	}
	// 当前快照 3 条（收缩门不参与本形态判定）。
	previous := []string{"203.0.113.1/32", "203.0.113.2/32", "203.0.113.3/32"}
	if err := upsertCrawlerIPList("googlebot", previous); err != nil {
		t.Fatalf("seed snapshot: %v", err)
	}

	err := GetCrawlerUpdateManager().RunUpdate(context.Background(), taskengine.RunContext{Ctx: context.Background(), Trigger: "manual"})
	if err == nil {
		t.Fatal("膨胀响应必须让源更新失败（保留上次快照），不得写入")
	}
	loaded, err := loadCrawlerIPListsFromDB()
	if err != nil {
		t.Fatalf("load lists: %v", err)
	}
	if got := loaded["googlebot"]; len(got) != len(previous) {
		t.Fatalf("旧快照被覆盖：%d 条, want %d（膨胀名单必须拒绝写入）", len(got), len(previous))
	}
	logText := readTaskLog(t, "crawlerbot-update")
	if !strings.Contains(logText, "超过系统名单上限") {
		t.Fatalf("任务日志缺少扩张门拒绝原因:\n%s", logText)
	}
}
