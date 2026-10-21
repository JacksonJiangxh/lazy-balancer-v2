// Package services —— 爬虫地址库定时更新任务（v2.3.8 用户裁定：厂商 IP
// 名单必须自动保鲜，独立源表/排程/日志/管理面，不并入威胁情报库）。
//
// 机制：security_crawler_sources 源表（Google/OpenAI/Bing/360 官方 JSON/表）
// 独立排程（默认每天 04:00）+ 手动触发下载 → 通用 CIDR 提取（JSON/HTML 通用解析）→
// security_ip_lists 系统名单（name=CrawlerIPListName(engine)，system=1）原子快照
// 写入；失败保留上次快照（fail-safe，绝不以更新失败破坏既有豁免）。
// 验证器（caddygeoip.VerifyCrawler）按 IP 段命中即豁免（方法 C 与方法 B
// PTR 双跳并行），名单投影与既有安全_ip_lists 同表复用。
package services

import (
	"context"
	"errors"
	"fmt"
	"math/big"
	"net/netip"
	"sort"
	"time"

	"lazy-balancer-v2/geoipnames"
	"lazy-balancer-v2/internal/db"
	"lazy-balancer-v2/internal/taskengine"
)

// CrawlerUpdateManager 爬虫地址库更新入口（与威胁库同为 Manager 形态；
// 当前无运行态字段，单例仅统一生命周期与调用契约）。
type CrawlerUpdateManager struct{}

// validateCrawlerEntriesSanity 爬虫名单合理性门（历史问题-02 + 历史问题 收紧）。
// 引擎声明了官方段（geoipnames 单一事实源）时，一切格式（含 JSON——结构化
// 字段白名单由 parseCrawlerCIDRsForFormat 承担，本门承担段集一致性）：
//  1. 子集门：每条解析结果必须 ⊆ 某官方段（off.Bits()<=prefix.Bits() 且
//     包含首地址）——历史问题 前为「交集」判定，0.0.0.0/0、10.0.0.0/8 等
//     覆盖官方段的超网会被放行，写入即对启用爬虫豁免的策略整体 fail-open；
//  2. 覆盖门：每个官方段至少被保留条目覆盖 1/8 地址空间（历史修复 起为
//     地址空间覆盖率口径，不再是「任一更具体条目命中」；阈值依据见函数内
//     360 官方页实测）——截断页/仅一条官方段内 IP 的错误页、以及「每段一个
//     单 IP」的占位形状都不得整体替换豁免名单（与 crawler_seed_parity_test.go
//     的「⊆ + 覆盖」双条件同口径）。
//
// 引擎未声明官方段时无可对照口径，原样放行（收缩门 crawlerSnapshotShrinkGuard
// 与扩张门 crawlerSnapshotGrowthGuard 仍兜底条数塌缩/膨胀）。
func validateCrawlerEntriesSanity(engineID string, entries []string) ([]string, error) {
	if len(entries) == 0 {
		return nil, errors.New("解析无产出（疑似错误页/限流页），保留上次快照")
	}
	declared := crawlerEngineDeclaredRanges(engineID)
	if len(declared) == 0 {
		return entries, nil // 引擎未声明官方段：无可对照的合理性口径
	}
	official := make([]netip.Prefix, 0, len(declared))
	for _, raw := range declared {
		if prefix, err := netip.ParsePrefix(raw); err == nil {
			official = append(official, prefix)
		}
	}
	if len(official) == 0 {
		return entries, nil
	}
	// 子集门：只保留落在某官方段内的条目；页面里的示例/无关 IP 与覆盖官方段
	// 的超网都不得进入豁免名单。
	filtered := make([]string, 0, len(entries))
	filteredPrefixes := make([]netip.Prefix, 0, len(entries))
	for _, entry := range entries {
		prefix, err := netip.ParsePrefix(entry)
		if err != nil {
			continue
		}
		for _, off := range official {
			if off.Bits() <= prefix.Bits() && off.Contains(prefix.Addr()) {
				filtered = append(filtered, entry)
				filteredPrefixes = append(filteredPrefixes, prefix)
				break
			}
		}
	}
	if len(filtered) == 0 {
		return nil, fmt.Errorf("解析结果（%d 条）未落在 %s 声明的官方 IP 段内（疑似错误页/版本串污染），保留上次快照", len(entries), engineID)
	}
	// 覆盖门：按地址空间覆盖率判定——每个官方段至少被保留条目
	// 覆盖 1/8 地址空间（等价于「至少一条窄于官方段 3 位的前缀证据」）。旧实现
	// 「任一更具体条目命中即算覆盖」：一条 /32 就能让官方 /24 算「已覆盖」，
	// 页面给出每段一个单 IP（5×/32）即可整体替换 5 个官方段的豁免名单（收缩门
	// 5*2<5 不命中）。地址空间口径下 /32 对 /24 仅 1/256、对 /21 仅 1/2048。
	//
	// 阈值为何是 1/8 而不是官方段的一半（实测证据，2026-10-20）：
	// 360 官方页（so.com/help/spider_ip.html）在 42.236.8.0/21 内只公布
	// 42.236.10.* / 42.236.12.* 两个 /24（= 该摘要段的 1/4），而引擎 IPRanges
	// 的 /21 是「42.236.10-15.x 归纳」的摘要段。以 50% 为门会把**真实官方页**
	// 永久判为截断（源每轮失败、名单永不更新）；1/8 既容纳官方页的发布粒度，
	// 也把「单 IP/极小段占位」挡在门外（单 IP 远低于 1/8）。
	for _, off := range official {
		if !crawlerPrefixCoverageSufficient(off, filteredPrefixes) {
			return nil, fmt.Errorf("解析结果（%d 条）对 %s 官方段 %s 的地址覆盖不足 1/8（疑似截断页/部分名单/单 IP 占位），保留上次快照", len(filtered), engineID, off)
		}
	}
	return filtered, nil
}

// crawlerPrefixCoverageSufficient 判断 retained（已经过子集门，可能来自其它
// 官方段）对官方段 off 的地址空间并集覆盖率是否 ≥1/8。
// 用 netip 位运算取各条目区间 [start, start+2^)，与 off 求交后
// 排序合并求并集大小：并集口径允许「多条 /24 合并成 /22」这类合法形态，
// 单 IP/极小段无法凑出 1/8 地址空间。条目量级为单源名单（百级），big.Int
// 开销可忽略且只在更新任务（日级）里执行。
func crawlerPrefixCoverageSufficient(off netip.Prefix, retained []netip.Prefix) bool {
	addrBits := off.Addr().BitLen()
	total := new(big.Int).Lsh(big.NewInt(1), uint(addrBits-off.Bits()))
	type span struct{ start, end *big.Int }
	spans := make([]span, 0, len(retained))
	for _, prefix := range retained {
		if prefix.Addr().BitLen() != addrBits {
			continue // 地址族不同，不可能 ⊆ 本官方段
		}
		if off.Bits() > prefix.Bits() || !off.Contains(prefix.Masked().Addr()) {
			continue // 非本段子集（属于其它官方段）
		}
		addr16 := prefix.Masked().Addr().As16()
		start := new(big.Int).SetBytes(addr16[:])
		size := new(big.Int).Lsh(big.NewInt(1), uint(addrBits-prefix.Bits()))
		spans = append(spans, span{start: start, end: new(big.Int).Add(start, size)})
	}
	if len(spans) == 0 {
		return false
	}
	sort.Slice(spans, func(i, j int) bool { return spans[i].start.Cmp(spans[j].start) < 0 })
	covered := new(big.Int)
	curStart, curEnd := spans[0].start, spans[0].end
	for _, s := range spans[1:] {
		if s.start.Cmp(curEnd) <= 0 { // 相邻或重叠 → 合并
			if s.end.Cmp(curEnd) > 0 {
				curEnd = s.end
			}
			continue
		}
		covered.Add(covered, new(big.Int).Sub(curEnd, curStart))
		curStart, curEnd = s.start, s.end
	}
	covered.Add(covered, new(big.Int).Sub(curEnd, curStart))
	// covered*8 >= total（阈值含等号：恰好 1/8 算覆盖）
	return covered.Lsh(covered, 3).Cmp(total) >= 0
}

// crawlerSnapshotBaseline 当前快照条数与「有可对照口径」标志：DB 行优先
// （运行期唯一真相），无行回退内置首版（首轮更新也受门），两者皆无 → known=false
// （无可对照口径，条数门放行）。基线读取失败按失败处理（保留上次快照，方向安全）。
func crawlerSnapshotBaseline(engineID string) (count int, known bool, err error) {
	if entries, ok := crawlerBuiltinSnapshot[engineID]; ok {
		count, known = len(entries), true
	}
	if db.DB == nil {
		return count, known, nil
	}
	all, err := loadCrawlerIPListsFromDB()
	if err != nil {
		return 0, false, err
	}
	if current, ok := all[engineID]; ok {
		return len(current), true, nil
	}
	return count, known, nil
}

// crawlerSnapshotShrinkGuard 条数收缩门（历史问题）：新名单条数较当前快照
// 收缩超过一半时拒绝写入、保留上次快照——子集/覆盖门之外的兜底（引擎未
// 声明官方段时它是唯一闸门）。基线=DB 名单行当前条数，无行回退内置首版
// （首轮更新也受门），两者皆无则放行（无可对照口径）。基线读取失败按
// 失败处理（保留上次快照，方向安全）。
func crawlerSnapshotShrinkGuard(engineID string, newCount int) error {
	baseline, known, err := crawlerSnapshotBaseline(engineID)
	if err != nil {
		return fmt.Errorf("读取爬虫名单基线失败: %w", err)
	}
	if !known {
		return nil
	}
	if baseline >= 2 && newCount*2 < baseline {
		return fmt.Errorf("解析条数 %d 较当前快照 %d 收缩超过一半（疑似错误页/劫持），保留上次快照", newCount, baseline)
	}
	return nil
}

// CrawlerIPListEntryCap 爬虫系统名单条目绝对上限。与产品口径
// handlers/securityiplists.go 的 ipListMaxEntries=2000 同义（services 不能
// import handlers，故此处单源声明并注明同义；两值漂移会让任务写入越过管理面
// 上限，与 AutobanListEntryCap 同型的跨包契约）。
const CrawlerIPListEntryCap = 2000

// crawlerSnapshotGrowthGuard 条数扩张门（历史修复，与收缩门对称）：源响应上限
// 16MB，通用 CIDR 提取后可产出数十万条，此前只有收缩门（防塌缩），膨胀会直接
// 放大 DB 行、crawler-ip-lists.json、插件每 10min 重载的前缀表与渲染期内存，
// 并绕过产品 2000 条口径。两道门：
//  1. 绝对上限 CrawlerIPListEntryCap（无对照基线的引擎同样受约束）；
//  2. 相对上限：较当前快照膨胀一倍以上（官方名单规模稳定，翻倍即视为劫持/
//     污染），无对照基线时不适用。
//
// 拒绝时保留上次快照；调用方按源失败留痕（任务日志 ERROR + 源状态 failed +
// 运行审计「更新失败」），不在此重复记录。
func crawlerSnapshotGrowthGuard(engineID string, newCount int) error {
	if newCount > CrawlerIPListEntryCap {
		return fmt.Errorf("解析条数 %d 超过系统名单上限 %d 条，拒绝写入（保留上次快照）", newCount, CrawlerIPListEntryCap)
	}
	baseline, known, err := crawlerSnapshotBaseline(engineID)
	if err != nil {
		return fmt.Errorf("读取爬虫名单基线失败: %w", err)
	}
	if known && baseline > 0 && newCount > baseline*2 {
		return fmt.Errorf("解析条数 %d 较当前快照 %d 膨胀超过一倍（疑似劫持/污染），拒绝写入（保留上次快照）", newCount, baseline)
	}
	return nil
}

// crawlerEngineDeclaredRanges 返回引擎声明的官方 IP 段（geoipnames 单一源）。
func crawlerEngineDeclaredRanges(engineID string) []string {
	for _, engine := range geoipnames.CrawlerEngines() {
		if engine.ID == engineID {
			return engine.IPRanges
		}
	}
	return nil
}

var crawlerUpdateManager = &CrawlerUpdateManager{}

func GetCrawlerUpdateManager() *CrawlerUpdateManager { return crawlerUpdateManager }

// RunUpdate 单轮全量更新（手动/自动同体）：逐源下载+解析+快照。
// 任一源失败记录失败态但**不回滚其它源**（与威胁库同语义：失败保留上次快照）。
// 任务时间源=task_runs.started_at（经 RunID，配置时区墙钟→UTC 存储）：
// 源 started_at/last_checked 与任务监控为同一时刻；业务流水统一写任务日志。
func (m *CrawlerUpdateManager) RunUpdate(ctx context.Context, rc taskengine.RunContext) error {
	operator := rc.Operator
	if operator == "" {
		operator = "system"
	}
	outcome := "success"
	defer func() {
		detail := fmt.Sprintf("更新%s（触发：%s）", map[string]string{
			"success": "成功", "failed": "失败", "cancelled": "已取消", "skipped": "跳过",
		}[outcome], rc.Trigger)
		switch outcome {
		case "failed":
			RecordAuditLog(operator, "更新失败", "爬虫地址库", detail, "")
		case "cancelled":
			RecordAuditLog(operator, "取消", "爬虫地址库", detail, "")
		default:
			RecordAuditLog(operator, "更新", "爬虫地址库", detail, "")
		}
	}()
	if db.DB == nil {
		outcome = "failed"
		return errors.New("主库未初始化")
	}
	if !updateRunStillMaster() {
		outcome = "skipped"
		TaskLogfWarn("crawlerbot-update", "skipped", "当前节点为从节点，终止爬虫地址更新")
		return taskengine.ErrTaskSkipped
	}
	if err := ctx.Err(); err != nil {
		outcome = "cancelled"
		return err
	}
	if err := ensureCrawlerSources(); err != nil {
		outcome = "failed"
		return err
	}
	sources, err := crawlerDueSources(rc.Trigger)
	if err != nil {
		outcome = "failed"
		return err
	}
	if len(sources) == 0 {
		outcome = "skipped"
		TaskLogf("crawlerbot-update", "skipped", "没有启用或到期的爬虫源")
		return nil
	}
	TaskLogf("crawlerbot-update", "checking", "开始更新爬虫地址库（%d 个启用源）", len(sources))
	runStarted := taskRunStartedAt(&rc)
	var firstErr error
	successCount, failedCount, totalEntries, changedCount := 0, 0, 0, 0
	for _, src := range sources {
		if !updateRunStillMaster() {
			outcome = "skipped"
			TaskLogfWarn("crawlerbot-update", "skipped", "节点已降级为从节点，终止爬虫地址更新（已完成源保留）")
			return taskengine.ErrTaskSkipped
		}
		if err := ctx.Err(); err != nil {
			outcome = "cancelled"
			return err
		}
		if err := markCrawlerSourceRunning(src.Name, rc.Trigger, runStarted); err != nil {
			if firstErr == nil {
				firstErr = fmt.Errorf("源 %s 标记运行失败: %w", src.Name, err)
			}
			failedCount++
			taskengine.TeeTaskLogTime("crawlerbot-update", "ERROR", "failed", fmt.Sprintf("源 %s 标记运行失败: %v", src.Name, err))
			continue
		}
		TaskLogf("crawlerbot-update", "downloading", "下载 %s（%s）", src.Name, src.URL)
		var body string
		err = runWithInTaskRetry(ctx, func() error {
			var fetchErr error
			body, fetchErr = crawlerFetchBody(ctx, src)
			return fetchErr
		}, func(attempt int, wait time.Duration, rerr error) {
			TaskLogfWarn("crawlerbot-update", "retry", "源 %s 下载失败: %v；等待 %s 重试，第 %d 次，共 3 次", src.Name, rerr, wait, attempt)
		})
		if err != nil {
			if ctx.Err() != nil {
				if !updateRunStillMaster() {
					outcome = "skipped"
					TaskLogfWarn("crawlerbot-update", "skipped", "节点已降级为从节点，终止爬虫地址更新（已完成源保留）")
					return taskengine.ErrTaskSkipped
				}
				outcome = "cancelled"
				markCrawlerSourceCancelled(src.Name)
				TaskLogfWarn("crawlerbot-update", "cancelled", "源 %s 更新已手动取消（保留上次快照）", src.Name)
				return ctx.Err()
			}
			if firstErr == nil {
				firstErr = fmt.Errorf("源 %s 下载失败: %w", src.Name, err)
			}
			failedCount++
			markCrawlerSourceFailed(src.Name, rc.Trigger)
			taskengine.TeeTaskLogTime("crawlerbot-update", "ERROR", "failed", fmt.Sprintf("源 %s 更新失败: %v", src.Name, err))
			continue
		}
		// 历史问题：按源声明格式解析（json 源的非 JSON 响应=错误页 → 失败并
		// 保留上次快照；词法边界已排除版本号/日期等 IP 同形 token）。
		entries, perr := parseCrawlerCIDRsForFormat(body, src.Format)
		if perr == nil {
			// 历史问题-02（历史）+ 历史问题（历史收紧）：合理性门——
			// 子集（每条 ⊆ 官方段，取代旧交集判定）+ 覆盖（官方段全覆盖），
			// 一切格式同口径；错误页/超网/截断名单保留上次快照。
			entries, perr = validateCrawlerEntriesSanity(src.Name, entries)
		}
		if perr == nil {
			// 历史问题：条数收缩门——较当前快照（DB/内置首版）收缩过半拒绝写入。
			perr = crawlerSnapshotShrinkGuard(src.Name, len(entries))
		}
		if perr == nil {
			// 条数扩张门——绝对 2000 条上限 + 较当前快照翻倍拒绝
			// （源响应可达 16MB，无上限会绕过产品口径放大系统名单）。
			perr = crawlerSnapshotGrowthGuard(src.Name, len(entries))
		}
		if perr != nil {
			if firstErr == nil {
				firstErr = fmt.Errorf("源 %s 解析失败: %w", src.Name, perr)
			}
			failedCount++
			markCrawlerSourceFailed(src.Name, rc.Trigger)
			taskengine.TeeTaskLogTime("crawlerbot-update", "ERROR", "failed", fmt.Sprintf("源 %s 更新失败: %v", src.Name, perr))
			continue
		}
		changed, err := upsertCrawlerIPListChanged(src.Name, entries)
		if err != nil {
			if firstErr == nil {
				firstErr = fmt.Errorf("源 %s 写名单失败: %w", src.Name, err)
			}
			failedCount++
			markCrawlerSourceFailed(src.Name, rc.Trigger)
			taskengine.TeeTaskLogTime("crawlerbot-update", "ERROR", "failed", fmt.Sprintf("源 %s 更新失败: %v", src.Name, err))
			continue
		}
		if changed {
			changedCount++
		}
		markCrawlerSourceSuccess(src.Name, rc.Trigger, len(entries))
		successCount++
		totalEntries += len(entries)
		TaskLogf("crawlerbot-update", "success", "源 %s 更新成功（%d 条，版本 %s）", src.Name, len(entries), time.Now().UTC().Format("2006.01.02"))
	}
	if failedCount > 0 {
		outcome = "failed"
		TaskLogfWarn("crawlerbot-update", "failed", "爬虫地址更新完成：成功 %d、失败 %d", successCount, failedCount)
	} else {
		TaskLogf("crawlerbot-update", "success", "爬虫地址更新完成：%d 个源成功，共 %d 条", successCount, totalEntries)
	}
	// 历史问题：名单内容变化后的收敛——复用威胁库的单源热路径（投影重写
	// 零 /load；未证实收敛回退强制重载）。无变化/全失败不触碰 Caddy。
	if changedCount > 0 {
		convergeIPListProjectionAfterMutation("crawlerbot-update")
	}
	return firstErr
}

// convergeIPListProjectionAfterMutation 内置名单（system=1，可被 ACL/信任面
// 引用）内容变化后的生效路径（历史问题，复用威胁库单源回调）：
//   - 投影刷新器已注册 → RefreshIPListProjections（毫秒级、零 /load，
//     @ipListFast 匹配器 ≤1s stat 热感知）；
//   - 未证实收敛（发射面变化/运行配置不可读/刷新被拒）或回调未注册 →
//     回退全量 /load（宁可一次重载，不欠引用方渲染收敛）。
func convergeIPListProjectionAfterMutation(task string) {
	if threatProjectionRefresher == nil {
		TaskLogfWarn(task, "unchanged", "投影刷新器未注册，跳过名单投影热路径（引用方由下次配置变更收敛）")
		return
	}
	hot, err := threatProjectionRefresher()
	if err == nil && hot == ProjectionConverged {
		TaskLogf(task, "hot", "名单内容变化经投影热路径收敛（零 Caddy 重载）")
		return
	}
	TaskLogf(task, "reloading", "投影热路径未证实收敛，回退重载 Caddy 配置")
	if threatReloader == nil {
		TaskLogfWarn(task, "reloading", "重载回调未注册，引用方渲染由下次配置变更收敛")
		return
	}
	// 真实 /load 与同族（threat_update/autoban/crs/ip2region）同口径
	// 留系统重载审计——此前爬虫路径只写应用日志，审计中心无记录。
	rerr := threatReloader()
	recordSystemReloadAudit("crawlerbot_update", rerr)
	if rerr != nil {
		Logf("error", "爬虫地址库: 名单变化后重载失败: %v", rerr)
		TaskLogfWarn(task, "reloading", "重载 Caddy 配置失败: %v", rerr)
	}
}

// markCrawlerSourceRunning 源开始态：任务开始时刻统一以 UTC 写 started_at/
// last_checked，前端按配置时区展示，避免墙钟被二次 +8h。
func markCrawlerSourceRunning(name, trigger, started string) error {
	_, err := db.DB.Exec(`UPDATE security_crawler_sources SET update_status='running', message='', trigger=?, started_at=?, last_checked=?, updated_at=datetime('now') WHERE name=?`,
		trigger, started, started, name)
	return err
}

// crawlerSlotAdvanceSQL 爬虫源族排程槽推进门（历史问题-2，历史）：与威胁源族
// 同一谓词（schedule.go slotAdvanceGateSQL 单源）——仅 auto 触发且现存槽
// 空/过期才推进。手动触发不动预约、未来槽不回拨（2026-10-11 排程槽生命周期
// 裁定；crawlerbot 新族此前无条件改写 next_update：手动轮可静默吞掉当天自动
// 轮，手动失败也推进槽抑制自动重试）。
const crawlerSlotAdvanceSQL = `next_update=IIF(` + slotAdvanceGateSQL + `, ?, next_update)`

// markCrawlerSourceSuccess 源成功态：entry_count 更新 + version=成功日期 +
// consecutive_failures 清零 + next_update 按排程槽推进门更新。
func markCrawlerSourceSuccess(name, trigger string, entryCount int) {
	next := crawlerNextSlot(time.Now().UTC())
	_, err := db.DB.Exec(`UPDATE security_crawler_sources SET entry_count=?, version=?, update_status='success', message='', consecutive_failures=0, `+crawlerSlotAdvanceSQL+`, finished_at=datetime('now') WHERE name=?`,
		entryCount, time.Now().UTC().Format("2006.01.02"), trigger, next, name)
	if err != nil {
		Logf("error", "crawlerbot-update: 源 %s 写成功态失败: %v", name, err)
	}
}

// markCrawlerSourceCancelled 用户取消终态：保留上次快照、版本与失败计数，
// 不推进排程槽。
func markCrawlerSourceCancelled(name string) {
	_, err := db.DB.Exec(`UPDATE security_crawler_sources SET update_status='cancelled', message='已手动取消（保留上次快照）', finished_at=datetime('now') WHERE name=?`, name)
	if err != nil {
		Logf("error", "crawlerbot-update: 源 %s 写取消态失败: %v", name, err)
	}
}

// markCrawlerSourceFailed 源失败态：consecutive_failures+1、next_update 按
// 同一推进门更新（退避机制已撤除；失败保留上次快照，内容表 entries 不动）。
func markCrawlerSourceFailed(name, trigger string) {
	next := crawlerNextSlot(time.Now().UTC())
	_, err := db.DB.Exec(`UPDATE security_crawler_sources SET update_status='failed', message='下载或解析失败（保留上次快照）', consecutive_failures=consecutive_failures+1, `+crawlerSlotAdvanceSQL+`, finished_at=datetime('now') WHERE name=?`, trigger, next, name)
	if err != nil {
		Logf("error", "crawlerbot-update: 源 %s 写失败态失败: %v", name, err)
	}
}
