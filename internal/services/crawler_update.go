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
	"net/netip"
	"strings"
	"time"

	"lazy-balancer-v2/geoipnames"
	"lazy-balancer-v2/internal/db"
	"lazy-balancer-v2/internal/taskengine"
)

// CrawlerUpdateManager 爬虫地址库更新入口（与威胁库同为 Manager 形态；
// 当前无运行态字段，单例仅统一生命周期与调用契约）。
type CrawlerUpdateManager struct{}

// validateCrawlerEntriesSanity 非结构化源（html/plain）的合理性门（历史问题-02）：
// 解析结果至少一条须落在该引擎声明的官方段（geoipnames 单一事实源）内，
// 否则视为错误页/版本串污染，保留上次快照。JSON 源已由结构化字段校验承担。
func validateCrawlerEntriesSanity(engineID, format string, entries []string) error {
	if strings.EqualFold(strings.TrimSpace(format), "json") {
		return nil
	}
	if len(entries) == 0 {
		return errors.New("解析无产出（疑似错误页/限流页），保留上次快照")
	}
	declared := crawlerEngineDeclaredRanges(engineID)
	if len(declared) == 0 {
		return nil // 引擎未声明官方段：无可对照的合理性口径
	}
	parsed := make([]netip.Prefix, 0, len(entries))
	for _, entry := range entries {
		if prefix, err := netip.ParsePrefix(entry); err == nil {
			parsed = append(parsed, prefix)
		}
	}
	for _, raw := range declared {
		official, err := netip.ParsePrefix(raw)
		if err != nil {
			continue
		}
		for _, prefix := range parsed {
			if official.Contains(prefix.Addr()) || prefix.Contains(official.Addr()) {
				return nil
			}
		}
	}
	return fmt.Errorf("解析结果（%d 条）未落在 %s 声明的官方 IP 段内（疑似错误页/版本串污染），保留上次快照", len(entries), engineID)
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
		if outcome == "failed" || outcome == "cancelled" {
			RecordAuditLog(operator, "更新失败", "爬虫地址库", detail, "")
		} else {
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
		err = runWithInTaskRetry(func() error {
			var fetchErr error
			body, fetchErr = crawlerFetchBody(ctx, src)
			return fetchErr
		}, func(attempt int, wait time.Duration, rerr error) {
			TaskLogfWarn("crawlerbot-update", "retry", "源 %s 下载失败: %v；等待 %s 重试，第 %d 次，共 3 次", src.Name, rerr, wait, attempt)
		})
		if err != nil {
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
			// 历史问题-02（历史）：非结构化源（html/plain）增加合理性门——
			// 错误页/限流页只要含四段数字就可能覆盖豁免名单；解析结果至少一条
			// 必须落在该引擎声明的官方段内，否则保留上次快照。
			perr = validateCrawlerEntriesSanity(src.Name, src.Format, entries)
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
	if rerr := threatReloader(); rerr != nil {
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

// markCrawlerSourceFailed 源失败态：consecutive_failures+1、next_update 按
// 同一推进门更新（退避机制已撤除；失败保留上次快照，内容表 entries 不动）。
func markCrawlerSourceFailed(name, trigger string) {
	next := crawlerNextSlot(time.Now().UTC())
	_, err := db.DB.Exec(`UPDATE security_crawler_sources SET update_status='failed', message='下载或解析失败（保留上次快照）', consecutive_failures=consecutive_failures+1, `+crawlerSlotAdvanceSQL+`, finished_at=datetime('now') WHERE name=?`, trigger, next, name)
	if err != nil {
		Logf("error", "crawlerbot-update: 源 %s 写失败态失败: %v", name, err)
	}
}
