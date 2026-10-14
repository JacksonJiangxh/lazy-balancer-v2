// Package services 自动封禁（历史问题）：WAF 事件滑动窗口计数 → 阈值判定 →
// 「自动封禁名单」条目 merge → 引用策略重载（节流）。
//
// 数据流：security-events-ingestion 提交点（securityEventsProcessPass 每批
// Commit 后）喂 autobanObserveBatch（主节点+启用+口径+WAF 事件四重过滤）→
// 固定桶计数器；autoban 任务（60s 循环、主节点、EnabledFn=autoban_enabled）
// 每轮评估候选并执行「观察建议或名单 merge」。
//
// 名单形态：预置 security_ip_lists 行（system=1，name=自动封禁名单，DB entries）。
// 条目扩展 created_at/expires_at（RFC 墙钟串、UTC 存储）——投影层
// （loadIPListEntriesVia）过滤已到期条目，到期即「自动解封」；手动条目
// （remark≠自动封禁）永不被任务挤出。手动解封写 autoban_suppressed 抑制表
// （30 天窗口），期内该 IP 不再被自动封禁。
package services

import (
	"encoding/json"
	"errors"
	"fmt"
	"sort"
	"strings"
	"sync"
	"time"

	"lazy-balancer-v2/internal/db"
	"lazy-balancer-v2/internal/models"
	"lazy-balancer-v2/internal/taskengine"
)

const (
	// AutobanTaskID 任务 ID（taskengine 注册/任务监控/日志文件名共用）。
	AutobanTaskID = "autoban"
	// AutobanPresetListName 预置名单行名（迁移种子同字面值，db_autoban_migration_test 锚定）。
	AutobanPresetListName = "自动封禁名单"
	// AutobanEntryRemark 自动条目标记：merge 挤出与「今日封禁数」统计的唯一判据。
	AutobanEntryRemark = "自动封禁"
	// AutobanManualUnbanRemark 手动追加条目的默认备注（地址列表页手动封禁）。
	AutobanManualUnbanRemark = "手动封禁"

	// autobanSuppressDays 手动解封抑制窗口：期内不再自动封禁（防解封→重封拉锯）。
	autobanSuppressDays = 30 * 24 * time.Hour
	// autobanReloadThrottle 重载节流窗口：名单变化后至少间隔 60s 才真实重载，
	// 窗口内的变化暂存合并到下一轮。
	autobanReloadThrottle = time.Minute
	// autobanSuggestionCap 观察建议保留上限（按计数降序截断）。
	autobanSuggestionCap = 200
)

// autobanTimeLayout 名单条目时间戳形态（UTC 墙钟串，前端 parseDateValue 按
// DB datetime 同款 +Z 规范化消费）。
const autobanTimeLayout = "2006-01-02 15:04:05"

// autobanMaxTrackedIPs 计数器键上限（超限丢新键并告警一次）——攻击洪峰下
// 计数器内存有界（10 万键 × ~50B ≈ 5MB 量级）。
var autobanMaxTrackedIPs = 100000

// AutobanListEntryCap 名单条目上限（与 handlers ipListMaxEntries 同值——
// handlers 侧有钉测锁定相等；merge 超限时挤最早到期的自动条目）。
var AutobanListEntryCap = 500

// AutobanDuration/Clock/Scope：配置枚举与时长换算。
var autobanDurations = map[string]time.Duration{
	"10m":       10 * time.Minute,
	"30m":       30 * time.Minute,
	"1h":        time.Hour,
	"6h":        6 * time.Hour,
	"12h":       12 * time.Hour,
	"24h":       24 * time.Hour,
	"permanent": 0, // 永久：expires_at 留空
}

func ValidAutobanDuration(s string) bool { _, ok := autobanDurations[s]; return ok }
func ValidAutobanScope(s string) bool    { return s == "blocked" || s == "logged" || s == "all" }

// AutobanDurationLabel 时长枚举的展示文案（前端配置弹框同款语义）。
func AutobanDurationLabel(s string) string {
	switch s {
	case "permanent":
		return "永久"
	case "10m":
		return "10 分钟"
	case "30m":
		return "30 分钟"
	case "6h":
		return "6 小时"
	case "12h":
		return "12 小时"
	case "24h":
		return "24 小时"
	case "1h":
		return "1 小时"
	default:
		return s
	}
}

// AutobanConfig 六项配置（GET/PUT /security/autoban 载荷与任务/计数器共用形态）。
type AutobanConfig struct {
	Enabled       bool   `json:"enabled"`
	Threshold     int    `json:"threshold"`
	WindowMinutes int    `json:"window_minutes"`
	Duration      string `json:"duration"`
	Scope         string `json:"scope"`
	DryRun        bool   `json:"dry_run"`
}

// autobanNow 时钟缝（测试注入时间轴）。
var autobanNow = func() time.Time { return time.Now().UTC() }

// autobanIsMaster 主节点缝（生产=引擎角色；测试可覆写）。
var autobanIsMaster = func() bool {
	te := TaskEngine()
	return te != nil && te.IsMaster()
}

// autobanReloader 名单内容变化后的 Caddy 重载（main.go 注入 caddyReloader，
// 与 SetThreatReloader 同点注入）。
var autobanReloader func() error

// SetAutobanReloader 注册重载回调（nil=清除，测试用）。
func SetAutobanReloader(fn func() error) { autobanReloader = fn }

// ---- 配置读写 ----

// GetAutobanConfig 读六项配置（COALESCE 兜底默认值——存量行/带外 NULL 行归一）。
func GetAutobanConfig() AutobanConfig {
	cfg := AutobanConfig{Threshold: 100, WindowMinutes: 5, Duration: "1h", Scope: "all", DryRun: true}
	if db.DB == nil {
		return cfg
	}
	var en, threshold, window, dry int
	var duration, scope string
	err := db.DB.QueryRow(`SELECT COALESCE(autoban_enabled,0), COALESCE(autoban_threshold,100), COALESCE(autoban_window_minutes,5),
		COALESCE(autoban_duration,'1h'), COALESCE(autoban_scope,'all'), COALESCE(autoban_dry_run,1)
		FROM global_config WHERE id=1`).Scan(&en, &threshold, &window, &duration, &scope, &dry)
	if err != nil {
		return cfg
	}
	cfg.Enabled = en == 1
	cfg.Threshold = threshold
	cfg.WindowMinutes = window
	cfg.Duration = duration
	cfg.Scope = scope
	cfg.DryRun = dry == 1
	return cfg
}

// ValidateAutobanConfig 写侧校验：阈值 1-10000、窗口 1-60 分钟、时长/口径枚举。
func ValidateAutobanConfig(cfg AutobanConfig) error {
	if cfg.Threshold < 1 || cfg.Threshold > 10000 {
		return errors.New("阈值须在 1-10000 之间")
	}
	if cfg.WindowMinutes < 1 || cfg.WindowMinutes > 60 {
		return errors.New("统计窗口须在 1-60 分钟之间")
	}
	if !ValidAutobanDuration(cfg.Duration) {
		return errors.New("封禁时长取值无效")
	}
	if !ValidAutobanScope(cfg.Scope) {
		return errors.New("统计口径取值无效")
	}
	return nil
}

// SetAutobanConfig 写六项配置；窗口/口径变更时重置计数器（口径语义变了，
// 旧计数不可与新口径混算）。
func SetAutobanConfig(cfg AutobanConfig) error {
	if err := ValidateAutobanConfig(cfg); err != nil {
		return err
	}
	prev := GetAutobanConfig()
	en, dry := 0, 0
	if cfg.Enabled {
		en = 1
	}
	if cfg.DryRun {
		dry = 1
	}
	if _, err := db.DB.Exec(`UPDATE global_config SET autoban_enabled=?, autoban_threshold=?, autoban_window_minutes=?, autoban_duration=?, autoban_scope=?, autoban_dry_run=? WHERE id=1`,
		en, cfg.Threshold, cfg.WindowMinutes, cfg.Duration, cfg.Scope, dry); err != nil {
		return err
	}
	if prev.WindowMinutes != cfg.WindowMinutes || prev.Scope != cfg.Scope {
		ResetAutobanCounters()
	}
	return nil
}

// AutobanEnabled 业务开关（EnabledFn 数据源，fail-closed：读库失败=已停止）。
func AutobanEnabled() bool {
	if db.DB == nil {
		return false
	}
	var en int
	if err := db.DB.QueryRow(`SELECT COALESCE(autoban_enabled,0) FROM global_config WHERE id=1`).Scan(&en); err != nil {
		return false
	}
	return en == 1
}

// ---- 计数器（固定桶滑动窗口） ----

type autobanCounter struct {
	Count       int
	WindowStart time.Time
}

// autobanFeedItem 摄取提交点的最小喂入形态。
type autobanFeedItem struct {
	IP            string
	Action        string
	RuleTriggered string
}

var autobanMu sync.Mutex

// autobanWindows 固定桶计数器（ip → 窗口计数/窗口起点）。
var autobanWindows = make(map[string]*autobanCounter)

// autobanSuggestions 上一轮观察建议（dry-run；/status 建议列表数据源）。
var autobanSuggestions []AutobanSuggestion

// autobanReloadPending/autobanLastReload 重载节流状态；autobanCapWarned 上限告警单次留痕。
var autobanReloadPending bool
var autobanLastReload time.Time
var autobanCapWarned bool

// ResetAutobanCounters 清空计数器（口径/窗口变更/测试用）。
func ResetAutobanCounters() {
	autobanMu.Lock()
	defer autobanMu.Unlock()
	autobanWindows = make(map[string]*autobanCounter)
}

// autobanActionMatches 口径过滤：scope=blocked 只统计拦截，logged 只统计检测，
// all 全统计。
func autobanActionMatches(scope, action string) bool {
	switch scope {
	case "blocked":
		return action == "blocked"
	case "logged":
		return action == "logged"
	default:
		return action == "blocked" || action == "logged"
	}
}

// autobanObserveBatch 摄取提交点喂入（每批 Commit 后调用）。四重门：主节点 +
// 启用 + WAF 事件（rule_triggered 非空）+ 口径。任一门不过整批跳过；批内
// 逐条按口径过滤。
func autobanObserveBatch(items []autobanFeedItem) {
	if len(items) == 0 || !autobanIsMaster() || !AutobanEnabled() {
		return
	}
	scope := GetAutobanConfig().Scope
	for _, it := range items {
		autobanObserveEventScoped(it.IP, it.Action, it.RuleTriggered, scope)
	}
}

// autobanObserveEvent 单事件喂入（门：主节点+启用+口径+WAF 事件；口径当轮直读）。
func autobanObserveEvent(ip, action, ruleTriggered string) {
	if !autobanIsMaster() || !AutobanEnabled() || ruleTriggered == "" {
		return
	}
	autobanObserveEventScoped(ip, action, ruleTriggered, GetAutobanConfig().Scope)
}

func autobanObserveEventScoped(ip, action, ruleTriggered, scope string) {
	if ip == "" || ruleTriggered == "" || !autobanActionMatches(scope, action) {
		return
	}
	now := autobanNow()
	window := time.Duration(GetAutobanConfig().WindowMinutes) * time.Minute
	if window <= 0 {
		window = 5 * time.Minute
	}
	autobanMu.Lock()
	defer autobanMu.Unlock()
	w, exists := autobanWindows[ip]
	if !exists {
		if len(autobanWindows) >= autobanMaxTrackedIPs {
			if !autobanCapWarned {
				autobanCapWarned = true
				Logf("warn", "自动封禁计数器达 %d 键上限，新 IP 不再计数（既有键不受影响）", autobanMaxTrackedIPs)
			}
			return
		}
		w = &autobanCounter{}
		autobanWindows[ip] = w
	}
	if w.WindowStart.IsZero() || now.Sub(w.WindowStart) >= window {
		w.Count = 0
		w.WindowStart = now
	}
	w.Count++
}

// AutobanSuggestion 观察建议/候选形态。
type AutobanSuggestion struct {
	IP    string `json:"ip"`
	Count int    `json:"count"`
}

// autobanCandidates 评估候选：修剪过期桶后返回 count≥threshold 的 IP（计数降序，
// 截 autobanSuggestionCap）。
func autobanCandidates(threshold int, window time.Duration) []AutobanSuggestion {
	now := autobanNow()
	autobanMu.Lock()
	defer autobanMu.Unlock()
	for ip, w := range autobanWindows {
		if !w.WindowStart.IsZero() && now.Sub(w.WindowStart) >= window {
			delete(autobanWindows, ip)
		}
	}
	var out []AutobanSuggestion
	for ip, w := range autobanWindows {
		if w.Count >= threshold {
			out = append(out, AutobanSuggestion{IP: ip, Count: w.Count})
		}
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Count != out[j].Count {
			return out[i].Count > out[j].Count
		}
		return out[i].IP < out[j].IP
	})
	if len(out) > autobanSuggestionCap {
		out = out[:autobanSuggestionCap]
	}
	return out
}

// AutobanSuggestions 上一轮观察建议（/status 建议列表数据源；未运行过=空）。
func AutobanSuggestions() []AutobanSuggestion {
	autobanMu.Lock()
	defer autobanMu.Unlock()
	return append([]AutobanSuggestion(nil), autobanSuggestions...)
}

func autobanSetSuggestions(s []AutobanSuggestion) {
	autobanMu.Lock()
	defer autobanMu.Unlock()
	autobanSuggestions = s
}

// ---- 抑制表（手动解封 30 天窗口） ----

// SuppressAutobanIP 手动解封抑制：UPSERT 到 now+30 天（重复解封续期）。
func SuppressAutobanIP(ip string) error {
	if db.DB == nil || ip == "" {
		return nil
	}
	until := autobanNow().Add(autobanSuppressDays).Format(autobanTimeLayout)
	_, err := db.DB.Exec(`INSERT INTO autoban_suppressed (ip, suppressed_until) VALUES (?, ?)
		ON CONFLICT(ip) DO UPDATE SET suppressed_until=excluded.suppressed_until`, ip, until)
	return err
}

// AutobanSuppressWindow 手动解封抑制窗口（30 天；handlers 解封路径在自身
// 事务内落抑制行，与条目移除原子）。
func AutobanSuppressWindow() time.Duration { return autobanSuppressDays }

// AutobanTimeLayout 条目/抑制时间戳形态（UTC 墙钟串，前端按 DB datetime
// 同款 +Z 规范化消费）。
const AutobanTimeLayout = autobanTimeLayout

// autobanSuppressedSet 当前生效的抑制集合（suppressed_until > now）。
func autobanSuppressedSet(now time.Time) map[string]struct{} {
	set := make(map[string]struct{})
	if db.DB == nil {
		return set
	}
	rows, err := db.DB.Query(`SELECT ip FROM autoban_suppressed WHERE suppressed_until > ?`, now.Format(autobanTimeLayout))
	if err != nil {
		return set
	}
	defer rows.Close()
	for rows.Next() {
		var ip string
		if rows.Scan(&ip) == nil {
			set[ip] = struct{}{}
		}
	}
	return set
}

// autobanCleanupSuppression 删除已过期抑制行（Run 轮内自然清理），返回删除数。
func autobanCleanupSuppression() int64 {
	if db.DB == nil {
		return 0
	}
	res, err := db.DB.Exec(`DELETE FROM autoban_suppressed WHERE suppressed_until <= ?`, autobanNow().Format(autobanTimeLayout))
	if err != nil {
		return 0
	}
	n, _ := res.RowsAffected()
	return n
}

// ---- 名单 merge ----

// autobanMergeOutcome 单轮 merge 结果（TaskLogf 摘要与审计数据源）。
type autobanMergeOutcome struct {
	ListID            int64
	Expired           []string // 到期自动解封的 IP
	Banned            []string // 本轮新封禁的 IP
	SkippedSuppressed int      // 抑制期内跳过数
	Evicted           int      // 超限挤出的自动条目数
	DroppedNew        int      // 容量不足丢弃的新封数
	Total             int      // merge 后名单总条数
	Changed           bool
}

// parseAutobanEntryTime 解析条目时间戳（UTC 墙钟串）；畸形视为零值（调用方
// 按无时间处理——到期过滤只认可解析且 <= now 的值，畸形 expires_at 保留条目
// 不误删）。
func parseAutobanEntryTime(s string) time.Time {
	if s == "" {
		return time.Time{}
	}
	ts, err := time.ParseInLocation(autobanTimeLayout, s, time.UTC)
	if err != nil {
		return time.Time{}
	}
	return ts
}

// autobanMergeEntries 单次 merge（纯 DB 侧，无重载/审计副作用——便于钉测）：
// 清到期 → 抑制/已在名单过滤 → 追加新封 → 超限挤最早到期自动条目 → 回写。
func autobanMergeEntries(cfg AutobanConfig, candidates []AutobanSuggestion) (autobanMergeOutcome, error) {
	var out autobanMergeOutcome
	if db.DB == nil {
		return out, errors.New("数据库未初始化")
	}
	now := autobanNow()
	nowStr := now.Format(autobanTimeLayout)
	var id int64
	if err := db.DB.QueryRow(`SELECT id FROM security_ip_lists WHERE name=? AND COALESCE(system,0)=1`, AutobanPresetListName).Scan(&id); err != nil {
		return out, fmt.Errorf("预置名单「%s」不存在: %w", AutobanPresetListName, err)
	}
	out.ListID = id
	var raw string
	if err := db.DB.QueryRow(`SELECT COALESCE(entries,'[]') FROM security_ip_lists WHERE id=?`, id).Scan(&raw); err != nil {
		return out, err
	}
	var entries []models.IPListEntry
	if err := json.Unmarshal([]byte(raw), &entries); err != nil {
		return out, fmt.Errorf("预置名单条目解析失败: %w", err)
	}

	// 1) 清到期（到期即解封）；不可解析的 expires_at 保留（fail-open 不误删）。
	kept := make([]models.IPListEntry, 0, len(entries))
	inList := make(map[string]struct{}, len(entries))
	for _, e := range entries {
		if exp := parseAutobanEntryTime(e.ExpiresAt); !exp.IsZero() && !exp.After(now) {
			out.Expired = append(out.Expired, e.Value)
			out.Changed = true
			continue
		}
		kept = append(kept, e)
		inList[e.Value] = struct{}{}
	}

	// 2) 新封过滤：已在名单/抑制期内跳过；其余追加（permanent 不带 expires_at）。
	suppressed := autobanSuppressedSet(now)
	duration := autobanDurations[cfg.Duration]
	var toAdd []models.IPListEntry
	for _, c := range candidates {
		if c.IP == "" {
			continue
		}
		if _, exists := inList[c.IP]; exists {
			continue
		}
		if _, ok := suppressed[c.IP]; ok {
			out.SkippedSuppressed++
			continue
		}
		entry := models.IPListEntry{Value: c.IP, Remark: AutobanEntryRemark, CreatedAt: nowStr}
		if duration > 0 {
			entry.ExpiresAt = now.Add(duration).Format(autobanTimeLayout)
		}
		toAdd = append(toAdd, entry)
		inList[c.IP] = struct{}{}
	}

	// 3) 容量收敛：先挤「最早到期的自动条目」（永久自动条目次之），手动条目
	//（remark≠自动封禁）不挤；仍不足丢弃剩余新封。
	evict := func() (models.IPListEntry, bool) {
		var victimIdx = -1
		var victimTime time.Time
		var victimPermanent bool
		for i, e := range kept {
			if e.Remark != AutobanEntryRemark {
				continue
			}
			exp := parseAutobanEntryTime(e.ExpiresAt)
			perm := exp.IsZero()
			if victimIdx == -1 {
				victimIdx, victimTime, victimPermanent = i, exp, perm
				continue
			}
			// 挤出序：有到期时间者按到期升序先挤；永久条目排在所有有到期者之后。
			switch {
			case !perm && victimPermanent:
				victimIdx, victimTime, victimPermanent = i, exp, perm
			case !perm && !victimPermanent && exp.Before(victimTime):
				victimIdx, victimTime, victimPermanent = i, exp, perm
			case perm && victimPermanent:
				// 两个永久条目：按 created_at 更早者先挤
				if cur := parseAutobanEntryTime(e.CreatedAt); !cur.IsZero() {
					if vk := parseAutobanEntryTime(kept[victimIdx].CreatedAt); vk.IsZero() || cur.Before(vk) {
						victimIdx = i
					}
				}
			}
		}
		if victimIdx == -1 {
			return models.IPListEntry{}, false
		}
		victim := kept[victimIdx]
		kept = append(kept[:victimIdx], kept[victimIdx+1:]...)
		return victim, true
	}
	for len(kept)+len(toAdd) > AutobanListEntryCap {
		if victim, ok := evict(); ok {
			out.Evicted++
			out.Changed = true
			_ = victim
			continue
		}
		// 手动条目占满容量：丢弃剩余新封（最早到期的自动条目已无可挤）。
		out.DroppedNew = len(toAdd)
		toAdd = nil
		break
	}

	// 4) 落库（有变化时）。
	kept = append(kept, toAdd...)
	out.Total = len(kept)
	if len(toAdd) > 0 {
		out.Banned = make([]string, len(toAdd))
		for i, e := range toAdd {
			out.Banned[i] = e.Value
		}
		out.Changed = true
	}
	if !out.Changed {
		return out, nil
	}
	merged, err := json.Marshal(kept)
	if err != nil {
		return out, err
	}
	if _, err := db.DB.Exec(`UPDATE security_ip_lists SET entries=?, updated_by=0, updated_at=? WHERE id=?`, string(merged), nowStr, id); err != nil {
		return out, err
	}
	return out, nil
}

// ---- 重载节流 ----

// autobanRequestReload 名单变化后请求重载：距上次真实重载 ≥60s 立即执行，
// 否则置暂存（下一轮 Run 的 autobanFlushPendingReload 合并执行）。
func autobanRequestReload(reason string) {
	if autobanReloader == nil {
		return
	}
	autobanMu.Lock()
	if autobanLastReload.IsZero() || autobanNow().Sub(autobanLastReload) >= autobanReloadThrottle {
		autobanLastReload = autobanNow()
		autobanMu.Unlock()
		if err := autobanReloader(); err != nil {
			Logf("warn", "自动封禁名单重载失败（%s）: %v", reason, err)
		}
		return
	}
	autobanReloadPending = true
	autobanMu.Unlock()
}

// autobanFlushPendingReload Run 轮首调用：暂存重载在节流窗口外时合并执行。
func autobanFlushPendingReload() {
	autobanMu.Lock()
	if !autobanReloadPending || autobanReloader == nil {
		autobanMu.Unlock()
		return
	}
	if !autobanLastReload.IsZero() && autobanNow().Sub(autobanLastReload) < autobanReloadThrottle {
		autobanMu.Unlock()
		return
	}
	autobanReloadPending = false
	autobanLastReload = autobanNow()
	autobanMu.Unlock()
	if err := autobanReloader(); err != nil {
		Logf("warn", "自动封禁名单暂存重载失败: %v", err)
	}
}

// ---- Run 循环 ----

// RunAutobanCycle 单轮执行（引擎 autoban 任务体；手动触发同体）：
// 修剪计数器 → 评估候选 → 观察建议或名单 merge → 审计/重载/每轮摘要行。
func RunAutobanCycle(rc taskengine.RunContext) error {
	cfg := GetAutobanConfig()
	window := time.Duration(cfg.WindowMinutes) * time.Minute
	autobanFlushPendingReload()
	autobanCleanupSuppression()
	candidates := autobanCandidates(cfg.Threshold, window)

	if cfg.DryRun {
		autobanSetSuggestions(candidates)
		TaskLogf(AutobanTaskID, "cycle", "观察模式：计数 %d IP / 达阈值 %d（阈值 %d 次/%d 分钟，口径 %s）",
			autobanTrackedCount(), len(candidates), cfg.Threshold, cfg.WindowMinutes, autobanScopeLabel(cfg.Scope))
		return nil
	}

	out, err := autobanMergeEntries(cfg, candidates)
	if err != nil {
		return err
	}
	autobanSetSuggestions(nil)
	if out.Changed {
		// 审计逐 IP「自动封禁」+ 每批「到期自动解封」汇总（系统操作者）。
		for _, ip := range out.Banned {
			RecordAuditLog("system", "自动封禁", "IP 地址列表",
				FormatAuditDetail("IP："+ip,
					fmt.Sprintf("命中：%d 次/%d 分钟", cfg.Threshold, cfg.WindowMinutes),
					"时长："+AutobanDurationLabel(cfg.Duration),
					AuditResultPart("success")), "")
		}
		if len(out.Expired) > 0 {
			RecordAuditLog("system", "自动解封", "IP 地址列表",
				fmt.Sprintf("到期自动解封 %d 个 IP：%s", len(out.Expired), strings.Join(out.Expired, "、")), "")
		}
		if out.Evicted > 0 {
			Logf("warn", "自动封禁名单容量收敛：挤出 %d 条自动条目、丢弃 %d 条新封（上限 %d）", out.Evicted, out.DroppedNew, AutobanListEntryCap)
		}
		autobanRequestReload("名单更新")
	}
	TaskLogf(AutobanTaskID, "cycle", "本轮：计数 %d IP / 候选 %d / 新封 %d / 到期解封 %d / 抑制跳过 %d / 名单 %d 条%s",
		autobanTrackedCount(), len(candidates), len(out.Banned), len(out.Expired), out.SkippedSuppressed, out.Total, reloadNote(out.Changed))
	return nil
}

func reloadNote(changed bool) string {
	if changed {
		return "（已触发重载/暂存）"
	}
	return ""
}

func autobanScopeLabel(scope string) string {
	switch scope {
	case "blocked":
		return "仅拦截"
	case "logged":
		return "仅检测"
	default:
		return "全部"
	}
}

func autobanTrackedCount() int {
	autobanMu.Lock()
	defer autobanMu.Unlock()
	return len(autobanWindows)
}

// AutobanTrackedIPs 当前计数器键数（/status tracked_ips）。
func AutobanTrackedIPs() int { return autobanTrackedCount() }

// ---- Status 辅助 ----

// AutobanListEntries 预置名单条目与名单 ID（/status 名单条数与前端条目管理数据源）。
func AutobanListEntries() ([]models.IPListEntry, int64, error) {
	if db.DB == nil {
		return nil, 0, errors.New("数据库未初始化")
	}
	var id int64
	var raw string
	if err := db.DB.QueryRow(`SELECT id, COALESCE(entries,'[]') FROM security_ip_lists WHERE name=? AND COALESCE(system,0)=1`, AutobanPresetListName).Scan(&id, &raw); err != nil {
		return nil, 0, err
	}
	var entries []models.IPListEntry
	if err := json.Unmarshal([]byte(raw), &entries); err != nil {
		return nil, id, err
	}
	return entries, id, nil
}

// AutobanBannedToday 今日自动封禁数：自动条目（remark=自动封禁）created_at
// 落在配置时区的今天。
func AutobanBannedToday() int {
	entries, _, err := AutobanListEntries()
	if err != nil {
		return 0
	}
	loc := CurrentLocation()
	today := autobanNow().In(loc).Format("2006-01-02")
	n := 0
	for _, e := range entries {
		if e.Remark != AutobanEntryRemark {
			continue
		}
		ts := parseAutobanEntryTime(e.CreatedAt)
		if !ts.IsZero() && ts.In(loc).Format("2006-01-02") == today {
			n++
		}
	}
	return n
}
