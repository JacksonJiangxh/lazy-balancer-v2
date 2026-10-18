package handlers

import (
	"bytes"
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"regexp"
	"runtime"
	"sort"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/gin-gonic/gin"

	"lazy-balancer-v2/geoipnames"
	"lazy-balancer-v2/internal/db"
	"lazy-balancer-v2/internal/models"
	"lazy-balancer-v2/internal/services"
)

// 威胁大屏（ThreatScreen）数据端点——只读聚合，复用安全总览查询核心
// （security_events 单表 + categorizeAttack 家族单源 + enrichIPLocation 归属
// 地单源），从节点可读（不挂 requireMaster）。

// threatScreenMaxHours hours 参数上限（30 天）——超出回退默认 24h，与非法
// 值同口径（大屏固定 24h 消费，参数仅为后续扩展保留）。
const threatScreenMaxHours = 24 * 30

// threatActiveSourceWindow 活跃攻击源窗口（设计定稿）：近 10 分钟去重 client_ip。
const threatActiveSourceWindow = 10 * time.Minute

// topThreatEntries 计数 map → 前 n 条（值降序；同值按名称升序——确定性输出，
// 大屏 30s 轮询重渲染名次不抖动）。
func topThreatEntries(counts map[string]int, n int) []models.SecurityAttackType {
	entries := make([]models.SecurityAttackType, 0, len(counts))
	for name, value := range counts {
		entries = append(entries, models.SecurityAttackType{Name: name, Value: value})
	}
	sort.Slice(entries, func(i, j int) bool {
		if entries[i].Value != entries[j].Value {
			return entries[i].Value > entries[j].Value
		}
		return entries[i].Name < entries[j].Name
	})
	if len(entries) > n {
		entries = entries[:n]
	}
	return entries
}

// ipSource 公网 IP 回显源（v5 多源回退链，用户指定国内可达优先）：
// 任一源成功（首个合法 IPv4/IPv6）即用；每源独立 3.5s 超时、整体 10s 上限；
// 源名随响应/审计披露便于排障。GitHub 加速代理仅支持 GitHub 路径
// （crshttp.go 契约），不适用本类回显服务，直连。
type ipSource struct {
	name      string
	url       string
	multiLine bool // 文本含附加信息（需正则提取 IP），false=整行即 IP
}

var publicIPSources = []ipSource{
	{name: "myip.ipip.net", url: "https://myip.ipip.net", multiLine: true},
	{name: "cip.cc", url: "https://cip.cc", multiLine: true},
	{name: "ipv4.icanhazip.com", url: "https://ipv4.icanhazip.com"},
	{name: "api.ipify.org", url: "https://api.ipify.org"},
}

var ipExtractPattern = regexp.MustCompile(`\b(?:\d{1,3}\.){3}\d{1,3}\b`)

// fetchPublicIP 出站获取本机公网 IP：多源按序回退（整体 10s 上限），返回
// (IP, 源名)。显式按钮触发、无后台轮询。测试经包级缝注入。
var fetchPublicIP = func() (ip string, source string, err error) {
	client := &http.Client{Timeout: 3500 * time.Millisecond}
	deadline := time.Now().Add(10 * time.Second)
	var lastErr error
	for _, src := range publicIPSources {
		if time.Now().After(deadline) {
			if lastErr == nil {
				lastErr = fmt.Errorf("整体超时")
			}
			break
		}
		ip, err := fetchIPFromSource(client, src)
		if err == nil {
			return ip, src.name, nil
		}
		lastErr = err
		services.Logf("warn", "threat-screen site detect: source %s failed: %v", src.name, err)
	}
	return "", "", lastErr
}

func fetchIPFromSource(client *http.Client, source ipSource) (string, error) {
	resp, err := client.Get(source.url)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("响应 %d", resp.StatusCode)
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, 512))
	if err != nil {
		return "", err
	}
	text := strings.TrimSpace(string(body))
	var ip string
	if source.multiLine {
		if m := ipExtractPattern.FindString(text); m != "" {
			ip = m
		}
	} else {
		ip = text
	}
	if net.ParseIP(ip) == nil {
		return "", fmt.Errorf("未解析到合法 IP")
	}
	return ip, nil
}

// locateSiteCoords 公网 IP → 归属地文本 → 经纬度（本地 xdb + 质心表派生表）：
// 国内取省短名质心、海外取国家质心；无法定位 ok=false（调用方走手动填写指引）。
var locateSiteCoords = func(ip string) (lat, lon float64, location string, ok bool) {
	location = enrichIPLocation(ip)
	if location == "" {
		return 0, 0, "", false
	}
	parts := strings.SplitN(location, "·", 3)
	if len(parts) == 0 || parts[0] == "" {
		return 0, 0, "", false
	}
	if parts[0] == "中国" {
		if len(parts) < 2 {
			return 0, 0, "", false
		}
		if c, found := threatScreenProvinceCentroids[parts[1]]; found {
			return c[1], c[0], location, true
		}
		return 0, 0, "", false
	}
	if c, found := threatScreenCountryCentroids[parts[0]]; found {
		return c[1], c[0], location, true
	}
	return 0, 0, "", false
}

// threatRollupMu 懒固化互斥（每次固化幂等 DELETE+INSERT）；ensure 在批次间
// 主动释放本锁，摄取钩子用 TryLock 排队而不阻塞请求路径。
var threatRollupMu sync.Mutex

// threatRollupEnsureMu 串行化 ensure 调用（与 threatRollupMu 分层）：批次间
// 释放文件/聚合锁但仍只允许一个 ensure 推进覆盖状态。
var threatRollupEnsureMu sync.Mutex

// threatRollupRewindPending 待处理回退目标（UTC 分钟 Unix 秒，0=无）。钩子
// 抢不到锁时置最小值，由下一次 ensure 批次间隙/入口合并处理，避免摄取提交
// 被长回填阻塞。
var threatRollupRewindPending atomic.Int64

var errThreatRollupRestart = errors.New("threat rollup restart after concurrent rewind")

// threatScreenNow 时钟缝（历史 历史问题：可控时间轴验证「上一分钟在完整后
// 至少终固一次」——迟到写入必须被下一次固化覆盖）。
var threatScreenNow = func() time.Time { return time.Now().UTC() }

const (
	// threatRollupWatermarkKey 已覆盖区间的**最新**完整分钟（metrics_state 键）；
	// threatRollupCoveredFromKey 已覆盖区间的**最旧**分钟（空覆盖=lastComplete）。
	threatRollupWatermarkKey   = "threat_rollup_last_fixed_minute"
	threatRollupCoveredFromKey = "threat_rollup_covered_from"
	// threatRollupBatchMinutes 单事务回填分钟数（历史问题：有界批，批间让写锁）。
	threatRollupBatchMinutes = 60
	// threatRollupMaxBatchesPerCall 单次请求最多提交的事务批数（25 批 =
	// 24h 回填 + 最新两分钟段）——空库首屏先返回部分，后续轮询按水位续做，
	// 避免单请求长时间占锁/占连接。默认 24h 窗口一轮完成；更大窗口跨请求
	// 续做。
	threatRollupMaxBatchesPerCall = 25
	// threatRollupRepairMinutes 迟到事件回填窗口（≥摄取停顿 + 一轮 warmer）。
	threatRollupRepairMinutes = 10
	// threatRollupTargetReadyKey 目标维度 rollup 就绪标记（历史 历史问题）：
	// 升级后缺失 → 强制重置覆盖区间重固——否则既有 coverage 宣称已覆盖，
	// 历史窗口的目标计数永久缺失（top_targets 与其余卡片窗口分裂）。
	threatRollupTargetReadyKey = "threat_rollup_target_ready"
	// threatRollupGeoIPGenerationKey 固化时使用的归属地库代际（历史问题）：
	// 与当前代际不一致 → 重固窗口（库恢复后历史空归属地维度自愈）。
	threatRollupGeoIPGenerationKey = "threat_rollup_geoip_generation"
	// threatRollupStaleAfter 固化陈旧阈值（历史 历史问题）：warmer 每 60s
	// 一轮，超过 3 分钟无成功固化视为陈旧——请求路径改为同步固化，持续失败
	// 以 500 显式暴露，不得把旧值伪装成最新 200。
	threatRollupStaleAfter = 3 * time.Minute
)

// loadThreatRollupState 读持久分钟状态（无行/空值/损坏 = 未初始化）。
func loadThreatRollupState(database *sql.DB, key string) (time.Time, bool, error) {
	raw, ok, err := loadThreatRollupRawState(database, key)
	if err != nil || !ok {
		return time.Time{}, false, err
	}
	parsed, perr := time.ParseInLocation("2006-01-02 15:04", raw, time.UTC)
	if perr != nil {
		// 状态损坏按「未初始化」处理（回填有界且幂等，重建成本可控）。
		return time.Time{}, false, nil
	}
	return parsed, true, nil
}

// loadThreatRollupRawState 读 metrics_state 原始值（无行/空值 = 未初始化）。
func loadThreatRollupRawState(database *sql.DB, key string) (string, bool, error) {
	var raw string
	err := database.QueryRow(`SELECT value FROM metrics_state WHERE key=?`, key).Scan(&raw)
	if errors.Is(err, sql.ErrNoRows) {
		return "", false, nil
	}
	if err != nil {
		return "", false, err
	}
	if strings.TrimSpace(raw) == "" {
		return "", false, nil
	}
	return raw, true, nil
}

// threatRollupRewindMinute 钳制回退目标到当前展示窗口下界：窗口外积压无需
// 重算历史 rollup（用户不可见），且避免把水位推到 emptyCoverage 判定之前
// 导致每次摄取都整窗重固。
func threatRollupRewindMinute(minute time.Time) time.Time {
	hours := 24
	if req := int(threatRollupRequestedHours.Load()); req > hours {
		hours = req
	}
	if hours > threatScreenMaxHours {
		hours = threatScreenMaxHours
	}
	horizon := threatScreenNow().UTC().Add(-time.Minute).Truncate(time.Minute).Add(-time.Duration(hours) * time.Hour)
	minute = minute.UTC().Truncate(time.Minute)
	if minute.Before(horizon) {
		minute = horizon
	}
	return minute
}

func queueThreatRollupRewind(minute time.Time) {
	ts := minute.UTC().Truncate(time.Minute).Unix()
	for {
		cur := threatRollupRewindPending.Load()
		if cur != 0 && cur <= ts {
			return
		}
		if threatRollupRewindPending.CompareAndSwap(cur, ts) {
			return
		}
	}
}

func applyPendingThreatRollupRewindInLock() {
	ts := threatRollupRewindPending.Swap(0)
	if ts == 0 {
		return
	}
	threatRollupRewindToInLock(time.Unix(ts, 0).UTC())
}

// ThreatRollupRewindTo 摄取提交后回退 rollup 覆盖水位（历史问题-1，历史）。
// minute=本批实际插入的最旧事件分钟（UTC）。若该分钟落在已覆盖区间内（停机/
// 升级积压、轮转补采），把 last_fixed 回退到 minute-1——下一次 ensureThreatRollup
// 从该分钟起重固到窗口末端（幂等）。
// 历史问题-历史问题：不得阻塞摄取提交——warmer 批次期间 TryLock 失败时仅排队，
// 由 ensure 的批次间隙/下一次 warmer 合并执行；窗口外目标钳制到展示下界。
func ThreatRollupRewindTo(minute time.Time) {
	if minute.IsZero() || db.MetricsDB == nil {
		return
	}
	minute = threatRollupRewindMinute(minute)
	if !threatRollupMu.TryLock() {
		queueThreatRollupRewind(minute)
		return
	}
	defer threatRollupMu.Unlock()
	applyPendingThreatRollupRewindInLock()
	threatRollupRewindToInLock(minute)
}

func drainThreatRollupRewindPending() bool {
	if threatRollupRewindPending.Load() == 0 {
		return false
	}
	if !threatRollupMu.TryLock() {
		return false
	}
	defer threatRollupMu.Unlock()
	applyPendingThreatRollupRewindInLock()
	return true
}

func threatRollupRewindToInLock(minute time.Time) {
	database := db.MetricsDB
	if database == nil {
		return
	}
	lastFixed, okFixed, err := loadThreatRollupState(database, threatRollupWatermarkKey)
	if err != nil {
		services.Logf("warn", "threat rollup rewind: read watermark failed: %v", err)
		return
	}
	if !okFixed {
		return
	}
	target := minute.UTC().Truncate(time.Minute).Add(-time.Minute)
	if !lastFixed.After(target) {
		return // 该分钟尚未被固化，无需回退
	}
	if _, err := database.Exec(`INSERT INTO metrics_state (key, value) VALUES (?, ?) ON CONFLICT(key) DO UPDATE SET value=excluded.value`,
		threatRollupWatermarkKey, target.Format("2006-01-02 15:04")); err != nil {
		services.Logf("warn", "threat rollup rewind: write watermark failed: %v", err)
		return
	}
	services.Logf("info", "threat rollup rewind: 摄取补齐历史分钟 %s，覆盖水位回退为 %s（下一次固化重算）",
		minute.UTC().Truncate(time.Minute).Format("2006-01-02 15:04"), target.Format("2006-01-02 15:04"))
}

// ensureThreatRollup 按需固化 rollup（幂等、自愈、可跨请求续做）：
//   - 水位持久化在 metrics_state（历史问题）——空分钟同样推进，不再用数据行
//     MAX(minute) 反推（空分钟不产行会让水位停滞）；
//   - 每次固化集合恒含 lastComplete 与 currentMinute（历史问题）——上一完整
//     分钟在首次固化后仍可能被迟到写入补充，必须至少终固一次；当前分钟恒
//     重固化（recent_rate 等「最近 N 分钟」口径）；
//   - 回填窗口与请求 hours 一致、下界钳制到 720h（历史问题）；按 60 分钟一批
//     提交、单请求最多 24 批（历史问题），水位与分钟数据同事务提交。
func ensureThreatRollup(hours int) error {
	threatRollupEnsureMu.Lock()
	defer threatRollupEnsureMu.Unlock()
	for {
		err := ensureThreatRollupWithYields(hours)
		if errors.Is(err, errThreatRollupRestart) {
			continue
		}
		if err != nil {
			return err
		}
		if drainThreatRollupRewindPending() {
			continue
		}
		return nil
	}
}

func ensureThreatRollupWithYields(hours int) error {
	threatRollupMu.Lock()
	defer threatRollupMu.Unlock()
	// 句柄快照：后台 warmer 协程可能与测试换库/关停并发——入口快照后全程
	// 使用局部句柄，句柄被置换/关闭时 Begin 报错上抛而非 nil 解引用 panic。
	database := db.MetricsDB
	if database == nil {
		return errors.New("metrics db unavailable")
	}
	if hours < 1 {
		hours = 24
	}
	if hours > threatScreenMaxHours {
		hours = threatScreenMaxHours
	}
	now := threatScreenNow().UTC()
	lastComplete := now.Add(-time.Minute).Truncate(time.Minute)
	currentMinute := now.Truncate(time.Minute)
	horizon := lastComplete.Add(-time.Duration(hours) * time.Hour)

	// 覆盖区间 [coveredFrom, lastFixed]（完整分钟，持久化在 metrics_state）：
	//   - 空覆盖 = coveredFrom 为 lastComplete（首个未来分钟）、lastFixed 为
	//     lastComplete-1；
	//   - 请求窗口 [dFrom, dTo] 中「更旧未覆盖段」与「更新未覆盖段」分别按批
	//     补齐（历史问题：先前窄窗口（hours=1）把水位推到最新后，后续宽窗口
	//     不得因「水位已到最新」而漏掉未回填的旧分钟）。
	// 历史问题：水位与分钟数据同事务提交；空分钟同样推进；陈旧/未来水位钳制。
	dFrom := horizon
	dTo := lastComplete.Add(-time.Minute)
	if dFrom.After(dTo) {
		dFrom = dTo
	}
	coveredFrom, okCovered, err := loadThreatRollupState(database, threatRollupCoveredFromKey)
	if err != nil {
		return err
	}
	lastFixed, okFixed, err := loadThreatRollupState(database, threatRollupWatermarkKey)
	if err != nil {
		return err
	}
	// 一致性归一（历史问题 陈旧/损坏标记钳制）：coveredFrom 在窗口之后、lastFixed
	// 在窗口之后、或 lastFixed 早于 coveredFrom-1（陈旧水位先于已覆盖底端）
	// 一律按空覆盖处理——空覆盖区间的端点=(dTo+1, dTo)，旧侧缺口一次性覆盖到
	// 窗口末端，回填有界且幂等。
	emptyCoverage := !okCovered || !okFixed || coveredFrom.After(dTo) || lastFixed.After(dTo) ||
		lastFixed.Before(coveredFrom.Add(-time.Minute)) ||
		// 历史问题：窗口起点早于已覆盖末端——中间存在未固化长缺口。不得把新侧
		// 起点钳到 dFrom 后仍保留旧 coveredFrom（会伪造连续覆盖并永久漏数）。
		lastFixed.Before(dFrom.Add(-time.Minute))
	// 历史问题：目标维度 rollup 升级标记缺失（旧库首次运行含此修复的版本）→
	// 覆盖区间同按空处理，窗口内分钟全部重固并补出 rule_caddy_id 计数。
	rebuildAll := false
	if _, targetReady, terr := loadThreatRollupState(database, threatRollupTargetReadyKey); terr != nil {
		return terr
	} else if !targetReady {
		emptyCoverage = true
		rebuildAll = true
	}
	// 历史问题：归属地维度只在固化时计算——xdb 在缺口分钟内不可用（启动期/
	// 热换窗口）会让该窗 country/province 永久为空。归属地库代际变化（首次
	// 加载/更新热换）→ 按空覆盖重固请求窗口，库恢复后历史空维度自愈；
	// 原始事件已被保留策略裁剪的分钟仍无法重建（已固化行只会保留原值）。
	geoipGen := strconv.FormatInt(services.GeoIPDataGeneration(), 10)
	if curGen, genOK, gerr := loadThreatRollupRawState(database, threatRollupGeoIPGenerationKey); gerr != nil {
		return gerr
	} else if !genOK || curGen != geoipGen {
		emptyCoverage = true
		rebuildAll = true
	}
	if emptyCoverage {
		coveredFrom = dTo.Add(time.Minute)
		lastFixed = dTo
	}
	saveCoverage := func(tx *sql.Tx, from, until time.Time) error {
		if _, err := tx.Exec(`INSERT INTO metrics_state (key, value) VALUES (?, ?) ON CONFLICT(key) DO UPDATE SET value=excluded.value`, threatRollupCoveredFromKey, from.Format("2006-01-02 15:04")); err != nil {
			return err
		}
		_, err := tx.Exec(`INSERT INTO metrics_state (key, value) VALUES (?, ?) ON CONFLICT(key) DO UPDATE SET value=excluded.value`, threatRollupWatermarkKey, until.Format("2006-01-02 15:04"))
		return err
	}
	backfillBatches := threatRollupMaxBatchesPerCall - 1 // 预留最新两分钟事务
	// 批次间隙释放 threatRollupMu 让摄取钩子/读者通过；重新取锁时先合并待
	// 处理回退，并检测是否发生了并发水位回退——是则从头重跑（本地覆盖状态
	// 已失效），避免旧值覆盖新回退而漏重算。
	yield := func() error {
		threatRollupMu.Unlock()
		runtime.Gosched()
		threatRollupMu.Lock()
		applyPendingThreatRollupRewindInLock()
		current, ok, err := loadThreatRollupState(database, threatRollupWatermarkKey)
		if err != nil {
			return err
		}
		if ok && current.Before(lastFixed) {
			return errThreatRollupRestart
		}
		return nil
	}
	// 1) 旧侧缺口：紧邻已覆盖区间的更旧分钟，从新到旧按批补齐（降序推进，
	// 每批内部升序固化；批提交后 coveredFrom 前移）。
	if coveredFrom.After(dFrom) {
		newestOld := coveredFrom.Add(-time.Minute)
		if newestOld.After(dTo) {
			newestOld = dTo
		}
		for end := newestOld; !end.Before(dFrom) && backfillBatches > 0; backfillBatches-- {
			start := end.Add(-time.Duration(threatRollupBatchMinutes-1) * time.Minute)
			if start.Before(dFrom) {
				start = dFrom
			}
			tx, err := database.Begin()
			if err != nil {
				return err
			}
			for m := start; !m.After(end); m = m.Add(time.Minute) {
				if err := threatFixMinuteWithMode(tx, m, rebuildAll); err != nil {
					tx.Rollback()
					return err
				}
			}
			if err := saveCoverage(tx, start, lastFixed); err != nil {
				tx.Rollback()
				return err
			}
			if err := tx.Commit(); err != nil {
				return err
			}
			if err := yield(); err != nil {
				return err
			}
			coveredFrom = start
			if start.Equal(dFrom) {
				break
			}
			end = start.Add(-time.Minute)
		}
	}
	// 2) 新侧缺口：已覆盖区间的更新分钟（升序按批推进）。
	if !lastFixed.Before(dTo) {
		// 已覆盖到窗口末端，无需新侧回填。
	} else {
		start := lastFixed.Add(time.Minute)
		if start.Before(dFrom) {
			start = dFrom
		}
		for !start.After(dTo) && backfillBatches > 0 {
			backfillBatches--
			end := start.Add(time.Duration(threatRollupBatchMinutes-1) * time.Minute)
			if end.After(dTo) {
				end = dTo
			}
			tx, err := database.Begin()
			if err != nil {
				return err
			}
			for m := start; !m.After(end); m = m.Add(time.Minute) {
				if err := threatFixMinuteWithMode(tx, m, rebuildAll); err != nil {
					tx.Rollback()
					return err
				}
			}
			if err := saveCoverage(tx, coveredFrom, end); err != nil {
				tx.Rollback()
				return err
			}
			if err := tx.Commit(); err != nil {
				return err
			}
			if err := yield(); err != nil {
				return err
			}
			lastFixed = end
			start = end.Add(time.Minute)
		}
	}
	// 3) 最新段：lastComplete（迟到写入终固，历史问题）+ currentMinute（实时
	// 口径）——每轮恒固化，首屏 recent_rate 不依赖回填进度。
	{
		tx, err := database.Begin()
		if err != nil {
			return err
		}
		repairStart := lastComplete.Add(-time.Duration(threatRollupRepairMinutes-1) * time.Minute)
		if repairStart.Before(dFrom) {
			repairStart = dFrom
		}
		for m := repairStart; !m.After(lastComplete); m = m.Add(time.Minute) {
			if err := threatFixMinuteWithMode(tx, m, rebuildAll); err != nil {
				tx.Rollback()
				return err
			}
		}
		if !currentMinute.Equal(lastComplete) {
			if err := threatFixMinuteWithMode(tx, currentMinute, rebuildAll); err != nil {
				tx.Rollback()
				return err
			}
		}
		// 历史问题：目标维度就绪标记与最新段同事务提交——任何成功固化后
		// 目标计数（至少最新两分钟）必然存在，后续轮次按正常 coverage 续做。
		if _, err := tx.Exec(`INSERT INTO metrics_state (key, value) VALUES (?, ?) ON CONFLICT(key) DO UPDATE SET value=excluded.value`,
			threatRollupTargetReadyKey, now.Format("2006-01-02 15:04")); err != nil {
			tx.Rollback()
			return err
		}
		// 历史问题：记录本轮使用的归属地库代际（下次代际变化触发重固）。
		if _, err := tx.Exec(`INSERT INTO metrics_state (key, value) VALUES (?, ?) ON CONFLICT(key) DO UPDATE SET value=excluded.value`,
			threatRollupGeoIPGenerationKey, geoipGen); err != nil {
			tx.Rollback()
			return err
		}
		if err := tx.Commit(); err != nil {
			return err
		}
	}
	markThreatRollupSuccess()
	return nil
}

// threatRollupWarmerStarted 后台固化协程启动标志（原子）。启动后大屏请求
// 路径不再懒固化（避免与 warmer 抢写锁/重复回填）；未启动（测试/旧路径）
// 保持请求路径懒固化。
var threatRollupWarmerStarted atomic.Bool

// threatRollupWarmerWg warmer 协程退出等待（关停/测试换库前先行等待，
// 避免固化中途句柄被关闭）。
var threatRollupWarmerWg sync.WaitGroup

// threatRollupReadyAt 最近一次成功固化的 UnixNano（0=从未成功，历史
// 历史问题）：请求路径据此区分「warmer 已启动」与「已有可用覆盖」。
// threatRollupReadyDB 记录该成功状态所属的指标库句柄——换库（测试/重启装配）
// 后旧就绪状态对新库无效，避免把上一库的覆盖误当当前库的。
var (
	threatRollupReadyAt atomic.Int64
	threatRollupReadyDB atomic.Pointer[sql.DB]
)

// threatRollupRequestedHours 最近请求过的最大窗口（小时）：宽窗口请求把
// 需求告知 warmer，后台每轮按 max(24, 需求) 扩窗回填（历史 历史问题）。
var threatRollupRequestedHours atomic.Int64

// markThreatRollupSuccess 记录一次成功固化（任何路径：warmer / 请求懒固化）。
func markThreatRollupSuccess() {
	if cur := db.MetricsDB; cur != nil {
		threatRollupReadyDB.Store(cur)
	}
	threatRollupReadyAt.Store(time.Now().UnixNano())
}

// threatRollupUsable 当前指标库是否已有一次成功固化（就绪判定，历史问题）。
func threatRollupUsable() bool {
	if threatRollupReadyAt.Load() == 0 {
		return false
	}
	cur := db.MetricsDB
	return cur != nil && threatRollupReadyDB.Load() == cur
}

// threatRollupStale 最近成功固化是否已超过陈旧阈值（历史问题）。
func threatRollupStale() bool {
	if !threatRollupUsable() {
		return true
	}
	return time.Since(time.Unix(0, threatRollupReadyAt.Load())) > threatRollupStaleAfter
}

// threatRollupCoverageReaches 持久 coverage 是否已覆盖请求窗口起点（宽窗口
// 请求决定是否需在请求路径补做旧侧分钟，历史问题）。读取失败按「未覆盖」
// 处理（宁可多做一次幂等回填）。
func threatRollupCoverageReaches(hours int) bool {
	database := db.MetricsDB
	if database == nil {
		return true
	}
	horizon := threatScreenNow().UTC().Add(-time.Minute).Truncate(time.Minute).Add(-time.Duration(hours) * time.Hour)
	coveredFrom, ok, err := loadThreatRollupState(database, threatRollupCoveredFromKey)
	if err != nil || !ok {
		return false
	}
	return !coveredFrom.After(horizon)
}

// StartThreatRollupWarmer 启动 rollup 后台固化协程（幂等：CAS 标志，重复
// 调用为空操作）：启动时立即 ensureThreatRollup(24)，之后每 60s 一轮；
// ctx 取消即退出。单轮失败仅告警，下一轮自愈（固化本身幂等）。
func StartThreatRollupWarmer(ctx context.Context) {
	if !threatRollupWarmerStarted.CompareAndSwap(false, true) {
		return
	}
	threatRollupWarmerWg.Add(1)
	go func() {
		defer threatRollupWarmerWg.Done()
		run := func() {
			hours := 24
			if req := int(threatRollupRequestedHours.Load()); req > hours {
				hours = req
			}
			if hours > threatScreenMaxHours {
				hours = threatScreenMaxHours
			}
			if err := ensureThreatRollup(hours); err != nil {
				services.Logf("warn", "threat rollup warmer: %v", err)
			}
		}
		select {
		case <-ctx.Done():
			return
		default:
		}
		run() // 启动即固化（首屏不等待首个 tick）
		ticker := time.NewTicker(time.Minute)
		defer ticker.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				run()
			}
		}
	}()
}

// resetThreatRollupWarmerForTest 测试缝：复位 warmer 启动标志（生产不调用）。
func resetThreatRollupWarmerForTest() {
	threatRollupWarmerStarted.Store(false)
	threatRollupReadyAt.Store(0)
	threatRollupReadyDB.Store(nil)
	threatRollupRequestedHours.Store(0)
}

// queryThreatRecentBlocked 近 5 分钟 blocked 计数（大屏 recent_rate 数据源）。
// 测试注入缝：历史问题 需要只让最后一条 SUM 失败，验证 500 不被 200 吞掉。
var queryThreatRecentBlocked = func(sinceMinute string) (int, error) {
	var blocked int
	err := db.MetricsDB.QueryRow(`SELECT COALESCE(SUM(count),0) FROM security_event_rollup WHERE minute >= ? AND action='blocked'`, sinceMinute).Scan(&blocked)
	return blocked, err
}

const threatRollupEventHighwaterPrefix = "threat_rollup_max_event_id:"

func loadThreatRollupEventHighwater(tx *sql.Tx, minute string) (int64, error) {
	var raw string
	err := tx.QueryRow(`SELECT value FROM metrics_state WHERE key=?`, threatRollupEventHighwaterPrefix+minute).Scan(&raw)
	if errors.Is(err, sql.ErrNoRows) {
		return 0, nil
	}
	if err != nil {
		return 0, err
	}
	id, perr := strconv.ParseInt(strings.TrimSpace(raw), 10, 64)
	if perr != nil || id < 0 {
		services.Logf("warn", "threat rollup: corrupted event highwater for minute %s (%q), treating as unset", minute, raw)
		return 0, nil
	}
	return id, nil
}

func saveThreatRollupEventHighwater(tx *sql.Tx, minute string, id int64) error {
	_, err := tx.Exec(`INSERT INTO metrics_state (key, value) VALUES (?, ?) ON CONFLICT(key) DO UPDATE SET value=excluded.value`,
		threatRollupEventHighwaterPrefix+minute, strconv.FormatInt(id, 10))
	return err
}

// threatFixMinute 单分钟固化（增量模式）：首次/旧状态按全量重建，已有事件
// 高水位后只叠加 id 更大的迟到事件——原始行被裁剪后不会把已固化计数覆盖掉。
func threatFixMinute(tx *sql.Tx, m time.Time) error {
	return threatFixMinuteWithMode(tx, m, false)
}

func threatFixMinuteWithMode(tx *sql.Tx, m time.Time, fullRebuild bool) error {
	next := m.Add(time.Minute)
	minuteStr := m.Format("2006-01-02 15:04")
	previousMaxID, err := loadThreatRollupEventHighwater(tx, minuteStr)
	if err != nil {
		return err
	}
	var currentMaxID int64
	if err := tx.QueryRow(`SELECT COALESCE(MAX(id),0) FROM security_events WHERE event_time >= ? AND event_time < ?`,
		m.Format("2006-01-02 15:04:05"), next.Format("2006-01-02 15:04:05")).Scan(&currentMaxID); err != nil {
		return err
	}
	type key struct{ country, province, family, rule, action string }
	agg := map[key]int{}
	targetAgg := map[string]int{}
	incremental := !fullRebuild && previousMaxID > 0
	if incremental {
		oldRows, err := tx.Query(`SELECT country, province, family, rule, action, count FROM security_event_rollup WHERE minute=?`, minuteStr)
		if err != nil {
			return err
		}
		for oldRows.Next() {
			var k key
			var count int
			if err := oldRows.Scan(&k.country, &k.province, &k.family, &k.rule, &k.action, &count); err != nil {
				oldRows.Close()
				return err
			}
			agg[k] = count
		}
		if err := oldRows.Err(); err != nil {
			oldRows.Close()
			return err
		}
		oldRows.Close()
		targetRows, err := tx.Query(`SELECT rule_caddy_id, count FROM security_event_target_rollup WHERE minute=?`, minuteStr)
		if err != nil {
			return err
		}
		for targetRows.Next() {
			var ruleID string
			var count int
			if err := targetRows.Scan(&ruleID, &count); err != nil {
				targetRows.Close()
				return err
			}
			targetAgg[ruleID] = count
		}
		if err := targetRows.Err(); err != nil {
			targetRows.Close()
			return err
		}
		targetRows.Close()
	}

	rawQuery := `SELECT client_ip, COALESCE(NULLIF(rule_name,''), COALESCE(rule_triggered,'')), COALESCE(rule_triggered,''), COALESCE(rule_msg,''), action, COALESCE(rule_caddy_id,''), COUNT(*)
		FROM security_events
		WHERE event_time >= ? AND event_time < ?`
	args := []any{m.Format("2006-01-02 15:04:05"), next.Format("2006-01-02 15:04:05")}
	if incremental {
		rawQuery += ` AND id > ?`
		args = append(args, previousMaxID)
	}
	rawQuery += `
		GROUP BY client_ip, COALESCE(NULLIF(rule_name,''), COALESCE(rule_triggered,'')), COALESCE(rule_triggered,''), COALESCE(rule_msg,''), action, COALESCE(rule_caddy_id,'')`
	rows, err := tx.Query(rawQuery, args...)
	if err != nil {
		return err
	}
	deltaTotal := 0
	for rows.Next() {
		var ip, ruleName, ruleTriggered, ruleMsg, action, ruleCaddyID string
		var count int
		if err := rows.Scan(&ip, &ruleName, &ruleTriggered, &ruleMsg, &action, &ruleCaddyID, &count); err != nil {
			rows.Close()
			return err
		}
		if isReservedIP(ip) {
			continue
		}
		country, province := threatLocationParts(enrichIPLocation(ip))
		k := key{country, province, categorizeAttack(ruleTriggered, ruleMsg), ruleName, action}
		agg[k] += count
		deltaTotal += count
		if ruleCaddyID != "" {
			targetAgg[ruleCaddyID] += count
		}
	}
	if err := rows.Err(); err != nil {
		rows.Close()
		return err
	}
	rows.Close()
	highwater := currentMaxID
	if previousMaxID > highwater {
		highwater = previousMaxID
	}
	if incremental {
		if deltaTotal == 0 {
			return saveThreatRollupEventHighwater(tx, minuteStr, highwater)
		}
	} else {
		newTotal := 0
		for _, count := range agg {
			newTotal += count
		}
		var oldTotal int
		if err := tx.QueryRow(`SELECT COALESCE(SUM(count),0) FROM security_event_rollup WHERE minute=?`, minuteStr).Scan(&oldTotal); err != nil {
			return err
		}
		if newTotal < oldTotal {
			// 原始事件已被裁剪且无高水位可做增量：保留两张 rollup 原行，
			// 但记录当前最大 id，下一次迟到事件起走增量叠加。
			return saveThreatRollupEventHighwater(tx, minuteStr, highwater)
		}
		if newTotal == 0 && oldTotal == 0 {
			return saveThreatRollupEventHighwater(tx, minuteStr, highwater)
		}
	}
	if _, err := tx.Exec(`DELETE FROM security_event_rollup WHERE minute = ?`, minuteStr); err != nil {
		return err
	}
	// 历史 历史问题：目标维度同批重固（rollup 主键无法承载 rule_caddy_id）。
	if _, err := tx.Exec(`DELETE FROM security_event_target_rollup WHERE minute = ?`, minuteStr); err != nil {
		return err
	}
	stmt, err := tx.Prepare(`INSERT INTO security_event_rollup (minute, country, province, family, rule, action, count) VALUES (?, ?, ?, ?, ?, ?, ?)`)
	if err != nil {
		return err
	}
	for k, count := range agg {
		if _, err := stmt.Exec(minuteStr, k.country, k.province, k.family, k.rule, k.action, count); err != nil {
			stmt.Close()
			return err
		}
	}
	if err := stmt.Close(); err != nil {
		return err
	}
	tstmt, err := tx.Prepare(`INSERT INTO security_event_target_rollup (minute, rule_caddy_id, count) VALUES (?, ?, ?)`)
	if err != nil {
		return err
	}
	for id, count := range targetAgg {
		if _, err := tstmt.Exec(minuteStr, id, count); err != nil {
			tstmt.Close()
			return err
		}
	}
	if err := tstmt.Close(); err != nil {
		return err
	}
	return saveThreatRollupEventHighwater(tx, minuteStr, highwater)
}

// threatLocationParts 归属地字符串 → (国家, 省简称)；中国省供省级聚合。
func threatLocationParts(location string) (string, string) {
	parts := strings.SplitN(location, "·", 3)
	country := ""
	province := ""
	if len(parts) > 0 {
		country = strings.TrimSpace(parts[0])
	}
	if country == "保留地址" {
		return "", ""
	}
	if country == "中国" && len(parts) > 1 {
		province = strings.TrimSpace(parts[1])
	}
	return country, province
}

// trafficCountry/trafficSnapshot Caddy admin /lb/traffic-stats 响应形状
// （caddygeoip per-country 原子计数器，attack/normal 双桶累计）。
type trafficCountry struct {
	Attack uint64 `json:"attack"`
	Normal uint64 `json:"normal"`
}

type trafficSnapshot struct {
	Countries map[string]trafficCountry `json:"countries"`
	SampleN   uint32                    `json:"sample_n"`
}

// threatTrafficEmptyDegrade admin 不可达/抓取失败时的降级响应（200 空数据，
// available=false）——大屏 1-2s 轮询容忍瞬时不可达，不 500。
func threatTrafficEmptyDegrade() gin.H {
	return gin.H{"countries": map[string]trafficCountry{}, "available": false, "sample_n": 1}
}

// ControlThreatScreenCollector POST/DELETE /security/overview/threat-screen/collector
// 代理 Caddy admin 的流量采集租约：大屏打开时申请/续租，关闭时释放；
// 插件在无租约时跳过所有流量采集热路径（安全日志不受影响）。
func (h *Handlers) ControlThreatScreenCollector(c *gin.Context) {
	body, err := io.ReadAll(io.LimitReader(c.Request.Body, 4096))
	if err != nil {
		c.JSON(http.StatusBadRequest, models.APIResponse{Code: 400, Message: "请求体读取失败"})
		return
	}
	target := strings.TrimRight(h.cfg.CaddyAdminURL, "/") + "/lb/traffic-collector"
	req, err := http.NewRequestWithContext(c.Request.Context(), c.Request.Method, target, bytes.NewReader(body))
	if err != nil {
		c.JSON(http.StatusInternalServerError, models.APIResponse{Code: 500, Message: "采集控制请求构造失败"})
		return
	}
	req.Header.Set("Content-Type", "application/json")
	client := &http.Client{Timeout: 2 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		services.Logf("warn", "threat-screen collector: admin request failed: %v", err)
		c.JSON(http.StatusServiceUnavailable, models.APIResponse{Code: 503, Message: "流量采集控制不可达"})
		return
	}
	defer resp.Body.Close()
	respBody, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
	c.Data(resp.StatusCode, "application/json", respBody)
}

// GetThreatScreenFlowEvents GET /security/overview/threat-screen/events
// 代理 Caddy admin 逐请求正常流量环形缓冲；since_seq 增量拉取，仅大屏打开时
// 前端轮询。响应透传 enabled/sample_n/events/next_seq。
func (h *Handlers) GetThreatScreenFlowEvents(c *gin.Context) {
	target := strings.TrimRight(h.cfg.CaddyAdminURL, "/") + "/lb/traffic-events"
	if raw := c.Request.URL.RawQuery; raw != "" {
		target += "?" + raw
	}
	req, err := http.NewRequestWithContext(c.Request.Context(), http.MethodGet, target, nil)
	if err != nil {
		c.JSON(http.StatusInternalServerError, models.APIResponse{Code: 500, Message: "事件流请求构造失败"})
		return
	}
	client := &http.Client{Timeout: 2 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		services.Logf("warn", "threat-screen events: admin request failed: %v", err)
		c.JSON(http.StatusServiceUnavailable, models.APIResponse{Code: 503, Message: "逐请求事件流不可达"})
		return
	}
	defer resp.Body.Close()
	// A81A-历史问题：对齐同族读端点（GetCRSRuleContent/GetCRSSetupConfig 的 413 口径）
	// ——超限显式拒绝而非把截断的 JSON 以 200 透传（调用方会把残缺事件流当
	// 完整增量消费）。
	body, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20+1))
	if err != nil {
		services.Logf("warn", "threat-screen events: read body failed: %v", err)
		c.JSON(http.StatusServiceUnavailable, models.APIResponse{Code: 503, Message: "逐请求事件流不可达"})
		return
	}
	if len(body) > 1<<20 {
		c.JSON(http.StatusRequestEntityTooLarge, models.APIResponse{Code: 413, Message: "逐请求事件流响应超过 1MB 读取上限"})
		return
	}
	c.Data(resp.StatusCode, "application/json", body)
}

// GetThreatScreenTraffic GET /security/overview/threat-screen/traffic
// 大屏实时流量代理（Plan B）：读 Caddy admin 自定义端点 /lb/traffic-stats，
// 国名翻译中文（geoipnames 单源）+ Reserved/空/0 键过滤。1s TTL + singleflight
// 进程内缓存（key=admin URL，大屏 1-2s 轮询不对 admin 放大请求；失败不缓存）。
func (h *Handlers) GetThreatScreenTraffic(c *gin.Context) {
	data, ok := threatTrafficSnapshot(strings.TrimRight(h.cfg.CaddyAdminURL, "/"))
	if !ok {
		c.JSON(http.StatusOK, models.APIResponse{Code: 0, Data: threatTrafficEmptyDegrade()})
		return
	}
	c.JSON(http.StatusOK, models.APIResponse{Code: 0, Data: data})
}

// fetchThreatTrafficSnapshot 抓取并翻译一次流量快照；任何失败（不可达/非
// 200/解码失败）ok=false 并告警——超时 2s，不阻塞大屏轮询协程。
func fetchThreatTrafficSnapshot(adminURL string) (gin.H, bool) {
	client := &http.Client{Timeout: 2 * time.Second}
	resp, err := client.Get(adminURL + "/lb/traffic-stats")
	if err != nil {
		services.Logf("warn", "threat-screen traffic: admin fetch failed: %v", err)
		return nil, false
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		services.Logf("warn", "threat-screen traffic: admin status %d", resp.StatusCode)
		return nil, false
	}
	var snap trafficSnapshot
	if err := json.NewDecoder(io.LimitReader(resp.Body, 1<<20)).Decode(&snap); err != nil {
		services.Logf("warn", "threat-screen traffic: decode failed: %v", err)
		return nil, false
	}
	out := make(map[string]trafficCountry, len(snap.Countries))
	for country, entry := range snap.Countries {
		if country == "" || country == "Reserved" || country == "0" {
			continue
		}
		name := geoipnames.CountryChinese(country)
		if name == country && country != "中国" {
			// 未收录英文名原样保留（前端质心表 miss 走兜底位）
			name = country
		}
		out[name] = entry
	}
	return gin.H{
		"countries": out,
		"available": true,
		"sample_n":  snap.SampleN,
	}, true
}

// DetectThreatScreenSite POST /security/overview/threat-screen/site-detect
// 大屏本站坐标自动检测：公网 IP → 本地归属地 → 经纬度。定位失败 422 并指引
// 手动填写（保留既有写侧校验路径）；出站失败 502 友好文案。
func (h *Handlers) DetectThreatScreenSite(c *gin.Context) {
	ip, source, err := fetchPublicIP()
	if err != nil {
		services.Logf("warn", "threat-screen site detect: fetch public ip failed: %v", err)
		recordAudit(c, "检测失败", "大屏坐标", services.FormatAuditDetail("公网 IP 获取失败", services.AuditResultPart("failure")))
		c.JSON(http.StatusBadGateway, models.APIResponse{Code: 502, Message: "公网 IP 获取失败（离线或超时），请检查网络后重试"})
		return
	}
	lat, lon, location, ok := locateSiteCoords(ip)
	if !ok {
		services.Logf("warn", "threat-screen site detect: ip %s (via %s) location unresolvable", ip, source)
		recordAudit(c, "检测失败", "大屏坐标", services.FormatAuditDetail("归属地无法定位: "+ip+"（源 "+source+"）", services.AuditResultPart("failure")))
		c.JSON(http.StatusUnprocessableEntity, models.APIResponse{Code: 422, Message: "归属地无法定位（GeoIP 库缺失或网段未知），请手动填写坐标"})
		return
	}
	recordAudit(c, "自动检测", "大屏坐标", services.FormatAuditDetail(location+" ("+ip+"，源 "+source+")"))
	// APIResponse 包装（全站契约）：前端 request 封装按 data 字段取值，
	// 裸 JSON 会被消费方判「响应缺失」误走失败分支（v5 实测修复）。
	c.JSON(http.StatusOK, models.APIResponse{Code: 0, Data: gin.H{"ip": ip, "location": location, "lat": lat, "lon": lon, "source": source}})
}

// threatHourlyBuckets 生成威胁大屏滑动直方图槽（小时或日桶）；返回桶起点
// （用于落桶）与已零填充的槽。hours<=24 为本地小时槽，否则日桶（上限 30）。
func threatHourlyBuckets(hours int, now time.Time, offset int) ([]time.Time, []models.SecurityAttackType) {
	shift := time.Duration(offset) * time.Second
	shiftedNow := now.UTC().Add(shift)
	var bucketStarts []time.Time
	var bucketNames []string
	if hours <= 24 {
		curHour := shiftedNow.Truncate(time.Hour)
		start := curHour.Add(-time.Duration(hours-1) * time.Hour)
		for i := range hours {
			tb := start.Add(time.Duration(i) * time.Hour)
			bucketStarts = append(bucketStarts, tb)
			bucketNames = append(bucketNames, fmt.Sprintf("%02d:00", tb.Hour()))
		}
	} else {
		n := (hours + 23) / 24
		if n > 30 {
			n = 30
		}
		dayStart := time.Date(shiftedNow.Year(), shiftedNow.Month(), shiftedNow.Day(), 0, 0, 0, 0, time.UTC)
		start := dayStart.AddDate(0, 0, -(n - 1))
		for i := range n {
			tb := start.AddDate(0, 0, i)
			bucketStarts = append(bucketStarts, tb)
			bucketNames = append(bucketNames, tb.Format("01-02"))
		}
	}
	hourly := make([]models.SecurityAttackType, len(bucketNames))
	for i := range hourly {
		hourly[i] = models.SecurityAttackType{Name: bucketNames[i], Value: 0}
	}
	return bucketStarts, hourly
}

// GetSecurityThreatScreen GET /security/overview/threat-screen?hours=24
// 返回大屏聚合：窗口总量/拦截率/logged 数/限流拦截数（Caddy metrics 429，
// 重载口径）/活跃攻击源（近 10min 去重）/国家计数 map（ip_location 首段，
// 空归属跳过）/Top5 攻击国家、攻击类型与被攻击目标（top_targets，
// rule_caddy_id 分组 + lb_rules 名域）。任一安全库查询失败显式 500
// （历史问题 D2：全零大屏与「无攻击」不可区分）；Caddy metrics 抓取失败降级
// 200——ratelimit_blocks=0 + ratelimit_available=false，其余维度照常
// （大屏 30s 轮询容忍指标瞬时不可达，可用性位披露）。
func (h *Handlers) GetSecurityThreatScreen(c *gin.Context) {
	hours := 24
	if raw := c.Query("hours"); raw != "" {
		if n, err := strconv.Atoi(raw); err == nil && n >= 1 && n <= threatScreenMaxHours {
			hours = n
		}
	}
	now := threatScreenNow()
	loc := services.CurrentLocation()
	_, offset := now.In(loc).Zone()
	zero := func() gin.H {
		_, hourly := threatHourlyBuckets(hours, now, offset)
		return gin.H{
			"hours":                hours,
			"window_start":         "",
			"rollup_ready":         false,
			"rollup_stale":         threatRollupStale(),
			"rollup_last_success":  "",
			"rollup_coverage_from": "",
			"backfill_incomplete":  false,
			"total_events":         0,
			"blocked_events":       0,
			"logged_events":        0,
			"block_rate":           0.0,
			"ratelimit_blocks":     0.0,
			"ratelimit_available":  false,
			"active_sources":       0,
			"countries":            map[string]int{},
			"china_provinces":      map[string]int{},
			"top_countries":        []models.SecurityAttackType{},
			"top_attack_types":     []models.SecurityAttackType{},
			"top_rules":            []models.SecurityAttackType{},
			"top_targets":          []models.SecurityAttackType{},
			"hourly_hist":          hourly,
			"attack_type_share":    []models.SecurityAttackType{},
			"recent_rate":          0.0,
		}
	}
	if db.MetricsDB == nil {
		// MetricsDB 未装配：零值面板 200 而非 panic（历史问题 家族口径）
		c.JSON(http.StatusOK, models.APIResponse{Code: 0, Data: zero()})
		return
	}

	since := now.UTC().Add(-time.Duration(hours) * time.Hour).Truncate(time.Second).Format("2006-01-02 15:04:05")
	activeSince := now.UTC().Add(-threatActiveSourceWindow).Truncate(time.Second).Format("2006-01-02 15:04:05")

	// 任一查询失败显式报错（历史问题 D2 单错误收敛，trackErr 同 GetSecurityOverview）
	var firstErr error
	trackErr := func(err error) {
		if err != nil && firstErr == nil {
			firstErr = err
		}
	}

	// v2.3.8 rollup 路径：懒固化后单次扫描 rollup 产出全部维度（总量/拦截/
	// 国家/省/攻击族/规则/小时——原 5 条原始表窗口扫描合并为 1 条 rollup 扫
	// 描，与原始表规模解耦）。保留/私网已在固化时排除（口径不变）。
	// warmer 已启动时由后台协程承担固化（每 60s 一轮），请求路径不再常规懒
	// 固化（避免与用户请求抢写锁/重复回填）。历史 历史问题/F02 修正：
	//   - 首轮未完成或最近成功固化已陈旧（warmer 持续失败）→ 请求路径同步
	//     固化，不得把「已启动」当作「已有可用覆盖」；
	//   - 宽窗口（>24h）尚未覆盖到窗口起点 → 按持久 coverage 在请求路径补做
	//     旧侧分钟（单次有界批，后续轮询/ warmer 续做），7d 窗口不依赖恒
	//     24h 的 warmer。
	if hours > 24 {
		for cur := threatRollupRequestedHours.Load(); int64(hours) > cur; cur = threatRollupRequestedHours.Load() {
			if threatRollupRequestedHours.CompareAndSwap(cur, int64(hours)) {
				break
			}
		}
	}
	needsSync := !threatRollupWarmerStarted.Load() || threatRollupStale() ||
		(hours > 24 && !threatRollupCoverageReaches(hours))
	if needsSync {
		if err := ensureThreatRollup(hours); err != nil {
			trackErr(err)
		}
	}
	// 历史问题-10：宽窗口首轮只回填有界批数（threatRollupMaxBatchesPerCall），
	// rollup_ready 仅代表「有过成功固化」——窗口头部未被覆盖时必须披露部分
	// 聚合，避免把少计的总量当作完整窗口返回。
	coverageFrom := ""
	backfillIncomplete := false
	windowStartMinute := now.UTC().Add(-time.Duration(hours) * time.Hour).Truncate(time.Minute)
	if coveredFrom, okCovered, cerr := loadThreatRollupState(db.MetricsDB, threatRollupCoveredFromKey); cerr != nil {
		trackErr(cerr)
	} else if okCovered {
		coverageFrom = coveredFrom.Format("2006-01-02 15:04")
		if coveredFrom.After(windowStartMinute) {
			backfillIncomplete = true
		}
	} else {
		backfillIncomplete = true
	}
	var total, blocked int
	countries := map[string]int{}
	chinaProvinces := map[string]int{}
	familyCounts := map[string]int{}
	ruleCounts := map[string]int{}
	sinceMinute := now.UTC().Add(-time.Duration(hours) * time.Hour).Truncate(time.Minute).Format("2006-01-02 15:04")
	bucketStarts, hourly := threatHourlyBuckets(hours, now, offset)
	bucketStep := time.Hour
	if hours > 24 {
		bucketStep = 24 * time.Hour
	}
	shift := time.Duration(offset) * time.Second
	if rollRows, err := db.MetricsDB.Query(`SELECT minute, country, province, family, rule, action, count FROM security_event_rollup WHERE minute >= ?`, sinceMinute); err != nil {
		trackErr(err)
	} else {
		for rollRows.Next() {
			var minute, country, province, family, rule, action string
			var count int
			trackErr(rollRows.Scan(&minute, &country, &province, &family, &rule, &action, &count))
			total += count
			if action == "blocked" {
				blocked += count
			}
			if country != "" {
				countries[country] += count
			}
			if province != "" {
				chinaProvinces[province] += count
			}
			familyCounts[family] += count
			if rule != "" {
				ruleCounts[rule] += count
			}
			// 滑动窗口落桶：rollup 分钟串为 UTC，加配置时区偏移后按桶起点/步长定位
			mt, err := time.ParseInLocation("2006-01-02 15:04", minute, time.UTC)
			if err == nil && len(bucketStarts) > 0 {
				idx := int(mt.Add(shift).Sub(bucketStarts[0]) / bucketStep)
				if idx < 0 {
					idx = 0
				}
				if idx < len(hourly) {
					hourly[idx].Value += count
				}
			}
		}
		trackErr(rollRows.Err())
		rollRows.Close()
	}
	// 活跃攻击源：近 10min 去重 client_ip，保留/私网排除（与总量同口径）
	activeSources := 0
	if activeRows, err := db.MetricsDB.Query(`SELECT client_ip FROM security_events WHERE event_time >= ? GROUP BY client_ip`, activeSince); err != nil {
		trackErr(err)
	} else {
		for activeRows.Next() {
			var ip string
			trackErr(activeRows.Scan(&ip))
			if !isReservedIP(ip) {
				activeSources++
			}
		}
		trackErr(activeRows.Err())
		activeRows.Close()
	}
	// top_targets：前 5 被攻击目标（历史 历史问题：读分钟 rollup 的目标
	// 维度，与 total/国家同窗口；原始表受保留期/行帽裁剪，不能作为旁路）
	topTargets, terr := threatTopTargets(sinceMinute, hours)
	trackErr(terr)
	if firstErr != nil {
		services.Logf("error", "threat-screen query failed: %v", firstErr)
		c.JSON(http.StatusInternalServerError, models.APIResponse{Code: 500, Message: "威胁大屏数据查询失败"})
		return
	}

	// 限流拦截：Caddy /metrics 429 总计（与 GetSecurityRateLimitBlocks 同源）。
	// 抓取失败不再整卡 500——ratelimit_blocks=0 + ratelimit_available=false
	// 降级，其余维度照常 200（大屏轮询容忍指标瞬时不可达，可用性位披露）。
	blocks, err := services.ScrapeRateLimitBlocks(h.cfg.CaddyMetricsURL)
	ratelimitAvailable := true
	var ratelimit float64
	if err != nil {
		services.Logf("warn", "threat-screen scrape rate-limit blocks failed: %v", err)
		ratelimitAvailable = false
	} else {
		for _, block := range blocks {
			ratelimit += block.Count
		}
	}

	blockRate := 0.0
	if total > 0 {
		blockRate = float64(blocked) / float64(total) * 100
		// 一位小数（百分比展示口径）
		blockRate = float64(int(blockRate*10+0.5)) / 10
	}
	// recent_rate：近 5 分钟 blocked/min（rollup 单前缀扫描；logged 不计）
	since5Minute := threatScreenNow().UTC().Add(-5 * time.Minute).Truncate(time.Minute).Format("2006-01-02 15:04")
	blocked5, rerr := queryThreatRecentBlocked(since5Minute)
	trackErr(rerr)
	// 历史问题：计算/响应前的最终错误检查——旧实现只在 rollup/active 扫描后
	// 检查一次，recent_rate 的 SUM 失败会被 200 响应吞掉（部分维度静默为 0）。
	// 产品语义保持整卡 500：不引入「部分卡片降级」的隐式可用性位。
	if firstErr != nil {
		services.Logf("error", "threat-screen query failed: %v", firstErr)
		c.JSON(http.StatusInternalServerError, models.APIResponse{Code: 500, Message: "威胁大屏数据查询失败"})
		return
	}
	recentRate := float64(int(float64(blocked5)/5.0*10+0.5)) / 10

	// logged_events = total - blocked（夹 >=0：口径防御，rollup 异常不输出负数）
	logged := total - blocked
	if logged < 0 {
		logged = 0
	}

	// 窗口起点（秒级，供前端展示）；rollup 就绪/陈旧度披露（历史问题）。
	rollupReady := threatRollupUsable()
	rollupLastSuccess := ""
	if rollupReady {
		rollupLastSuccess = time.Unix(0, threatRollupReadyAt.Load()).UTC().Format("2006-01-02 15:04:05")
	}

	c.JSON(http.StatusOK, models.APIResponse{Code: 0, Data: gin.H{
		"hours":               hours,
		"window_start":        since,
		"rollup_ready":        rollupReady,
		"rollup_stale":        threatRollupStale(),
		"rollup_last_success": rollupLastSuccess,
		// 历史问题-10：窗口头部覆盖披露——rollup_coverage_from 为已覆盖的最旧
		// 分钟；backfill_incomplete=true 表示本次响应的 total/各维度只覆盖
		// [rollup_coverage_from, now]，宽窗口回填仍在进行（后续轮询补齐）。
		"rollup_coverage_from": coverageFrom,
		"backfill_incomplete":  backfillIncomplete,
		"total_events":         total,
		"blocked_events":       blocked,
		"logged_events":        logged,
		"block_rate":           blockRate,
		"ratelimit_blocks":     ratelimit,
		"ratelimit_available":  ratelimitAvailable,
		"active_sources":       activeSources,
		"countries":            countries,
		"china_provinces":      chinaProvinces,
		"top_countries":        topThreatEntries(countries, 5),
		"top_attack_types":     topThreatEntries(familyCounts, 5),
		"top_rules":            topThreatEntries(ruleCounts, 6),
		"top_targets":          topTargets,
		"hourly_hist":          hourly,
		"attack_type_share":    topThreatEntries(familyCounts, len(familyCounts)),
		"recent_rate":          recentRate,
	}})
}

// GetSecurityEventFeed GET /security/events/feed?since_id=N&limit=50
// 大屏增量事件流（升序无漏语义），含归属地/攻击族富化（enrichIPLocation +
// categorizeAttack 单源）。limit 缺省 50、上限 200。
//   - since_id=0（首屏）：返回**最新** limit 条（降序扫描收集、响应按 id
//     升序输出），next_since_id=返回集最大 id，has_more=false（首屏不回溯
//     更老）；
//   - since_id>0（增量）：WHERE id > cursor ORDER BY id ASC 逐页扫描直至
//     凑满 limit 或到顶——>limit 积压分多次拉取无重无漏；has_more=本页
//     填满且可能还有更新未返回；
//   - 保留/私网 IP 过滤但游标照常推进（next_since_id=本批实际扫描到的
//     最大 id，含被过滤行）；单请求最多 20 页有界扫描。
func (h *Handlers) GetSecurityEventFeed(c *gin.Context) {
	const (
		defaultLimit = 50
		maxLimit     = 200
	)
	sinceID := int64(0)
	if raw := c.Query("since_id"); raw != "" {
		if n, err := strconv.ParseInt(raw, 10, 64); err == nil && n > 0 {
			sinceID = n
		}
	}
	limit := defaultLimit
	if raw := c.Query("limit"); raw != "" {
		if n, err := strconv.Atoi(raw); err == nil && n >= 1 {
			limit = n
		}
	}
	if limit > maxLimit {
		limit = maxLimit
	}
	empty := func() gin.H {
		return gin.H{"events": []models.SecurityEventFeedItem{}, "since_id": sinceID, "next_since_id": sinceID, "limit": limit, "has_more": false}
	}
	if db.MetricsDB == nil {
		// MetricsDB 未装配：空列表 200 而非 panic（历史问题 家族口径，键与成功路径同形状）
		c.JSON(http.StatusOK, models.APIResponse{Code: 0, Data: empty()})
		return
	}
	// 历史问题：游标高水位——next_since_id = 本批**实际扫描到的最大 id**
	//（含被保留地址过滤掉的行），分页循环扫描直至凑满 limit 或到顶。
	events := make([]models.SecurityEventFeedItem, 0, limit)
	nextSinceID := sinceID
	const maxScanPages = 20 // 有界扫描：洪峰下不让单请求无限翻页

	scanFailed := false
	// scanPage 执行一页查询：扫描/富化/保留地址过滤，追加到 events 并推进
	// nextSinceID；返回 (本页扫描行数, 本页末行 id)。任何失败置 scanFailed。
	scanPage := func(query string, args ...any) (int, int64) {
		rows, err := db.MetricsDB.Query(query, args...)
		if err != nil {
			services.Logf("error", "security event feed: query failed: %v", err)
			scanFailed = true
			return 0, 0
		}
		defer rows.Close()
		scanned := 0
		lastID := int64(0)
		for rows.Next() {
			scanned++
			var e models.SecurityEventFeedItem
			var ruleTriggered, ruleMsg string
			// Scan 失败必须中止（历史问题 D3：部分零值行不得当真实事件返回）
			if err := rows.Scan(&e.ID, &e.EventTime, &e.ClientIP, &e.Action, &e.RuleName, &ruleTriggered, &ruleMsg, &e.EventType, &e.DurationUs, &e.AnomalyScore); err != nil {
				services.Logf("error", "security event feed: scan failed: %v", err)
				scanFailed = true
				return scanned, lastID
			}
			lastID = int64(e.ID)
			if int64(e.ID) > nextSinceID {
				nextSinceID = int64(e.ID)
			}
			e.IPLocation = enrichIPLocation(e.ClientIP)
			// 保留/私网 IP 不进大屏事件流（v4 裁定，与聚合口径一致）；游标
			// 语义不受影响——next_since_id 恒为已扫描最大 id，被过滤行只是跳过。
			if isReservedIP(e.ClientIP) {
				continue
			}
			e.AttackType = categorizeAttack(ruleTriggered, ruleMsg)
			e.RuleTrigged = ruleTriggered
			e.TriggerType = triggerTypeForRule(ruleTriggered)
			events = append(events, e)
		}
		if err := rows.Err(); err != nil {
			services.Logf("error", "security event feed: rows iteration failed: %v", err)
			scanFailed = true
		}
		return scanned, lastID
	}

	const selectCols = `SELECT id, event_time, client_ip, action, COALESCE(rule_name,''), COALESCE(rule_triggered,''), COALESCE(rule_msg,''), COALESCE(event_type,''), COALESCE(duration_us,0), COALESCE(anomaly_score,0)
		FROM security_events`
	hasMore := false
	if sinceID <= 0 {
		// 首屏：从最新行降序扫描收集 limit 条（保留地址过滤时向更老续扫），
		// 收集完成后整体反转为 id 升序输出；has_more 恒 false（不回溯更老）。
		upperBound := int64(0) // 0=无上界；首页后改为「上一页最小 id」，继续向更老行扫描
		for page := 0; page < maxScanPages && len(events) < limit; page++ {
			pageLimit := limit - len(events)
			query := selectCols + ` WHERE id > 0`
			var args []any
			if upperBound > 0 {
				query += ` AND id < ?`
				args = append(args, upperBound)
			}
			query += ` ORDER BY id DESC LIMIT ?`
			args = append(args, pageLimit)
			scanned, lastID := scanPage(query, args...)
			if scanFailed {
				c.JSON(http.StatusInternalServerError, models.APIResponse{Code: 500, Message: "安全事件查询失败"})
				return
			}
			if lastID > 0 {
				upperBound = lastID // 继续向更老的行扫描（首页上界=0 表示从最新行开始）
			}
			if scanned < pageLimit {
				break // 已到顶（本页未填满 = 没有更老的行）
			}
		}
		for i, j := 0, len(events)-1; i < j; i, j = i+1, j-1 {
			events[i], events[j] = events[j], events[i]
		}
	} else {
		// 增量：id > cursor 升序逐页扫描直至凑满 limit 或到顶（无重无漏）。
		cursor := sinceID
		lastPageFull := false
		for page := 0; page < maxScanPages && len(events) < limit; page++ {
			pageLimit := limit - len(events)
			scanned, lastID := scanPage(selectCols+` WHERE id > ? ORDER BY id ASC LIMIT ?`, cursor, pageLimit)
			if scanFailed {
				c.JSON(http.StatusInternalServerError, models.APIResponse{Code: 500, Message: "安全事件查询失败"})
				return
			}
			if lastID > 0 {
				cursor = lastID
			}
			lastPageFull = scanned == pageLimit
			if scanned < pageLimit {
				break // 已到顶（本页未填满 = 没有更新的行）
			}
		}
		// has_more：末页填满且游标已推进 = 可能还有更新未返回（下次轮询以
		// next_since_id 续拉）
		hasMore = lastPageFull && nextSinceID > sinceID
	}
	c.JSON(http.StatusOK, models.APIResponse{Code: 0, Data: gin.H{"events": events, "since_id": sinceID, "next_since_id": nextSinceID, "limit": limit, "has_more": hasMore}})
}

// triggerTypeForRule 触发类型显示映射（v2.3.8 单源）：阶段 id → 业务语义类型。
// 爬虫事件独立于地域拦截（豁免/伪装不再落「IP 访问控制」桶，消除歧义）；
// WAF 拆 CRS/自定义（10000-899999=自定义规则库、1000000+=合成自定义）；
// 429→限流、GeoIP 老 id:8 兼容。
func triggerTypeForRule(ruleTriggered string) string {
	n, err := strconv.Atoi(ruleTriggered)
	if err == nil {
		switch {
		case n >= 810000 && n < 850000, n >= 850000 && n < 900000:
			return "爬虫Bot"
		case n >= 800000 && n < 810000:
			return "地域拦截"
		case n >= 1000000:
			return "WAF·自定义"
		case n >= 10000 && n < 900000:
			return "WAF·自定义"
		case n >= 900000:
			return "WAF·CRS"
		}
	}
	switch ruleTriggered {
	case "429":
		return "限流"
	case "2", "4", "5", "7":
		return "IP 访问控制"
	case "8":
		return "地域拦截"
	case "3", "12":
		return "信任名单"
	case "14":
		return "威胁情报库"
	case "11":
		return "请求体异常"
	default:
		return "其他"
	}
}
