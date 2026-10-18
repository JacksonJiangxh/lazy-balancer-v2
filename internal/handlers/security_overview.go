package handlers

import (
	"database/sql"
	"errors"
	"fmt"
	"net/http"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/gin-gonic/gin"

	"lazy-balancer-v2/internal/db"
	"lazy-balancer-v2/internal/models"
	"lazy-balancer-v2/internal/services"
)

// GetSecurityRateLimitBlocks 返回各站点被限流（HTTP 429）拦截的累计次数，数据
// 来自 Caddy admin /metrics。注意口径：仅按 code=429 过滤、含上游自返 429；
// 计数自最近一次 Caddy 配置重载以来累计（历史问题-1 历史实证：/load
// 重建 metrics registry 即归零；进程重启同），非进程启动口径（前端按"累计拦截"标注）。
// 抓取失败返回 500：降级为空列表会让「Caddy 指标不可达」与「暂无限流拦截」
// 不可区分，面板错误态需可达（历史问题 三-4）。
func (h *Handlers) GetSecurityRateLimitBlocks(c *gin.Context) {
	blocks, err := services.ScrapeRateLimitBlocks(h.cfg.CaddyMetricsURL)
	if err != nil {
		services.Logf("error", "Scrape rate-limit blocks failed: %v", err)
		c.JSON(http.StatusInternalServerError, models.APIResponse{Code: 500, Message: "限流拦截数据不可用"})
		return
	}
	var total float64
	for _, block := range blocks {
		total += block.Count
	}
	c.JSON(http.StatusOK, models.APIResponse{Code: 0, Data: gin.H{
		"total": total,
		"hosts": blocks,
	}})
}

// GetRuleStageStats 返回单规则的三阶段计数（流程抽屉计数 chip）：
//   - stage1_blocked_24h / stage3_blocked_24h：近 24h 该规则 blocked 安全事件
//     按 rule_triggered id 形状分桶——阶段 1（IP 访问控制+威胁情报库+地域拦截预检）=
//     {2,4,7,8,14} ∪ [800000,900000)，其余（CRS 9xxxxx/自定义/合成 id）归阶段 3；
//   - ratelimit_blocks_reload：Caddy /metrics 429 计数（重载口径，自最近一次
//     配置重载以来累计）按规则 domain 映射回规则求和——规则域名与 host 标签
//     不匹配的部署（泛域名/CNAME）显示 0 而非报错（已声明口径，不新造时序）。
//
// 429 抓取失败返回 500（与 GetSecurityRateLimitBlocks 同口径：指标不可达与
// 暂无限流拦截必须可区分，前端 chip 显示「暂无计数」）。
func (h *Handlers) GetRuleStageStats(c *gin.Context) {
	if db.MetricsDB == nil {
		// MetricsDB 未装配：与成功路径同键的零统计而非 panic（历史 历史问题）。
		c.JSON(http.StatusOK, models.APIResponse{Code: 0, Data: gin.H{
			"stage1_blocked_24h":      0,
			"stage3_blocked_24h":      0,
			"ratelimit_blocks_reload": 0.0,
			"precheck_avg_us":         0.0,
			"precheck_samples":        0,
			"waf_avg_us":              0.0,
			"waf_samples":             0,
		}})
		return
	}
	ruleCaddyID := c.Param("caddy_id")
	rows, err := db.MetricsDB.Query(`SELECT rule_triggered, COUNT(*) FROM security_events WHERE rule_caddy_id=? AND action='blocked' AND event_time >= datetime('now','-1 day') GROUP BY rule_triggered`, ruleCaddyID)
	if err != nil {
		services.Logf("error", "stage-stats query failed for %s: %v", ruleCaddyID, err)
		c.JSON(http.StatusInternalServerError, models.APIResponse{Code: 500, Message: "阶段统计查询失败"})
		return
	}
	stage1, stage3 := 0, 0
	for rows.Next() {
		var triggered string
		var count int
		if err := rows.Scan(&triggered, &count); err != nil {
			rows.Close()
			services.Logf("error", "stage-stats scan failed for %s: %v", ruleCaddyID, err)
			c.JSON(http.StatusInternalServerError, models.APIResponse{Code: 500, Message: "阶段统计查询失败"})
			return
		}
		n, convErr := strconv.Atoi(triggered)
		switch {
		case triggered == "429":
			// A81A-历史问题：限流拦截（429）由 ratelimit_blocks_reload（/metrics
			// 429 计数）单独供给阶段 2 chip；此前落入 else 分支被计入
			// stage3_blocked_24h，导致同一拦截同时出现在阶段 2 与阶段 3。
			continue
		case convErr == nil && services.IsStage1PrecheckID(n): // 历史收敛：五元组单一事实源
			stage1 += count
		default:
			stage3 += count
		}
	}
	if err := rows.Err(); err != nil {
		rows.Close()
		services.Logf("error", "stage-stats rows iteration failed for %s: %v", ruleCaddyID, err)
		c.JSON(http.StatusInternalServerError, models.APIResponse{Code: 500, Message: "阶段统计查询失败"})
		return
	}
	rows.Close()

	var domain string
	if err := db.DB.QueryRow(`SELECT COALESCE(domain,'') FROM lb_rules WHERE caddy_id=?`, ruleCaddyID).Scan(&domain); err != nil {
		// APIMCP45-3：ErrNoRows（规则不存在）与真实 DB 故障分判——前者归 404
		// not_found，后者保持 500 且 message 归位查询失败（不再借「规则不存在」
		// 文案）。前端对非 200 一律 stats=null，404 化不改变前端表现。
		if errors.Is(err, sql.ErrNoRows) {
			c.JSON(http.StatusNotFound, models.APIResponse{Code: 404, Message: "规则不存在"})
			return
		}
		services.Logf("error", "stage-stats read rule domain failed for %s: %v", ruleCaddyID, err)
		c.JSON(http.StatusInternalServerError, models.APIResponse{Code: 500, Message: "阶段统计查询失败"})
		return
	}
	var ratelimit float64
	if domain != "" {
		blocks, err := services.ScrapeRateLimitBlocks(h.cfg.CaddyMetricsURL)
		if err != nil {
			services.Logf("error", "stage-stats scrape rate-limit blocks failed: %v", err)
			c.JSON(http.StatusInternalServerError, models.APIResponse{Code: 500, Message: "限流拦截数据不可用"})
			return
		}
		ruleHosts := make(map[string]struct{})
		for _, host := range strings.Split(domain, ",") {
			if trimmed := services.NormalizeMetricsHost(host); trimmed != "" {
				ruleHosts[trimmed] = struct{}{}
			}
		}
		for _, block := range blocks {
			if _, ok := ruleHosts[services.NormalizeMetricsHost(block.Host)]; ok {
				ratelimit += block.Count
			}
		}
	}
	// 分段平均处理耗时（2026-09-27 用户裁定）：security_events.duration_us 按
	// 预检/WAF 段分桶平均（摄取管道已按规则归属选段值——预检事件=纯预检耗时,
	// WAF 事件=隔离预检后的 WAF 耗时）。24h 窗口对齐计数口径;duration_us>0 过滤
	// 历史行/未命中行;高并发下 GROUP BY 走 idx_security_events_rule+time 索引。
	preAvg, preCnt, wafAvg, wafCnt := 0.0, 0, 0.0, 0
	// 预检平均用 precheck_us 全样本(含 WAF 事件的预检快照,样本更大更准);
	// WAF 平均只用 WAF 段事件的 duration_us(已隔离预检开销)。
	stageTimingSQL := fmt.Sprintf(`SELECT rule_triggered, AVG(CASE WHEN %s THEN precheck_us ELSE duration_us END), COUNT(*) FROM security_events WHERE rule_caddy_id=? AND event_time >= datetime('now','-1 day') AND duration_us > 0 GROUP BY rule_triggered`, services.Stage1PrecheckSegmentSQL)
	if trows, terr := db.MetricsDB.Query(stageTimingSQL, ruleCaddyID); terr == nil {
		for trows.Next() {
			var triggered string
			var avg float64
			var cnt int
			if serr := trows.Scan(&triggered, &avg, &cnt); serr != nil {
				break
			}
			if n, cerr := strconv.Atoi(triggered); cerr == nil && services.IsStage1PrecheckID(n) {
				preAvg = (preAvg*float64(preCnt) + avg*float64(cnt)) / float64(preCnt+cnt)
				preCnt += cnt
			} else {
				wafAvg = (wafAvg*float64(wafCnt) + avg*float64(cnt)) / float64(wafCnt+cnt)
				wafCnt += cnt
			}
		}
		// SEC-历史问题（历史）：分段耗时迭代失败不再静默——与 历史问题 查询失败
		// 同待遇记 warn（耗时为增强信息，响应仍 200，已收样本保留）。
		if err := trows.Err(); err != nil {
			services.Logf("warn", "stage-stats timing rows iteration failed for %s: %v", ruleCaddyID, err)
		}
		trows.Close()
	} else {
		// 历史 历史问题:查询失败不再静默——留 warn 便于排查(响应仍 200,
		// 耗时为增强信息,与计数/429 的 500 纪律不同——已声明口径)
		services.Logf("warn", "stage-stats timing query failed for %s: %v", ruleCaddyID, terr)
	}
	c.JSON(http.StatusOK, models.APIResponse{Code: 0, Data: gin.H{
		"stage1_blocked_24h":      stage1,
		"stage3_blocked_24h":      stage3,
		"ratelimit_blocks_reload": ratelimit,
		"precheck_avg_us":         preAvg,
		"precheck_samples":        preCnt,
		"waf_avg_us":              wafAvg,
		"waf_samples":             wafCnt,
	}})
}

// 历史问题-11（历史）：安全总览的近 7 天聚合（趋势/Top10 IP/攻击族）此前
// 每请求执行 4 条无缓存的大范围扫描（趋势、Top IP、Top IP 攻击族、攻击类型），
// 100/s 攻击态 7 天可达数千万行时每 30s 轮询多趟全窗口聚合。改为 30s 进程内
// 缓存（键含指标库句柄/日界/时区偏移——换库/跨日/改时区即失效；失败不缓存）。
const securityOverviewAggCacheTTL = 30 * time.Second

type securityOverviewAggregates struct {
	trend            []models.SecurityTrendPoint
	topIPs           []models.SecurityTopIP
	attackTypes      []models.SecurityAttackType
	attackTypesStage []models.SecurityAttackType
}

type securityOverviewAggCacheKey struct {
	metrics    *sql.DB
	todayStart string
	tzModifier string
}

type securityOverviewAggCacheEntry struct {
	data      securityOverviewAggregates
	expiresAt time.Time
}

var (
	securityOverviewAggCacheMu sync.Mutex
	securityOverviewAggCache   = map[securityOverviewAggCacheKey]securityOverviewAggCacheEntry{}
)

// resetSecurityOverviewAggCacheForTest 测试缝：清空总览聚合缓存（生产不调用）。
func resetSecurityOverviewAggCacheForTest() {
	securityOverviewAggCacheMu.Lock()
	securityOverviewAggCache = map[securityOverviewAggCacheKey]securityOverviewAggCacheEntry{}
	securityOverviewAggCacheMu.Unlock()
}

// loadSecurityOverviewAggregates 计算（或命中缓存）近 7 天聚合。错误不缓存、
// 由调用方聚合成 500（与既有「任一查询失败显式报错」口径一致）。
func loadSecurityOverviewAggregates(metricsDB *sql.DB, today time.Time, todayStartUTC, tzModifier string) (securityOverviewAggregates, error) {
	key := securityOverviewAggCacheKey{metrics: metricsDB, todayStart: todayStartUTC, tzModifier: tzModifier}
	now := time.Now()
	securityOverviewAggCacheMu.Lock()
	if entry, ok := securityOverviewAggCache[key]; ok && now.Before(entry.expiresAt) {
		data := entry.data
		securityOverviewAggCacheMu.Unlock()
		return data, nil
	}
	securityOverviewAggCacheMu.Unlock()

	var firstErr error
	track := func(err error) {
		if err != nil && firstErr == nil {
			firstErr = err
		}
	}
	trendByDate := map[string]models.SecurityTrendPoint{}
	trendRows, err := metricsDB.Query(`SELECT date(event_time, ?) as d, SUM(CASE WHEN action='blocked' THEN 1 ELSE 0 END) as b, SUM(CASE WHEN action='logged' THEN 1 ELSE 0 END) as l FROM security_events WHERE event_time >= datetime(?, '-6 days') GROUP BY d`, tzModifier, todayStartUTC)
	track(err)
	for trendRows != nil && trendRows.Next() {
		var t models.SecurityTrendPoint
		track(trendRows.Scan(&t.Date, &t.Blocked, &t.Detected))
		trendByDate[t.Date] = t
	}
	if trendRows != nil {
		track(trendRows.Err())
		trendRows.Close()
	}
	trend := make([]models.SecurityTrendPoint, 0, 7)
	for i := 6; i >= 0; i-- {
		day := today.AddDate(0, 0, -i).Format("2006-01-02")
		point := trendByDate[day]
		point.Date = day
		trend = append(trend, point)
	}

	type topIPRow struct {
		ip                string
		blocked, detected int
		lastTime          string
	}
	var topRows []topIPRow
	ipRows, err := metricsDB.Query(`SELECT client_ip, SUM(CASE WHEN action='blocked' THEN 1 ELSE 0 END) as b, SUM(CASE WHEN action='logged' THEN 1 ELSE 0 END) as l, MAX(event_time) as last_time FROM security_events WHERE event_time >= datetime(?, '-6 days') GROUP BY client_ip ORDER BY b + l DESC LIMIT 10`, todayStartUTC)
	track(err)
	for ipRows != nil && ipRows.Next() {
		var row topIPRow
		track(ipRows.Scan(&row.ip, &row.blocked, &row.detected, &row.lastTime))
		topRows = append(topRows, row)
	}
	if ipRows != nil {
		track(ipRows.Err())
		ipRows.Close()
	}
	familyCountsByIP := map[string]map[string]int{}
	stageFamilyCountsByIP := map[string]map[string]int{}
	if len(topRows) > 0 {
		placeholders := make([]string, len(topRows))
		famArgs := make([]interface{}, 0, len(topRows)+1)
		famArgs = append(famArgs, todayStartUTC)
		for i, row := range topRows {
			placeholders[i] = "?"
			famArgs = append(famArgs, row.ip)
		}
		famRows, ferr := metricsDB.Query(fmt.Sprintf(`SELECT client_ip, COALESCE(rule_triggered,''), COALESCE(rule_msg,''), COUNT(*) as cnt FROM security_events WHERE event_time >= datetime(?, '-6 days') AND client_ip IN (%s) GROUP BY client_ip, rule_triggered, rule_msg`, strings.Join(placeholders, ",")), famArgs...)
		track(ferr)
		for famRows != nil && famRows.Next() {
			var ip, ruleTriggered, ruleMsg string
			var cnt int
			track(famRows.Scan(&ip, &ruleTriggered, &ruleMsg, &cnt))
			counts := familyCountsByIP[ip]
			if counts == nil {
				counts = map[string]int{}
				familyCountsByIP[ip] = counts
			}
			counts[categorizeAttack(ruleTriggered, ruleMsg)] += cnt
			stageCounts := stageFamilyCountsByIP[ip]
			if stageCounts == nil {
				stageCounts = map[string]int{}
				stageFamilyCountsByIP[ip] = stageCounts
			}
			stageCounts[stageCategorizeAttack(ruleTriggered, ruleMsg)] += cnt
		}
		if famRows != nil {
			track(famRows.Err())
			famRows.Close()
		}
	}
	topIPs := make([]models.SecurityTopIP, 0, len(topRows))
	for _, row := range topRows {
		topIPs = append(topIPs, models.SecurityTopIP{
			IP:              row.ip,
			IPLocation:      enrichIPLocation(row.ip),
			Blocked:         row.blocked,
			Detected:        row.detected,
			LastTime:        row.lastTime,
			AttackType:      joinDistinctFamilies(familyCountsByIP[row.ip]),
			AttackTypeStage: joinDistinctFamilies(stageFamilyCountsByIP[row.ip]),
		})
	}

	typeRows, err := metricsDB.Query(`SELECT COALESCE(rule_triggered,''), COALESCE(rule_msg,''), COUNT(*) as cnt FROM security_events WHERE event_time >= datetime(?, '-6 days') GROUP BY rule_triggered, rule_msg`, todayStartUTC)
	track(err)
	familyCounts := map[string]int{}
	stageCounts := map[string]int{}
	for typeRows != nil && typeRows.Next() {
		var ruleTriggered, ruleMsg string
		var cnt int
		track(typeRows.Scan(&ruleTriggered, &ruleMsg, &cnt))
		familyCounts[categorizeAttack(ruleTriggered, ruleMsg)] += cnt
		stageCounts[stageCategorizeAttack(ruleTriggered, ruleMsg)] += cnt
	}
	if typeRows != nil {
		track(typeRows.Err())
		typeRows.Close()
	}
	attackTypesStage := make([]models.SecurityAttackType, 0, len(stageCounts))
	for name, value := range stageCounts {
		attackTypesStage = append(attackTypesStage, models.SecurityAttackType{Name: name, Value: value})
	}
	// A81A-历史问题：值相等时按名称升序 tiebreak（map 迭代序随机，防轮询抖动）。
	sort.Slice(attackTypesStage, func(i, j int) bool {
		if attackTypesStage[i].Value != attackTypesStage[j].Value {
			return attackTypesStage[i].Value > attackTypesStage[j].Value
		}
		return attackTypesStage[i].Name < attackTypesStage[j].Name
	})

	attackTypes := make([]models.SecurityAttackType, 0, len(familyCounts))
	for name, value := range familyCounts {
		attackTypes = append(attackTypes, models.SecurityAttackType{Name: name, Value: value})
	}
	sort.Slice(attackTypes, func(i, j int) bool {
		if attackTypes[i].Value != attackTypes[j].Value {
			return attackTypes[i].Value > attackTypes[j].Value
		}
		return attackTypes[i].Name < attackTypes[j].Name
	})
	if len(attackTypes) > 10 {
		attackTypes = attackTypes[:10]
	}

	data := securityOverviewAggregates{trend: trend, topIPs: topIPs, attackTypes: attackTypes, attackTypesStage: attackTypesStage}
	if firstErr != nil {
		return data, firstErr
	}
	securityOverviewAggCacheMu.Lock()
	// 过期项顺带清理（键空间随时区/日界变化，且测试换库会产生旧键）。
	for k, entry := range securityOverviewAggCache {
		if !now.Before(entry.expiresAt) {
			delete(securityOverviewAggCache, k)
		}
	}
	securityOverviewAggCache[key] = securityOverviewAggCacheEntry{data: data, expiresAt: now.Add(securityOverviewAggCacheTTL)}
	securityOverviewAggCacheMu.Unlock()
	return data, nil
}
