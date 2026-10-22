package handlers

import (
	"context"
	"database/sql"
	"fmt"
	"io"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/gin-gonic/gin"
	"golang.org/x/sync/singleflight"

	"lazy-balancer-v2/internal/db"
	"lazy-balancer-v2/internal/models"
)

var caddyMetricsHTTPClient = &http.Client{Timeout: 10 * time.Second}

func fetchCaddyMetrics(ctx context.Context, url string) ([]byte, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, err
	}
	resp, err := caddyMetricsHTTPClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode < http.StatusOK || resp.StatusCode >= http.StatusMultipleChoices {
		return nil, fmt.Errorf("Caddy 指标接口返回状态码 %d", resp.StatusCode)
	}
	// （2026-09-05 审计）：与 services.go collect 的同型——limit+1
	// 探测读取，超 16MB 显式报错（共用本函数的指标端点回 502），防止指标基数
	// 膨胀时的无界内存分配。
	body, err := io.ReadAll(io.LimitReader(resp.Body, 16<<20+1))
	if err != nil {
		return nil, fmt.Errorf("读取 Caddy 指标响应失败: %w", err)
	}
	if len(body) > 16<<20 {
		return nil, fmt.Errorf("Caddy 指标响应超过 16MB 上限")
	}
	return body, nil
}

func caddyMetricsError(c *gin.Context, err error) {
	c.JSON(http.StatusBadGateway, models.APIResponse{Code: http.StatusBadGateway, Message: "采集 Caddy 指标失败: " + err.Error()})
}

func (h *Handlers) GetMetricsOverview(c *gin.Context) {
	overview := h.metricsService.GetOverview()
	c.JSON(http.StatusOK, models.APIResponse{Code: 0, Data: overview})
}

// metricsDashboardOutcome 面板聚合结果：status=0 为成功；否则携带错误状态码
// 与文案（负缓存需保存完整失败响应形态，命中时与真实失败一致）。
type metricsDashboardOutcome struct {
	payload gin.H
	status  int
	message string
}

var (
	// metricsDashboardTTL 成功聚合缓存窗口（与 systemSampleTTL 同量级）。
	metricsDashboardTTL = 5 * time.Second
	// metricsDashboardNegativeTTL 失败负缓存窗口：失败短缓存——多页签/多客户端
	// 在同一失败窗口内不再串行重试击穿 Caddy，到期立即重试（自愈快）。
	metricsDashboardNegativeTTL = 2 * time.Second
	// metricsDashboardFetch 指标抓取入口（测试缝：计数/慢响应/失败注入）。
	metricsDashboardFetch = fetchCaddyMetrics
	// metricsDashboardGroup 并发请求合并：同一时刻只跑一趟聚合，其余等待同一
	// 结果（旧实现以全局锁串行整个聚合，且失败不缓存→并发请求逐个重试）。
	metricsDashboardGroup singleflight.Group
)

var metricsDashboardState struct {
	sync.Mutex
	outcome   metricsDashboardOutcome
	expiresAt time.Time
	valid     bool
}

// resetMetricsDashboardCacheForTest 测试缝：清空面板缓存（生产不调用）。
func resetMetricsDashboardCacheForTest() {
	metricsDashboardState.Lock()
	metricsDashboardState.outcome = metricsDashboardOutcome{}
	metricsDashboardState.expiresAt = time.Time{}
	metricsDashboardState.valid = false
	metricsDashboardState.Unlock()
}

func (h *Handlers) GetMetricsDashboard(c *gin.Context) {
	outcome := h.metricsDashboardCached(c.Request.Context())
	if outcome.status != 0 {
		c.JSON(outcome.status, models.APIResponse{Code: outcome.status, Message: outcome.message})
		return
	}
	c.JSON(http.StatusOK, models.APIResponse{Code: 0, Data: outcome.payload})
}

// metricsDashboardCached TTL 命中直返；未命中经 single-flight 合并并发后聚合，
// 成功写正缓存、失败写短负缓存（失败不长期缓存）。
func (h *Handlers) metricsDashboardCached(ctx context.Context) metricsDashboardOutcome {
	if outcome, ok := loadMetricsDashboardCache(time.Now()); ok {
		return outcome
	}
	value, _, _ := metricsDashboardGroup.Do("dashboard", func() (any, error) {
		if outcome, ok := loadMetricsDashboardCache(time.Now()); ok {
			return outcome, nil
		}
		// 聚合脱离首个请求的取消信号（首请求断开不应让同批等待者失败），
		// 但保留总时长上限。
		workCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), 15*time.Second)
		defer cancel()
		outcome := h.buildMetricsDashboard(workCtx)
		storeMetricsDashboardOutcome(outcome, time.Now())
		return outcome, nil
	})
	outcome, _ := value.(metricsDashboardOutcome)
	return outcome
}

func loadMetricsDashboardCache(now time.Time) (metricsDashboardOutcome, bool) {
	metricsDashboardState.Lock()
	defer metricsDashboardState.Unlock()
	if metricsDashboardState.valid && now.Before(metricsDashboardState.expiresAt) {
		return metricsDashboardState.outcome, true
	}
	return metricsDashboardOutcome{}, false
}

func storeMetricsDashboardOutcome(outcome metricsDashboardOutcome, now time.Time) {
	ttl := metricsDashboardTTL
	if outcome.status != 0 {
		ttl = metricsDashboardNegativeTTL
	}
	if ttl <= 0 {
		return
	}
	metricsDashboardState.Lock()
	metricsDashboardState.outcome = outcome
	metricsDashboardState.expiresAt = now.Add(ttl)
	metricsDashboardState.valid = true
	metricsDashboardState.Unlock()
}

func (h *Handlers) buildMetricsDashboard(ctx context.Context) metricsDashboardOutcome {
	body, err := metricsDashboardFetch(ctx, h.cfg.CaddyMetricsURL)
	if err != nil {
		return metricsDashboardOutcome{status: http.StatusBadGateway, message: "采集 Caddy 指标失败: " + err.Error()}
	}
	samples, err := parsePrometheusSamples(string(body))
	if err != nil {
		return metricsDashboardOutcome{status: http.StatusBadGateway, message: "采集 Caddy 指标失败: " + err.Error()}
	}
	metricsIndex := buildPrometheusMetricsIndex(samples)

	type dashboardRule struct {
		id, domain, protocol string
		listenPort           int
		enableTLS, enabled   bool
	}
	ruleRows, err := db.DB.QueryContext(ctx, `
		SELECT caddy_id, COALESCE(domain,''), listen_port, COALESCE(protocol,''), COALESCE(enable_tls,0), IIF(enabled IN ('1',1),1,0)
		FROM lb_rules ORDER BY caddy_id`)
	if err != nil {
		return metricsDashboardOutcome{status: http.StatusInternalServerError, message: "读取规则指标配置失败"}
	}
	defer ruleRows.Close()
	rules := make([]dashboardRule, 0)
	for ruleRows.Next() {
		var rule dashboardRule
		if err := ruleRows.Scan(&rule.id, &rule.domain, &rule.listenPort, &rule.protocol, &rule.enableTLS, &rule.enabled); err != nil {
			return metricsDashboardOutcome{status: http.StatusInternalServerError, message: "读取规则指标配置失败"}
		}
		rules = append(rules, rule)
	}
	if err := ruleRows.Err(); err != nil {
		return metricsDashboardOutcome{status: http.StatusInternalServerError, message: "读取规则指标配置失败"}
	}

	upstreamRows, err := db.DB.QueryContext(ctx, `
		SELECT rule_id, COALESCE(host,''), COALESCE(port,0), COALESCE(enabled,0)
		FROM upstreams WHERE enabled=1`)
	if err != nil {
		return metricsDashboardOutcome{status: http.StatusInternalServerError, message: "读取规则上游失败"}
	}
	defer upstreamRows.Close()
	upstreamsByRule := make(map[string][]models.Upstream)
	for upstreamRows.Next() {
		var upstream models.Upstream
		if err := upstreamRows.Scan(&upstream.RuleID, &upstream.Host, &upstream.Port, &upstream.Enabled); err != nil {
			return metricsDashboardOutcome{status: http.StatusInternalServerError, message: "读取规则上游失败"}
		}
		upstreamsByRule[upstream.RuleID] = append(upstreamsByRule[upstream.RuleID], upstream)
	}
	if err := upstreamRows.Err(); err != nil {
		return metricsDashboardOutcome{status: http.StatusInternalServerError, message: "读取规则上游失败"}
	}

	// Block 标签+4xx 扣除(2026-09-15 用户裁定,方案 B):blocked 来自
	// lb_security_blocked_counter 插件(lazybalancer_security_blocked_total,
	// 与 status_4xx 同源同抓取零延迟);4xx 显示扣除安全拦截——不再双计。
	blockedByRule := metricsIndex.blockedByRule

	ruleMetrics := make(map[string]gin.H, len(rules))
	for _, rule := range rules {
		metrics := emptyRuleMetrics()
		if rule.enabled && rule.protocol == "tcp" {
			// TCP 口径=上游地址归集（caddy-l4 指标仅 upstream 标签，
			// 见 tcpRuleMetrics 注释）——多规则共享上游地址时为跨规则合计值，
			// Dashboard 请求数/处理中列 tooltip 已明示。
			metrics = metricsIndex.tcpRuleMetrics(upstreamsByRule[rule.id])
		} else if rule.enabled {
			metrics = metricsIndex.ruleMetrics(ruleMetricTarget{ruleID: rule.id, domain: rule.domain, listenPort: rule.listenPort, enableTLS: rule.enableTLS})
		}
		metrics["enabled"] = rule.enabled
		blocked := blockedByRule[rule.id]
		metrics["blocked"] = blocked
		// 4xx 扣除安全拦截(共享 deductBlockedFrom4xx）
		deductBlockedFrom4xx(metrics, blocked)
		ruleMetrics[rule.id] = metrics
	}
	payload := gin.H{
		"global":   metricsIndex.globalMetrics(),
		"hosts":    metricsIndex.hostMetrics(),
		"overview": h.metricsService.GetOverview(),
		"rules":    ruleMetrics,
	}
	return metricsDashboardOutcome{payload: payload}
}

func (h *Handlers) GetRuleMetrics(c *gin.Context) {
	ruleID := c.Param("caddy_id")

	var rule models.LbRule
	err := db.DB.QueryRow(`SELECT COALESCE(domain,''), listen_port, COALESCE(protocol,''), COALESCE(enable_tls,0) FROM lb_rules WHERE caddy_id = ?`, ruleID).Scan(
		&rule.Domain, &rule.ListenPort, &rule.Protocol, &rule.EnableTLS)
	if err == sql.ErrNoRows {
		c.JSON(http.StatusNotFound, models.APIResponse{Code: 404, Message: "Rule not found"})
		return
	}
	if err != nil {
		c.JSON(http.StatusInternalServerError, models.APIResponse{Code: 500, Message: "数据库错误"})
		return
	}

	body, err := fetchCaddyMetrics(c.Request.Context(), h.cfg.CaddyMetricsURL)
	if err != nil {
		caddyMetricsError(c, err)
		return
	}

	var metrics gin.H
	var parseErr error
	if rule.Protocol == "tcp" {
		upstreams, err := loadRuleUpstreams(ruleID)
		if err != nil {
			c.JSON(http.StatusInternalServerError, models.APIResponse{Code: 500, Message: "读取规则上游失败: " + err.Error()})
			return
		}
		metrics, parseErr = parseTCPRuleMetricsFromPrometheus(string(body), upstreams)
		if parseErr == nil {
			// TCP 规则无 lazybalancer 计数(L4 无插件)——
			// blocked 恒 0,与 Dashboard 对该形态恒写 blocked 键对齐。
			// 本端点 TCP 指标同为上游地址口径（L4 指标仅 upstream
			// 标签）——共享上游地址的多规则返回相同合计值，非规则独占计数。
			metrics["blocked"] = int64(0)
		}
	} else {
		metrics, parseErr = parseRuleMetricsFromPrometheus(string(body), rule.Domain, rule.ListenPort, rule.EnableTLS, ruleID)
	}
	if parseErr != nil {
		caddyMetricsError(c, parseErr)
		return
	}

	c.JSON(http.StatusOK, models.APIResponse{Code: 0, Data: metrics})
}

// parseMetricsInterval 解析 interval 参数（"<n>h"/"<n>d"/"<n>m"，空/非法回退
// 1h；上限 168h/7d/10080m——保留期固定 7 天）为 SQLite
// datetime modifier 与窗口秒数。单一解析源——此前
// metricsIntervalModifier 与 metricsIntervalSeconds 两份手写解析靠注释维持
// 一致（分桶粒度=窗口秒数/720 必须对应 SQL modifier），收敛后编译期
// 保证。SQLite 没有 "1h" 语法，算术拼接得 NULL。
func parseMetricsInterval(interval string) (modifier string, seconds int64) {
	interval = strings.TrimSpace(strings.ToLower(interval))
	if interval == "" {
		return "-1 hours", 3600
	}
	unit := interval[len(interval)-1:]
	n := strings.TrimSuffix(interval, unit)
	value, err := strconv.Atoi(n)
	if err != nil {
		return "-1 hours", 3600
	}
	// Atoi 接受负数/零——"-5h"/"0d" 曾拼出非法或零长 SQL modifier
	// （"-−5 hours"）与负/零桶宽。非正值一律回退默认窗口（上限钳制不变）。
	if value <= 0 {
		return "-1 hours", 3600
	}
	switch unit {
	case "h":
		if value > 168 {
			value = 168 // F9:保留期固定 7 天——小时上限 7×24
		}
		return "-" + strconv.Itoa(value) + " hours", int64(value) * 3600
	case "d":
		if value > 7 {
			value = 7 // F9:天上限 7(原 30d 超窗静默空)
		}
		return "-" + strconv.Itoa(value) + " days", int64(value) * 86400
	case "m":
		if value > 10080 {
			value = 10080 // F9:分钟上限 7×24×60
		}
		return "-" + strconv.Itoa(value) + " minutes", int64(value) * 60
	default:
		return "-1 hours", 3600
	}
}

// metricsHistoryBuckets 是历史序列的桶数上限（两条历史端点共用：每桶取末行
// 样本，桶数恒 ≤720，与 GetMetricsHistory 的窗口函数范式一致）。
const metricsHistoryBuckets = 720

// metricsHistoryRange 把规则历史端点的 range 参数解析为 (SQLite modifier,
// 桶宽秒数, 桶数)。桶宽由 parseMetricsInterval 的窗口秒数单源派生
// （窗口秒数/桶数）——7d 曾与 GetMetricsHistory 各写一份桶宽
// （900s vs 840s），同一时间窗在两个端点返回不同粒度的序列，前端叠图/对账
// 失真。支持集固定 1h/6h/24h/7d（缺省 24h），非法值回退默认。
func metricsHistoryRange(value string) (string, int, int) {
	normalized := strings.ToLower(strings.TrimSpace(value))
	switch normalized {
	case "1h", "6h", "24h", "7d":
	default:
		normalized = "24h"
	}
	modifier, seconds := parseMetricsInterval(normalized)
	bucketSeconds := int(seconds / metricsHistoryBuckets)
	if bucketSeconds < 1 {
		bucketSeconds = 1
	}
	return modifier, bucketSeconds, metricsHistoryBuckets
}

// GetRuleMetricsHistory returns cumulative history rows for one HTTP rule
// within the requested range (1h/6h/24h/7d). TCP rules have no per-rule
// traffic counters from caddy-l4 and return an empty list with a note.
func (h *Handlers) GetRuleMetricsHistory(c *gin.Context) {
	caddyID := c.Param("caddy_id")
	var protocol string
	if err := db.DB.QueryRow("SELECT COALESCE(protocol,'') FROM lb_rules WHERE caddy_id = ?", caddyID).Scan(&protocol); dbQueryNotFound(c, err, "规则不存在", "GetRuleMetricsHistory query rule") {
		return
	}
	if protocol != "http" {
		c.JSON(http.StatusOK, models.APIResponse{Code: 0, Data: gin.H{"protocol": protocol, "supported": false, "rows": []any{}}})
		return
	}
	modifier, bucketSeconds, bucketCount := metricsHistoryRange(c.DefaultQuery("range", "24h"))
	if db.MetricsDB == nil {
		// MetricsDB 未装配（单测/嵌入形态）不得
		// nil-deref panic——对齐家族（GetIPEventCount/GetRuleStageStats）
		// 返回空数据 200。
		c.JSON(http.StatusOK, models.APIResponse{Code: 0, Data: gin.H{"protocol": protocol, "supported": true, "bucket_interval_seconds": bucketSeconds, "rows": []any{}}})
		return
	}
	rows, err := db.MetricsDB.Query(`
		WITH ranked AS (
			SELECT CAST(strftime('%s', timestamp) AS INTEGER) / ? AS bucket,
			       requests_total, requests_2xx, requests_3xx, requests_4xx, requests_5xx, requests_blocked, bytes_in, bytes_out,
			       ROW_NUMBER() OVER (
				   PARTITION BY CAST(strftime('%s', timestamp) AS INTEGER) / ?
				   ORDER BY timestamp DESC, id DESC
			   ) AS sample_rank
			FROM metrics_history
			WHERE rule_id = ? AND timestamp > datetime('now', ?)
		), recent AS (
			SELECT bucket, requests_total, requests_2xx, requests_3xx, requests_4xx, requests_5xx, requests_blocked, bytes_in, bytes_out
			FROM ranked WHERE sample_rank = 1 ORDER BY bucket DESC LIMIT ?
		)
		SELECT datetime(bucket * ?, 'unixepoch'), requests_total, requests_2xx, requests_3xx,
		       requests_4xx, requests_5xx, requests_blocked, bytes_in, bytes_out
		FROM recent ORDER BY bucket
	`, bucketSeconds, bucketSeconds, caddyID, modifier, bucketCount, bucketSeconds)
	if err != nil {
		c.JSON(http.StatusInternalServerError, models.APIResponse{Code: 500, Message: "读取历史指标失败: " + err.Error()})
		return
	}
	defer rows.Close()
	type row struct {
		Timestamp string `json:"timestamp"`
		Requests  int64  `json:"requests_total"`
		Status2xx int64  `json:"requests_2xx"`
		Status3xx int64  `json:"requests_3xx"`
		Status4xx int64  `json:"requests_4xx"`
		Status5xx int64  `json:"requests_5xx"`
		Blocked   int64  `json:"requests_blocked"`
		BytesIn   int64  `json:"bytes_in"`
		BytesOut  int64  `json:"bytes_out"`
	}
	result := []row{}
	for rows.Next() {
		var r row
		var timestamp string
		if err := rows.Scan(&timestamp, &r.Requests, &r.Status2xx, &r.Status3xx, &r.Status4xx, &r.Status5xx, &r.Blocked, &r.BytesIn, &r.BytesOut); err != nil {
			c.JSON(http.StatusInternalServerError, models.APIResponse{Code: 500, Message: "读取历史指标失败: " + err.Error()})
			return
		}
		ts, err := time.ParseInLocation("2006-01-02 15:04:05", timestamp, time.UTC)
		if err != nil {
			c.JSON(http.StatusInternalServerError, models.APIResponse{Code: 500, Message: "解析历史指标时间失败: " + err.Error()})
			return
		}
		// 统一口径：返回裸 UTC 字符串，由前端 formatDate 按配置时区转换
		// （与 /metrics/history 的 RFC3339 UTC 及其它列表端点一致）。
		r.Timestamp = ts.UTC().Format("2006-01-02 15:04:05")
		result = append(result, r)
	}
	if err := rows.Err(); err != nil {
		c.JSON(http.StatusInternalServerError, models.APIResponse{Code: 500, Message: "读取历史指标失败: " + err.Error()})
		return
	}
	c.JSON(http.StatusOK, models.APIResponse{Code: 0, Data: gin.H{"protocol": protocol, "supported": true, "bucket_interval_seconds": bucketSeconds, "rows": result}})
}

func (h *Handlers) GetMetricsHistory(c *gin.Context) {
	ruleID := c.Query("rule_id")
	rawInterval := c.DefaultQuery("interval", "1h")
	// modifier 与窗口秒数取自同一解析（parseMetricsInterval），
	// 杜绝双解析器漂移。
	interval, intervalSeconds := parseMetricsInterval(rawInterval)
	// 分桶上限——镜像 get_rule_metrics_history 的窗口
	// 函数范式（每桶取末行样本，桶数 ≤720）。此前无上限无分桶：默认配置
	// 7 天窗 30s 间隔可达 ~2 万行 ≈2.5MB 一次性返回（5s 间隔可达 12 万行）。
	metricsHistoryMaxBuckets := int64(metricsHistoryBuckets)
	bucketSeconds := intervalSeconds / metricsHistoryMaxBuckets
	if bucketSeconds < 1 {
		bucketSeconds = 1
	}

	var rows *sql.Rows
	var err error

	if db.MetricsDB == nil {
		// 未装配形态返回空列表 `[]`（同
		// 空结果形态），不得 nil-deref panic。
		c.JSON(http.StatusOK, models.APIResponse{Code: 0, Data: []any{}})
		return
	}

	if ruleID != "" {
		rows, err = db.MetricsDB.Query(`
			WITH ranked AS (
				SELECT CAST(strftime('%s', timestamp) AS INTEGER) / ? AS bucket,
				       requests_total, requests_2xx, requests_3xx, requests_4xx, requests_5xx, bytes_in, bytes_out,
				       ROW_NUMBER() OVER (
					   PARTITION BY CAST(strftime('%s', timestamp) AS INTEGER) / ?
					   ORDER BY timestamp DESC, id DESC
				   ) AS sample_rank
				FROM metrics_history
				WHERE rule_id = ? AND timestamp > datetime('now', ?)
			)
			SELECT datetime(bucket * ?, 'unixepoch'), requests_total, requests_2xx, requests_3xx,
			       requests_4xx, requests_5xx, bytes_in, bytes_out
			FROM (SELECT bucket, requests_total, requests_2xx, requests_3xx, requests_4xx, requests_5xx, bytes_in, bytes_out
			      FROM ranked WHERE sample_rank = 1 ORDER BY bucket DESC LIMIT ?) ORDER BY bucket
		`, bucketSeconds, bucketSeconds, ruleID, interval, bucketSeconds, metricsHistoryMaxBuckets)
	} else {
		rows, err = db.MetricsDB.Query(`
			WITH per_ts AS (
				SELECT timestamp, SUM(requests_total) AS requests_total, SUM(requests_2xx) AS requests_2xx,
				       SUM(requests_3xx) AS requests_3xx, SUM(requests_4xx) AS requests_4xx,
				       SUM(requests_5xx) AS requests_5xx, SUM(bytes_in) AS bytes_in, SUM(bytes_out) AS bytes_out
				FROM metrics_history
				WHERE rule_id IS NULL AND timestamp > datetime('now', ?)
				GROUP BY timestamp
			), ranked AS (
				SELECT CAST(strftime('%s', timestamp) AS INTEGER) / ? AS bucket,
				       requests_total, requests_2xx, requests_3xx, requests_4xx, requests_5xx, bytes_in, bytes_out,
				       ROW_NUMBER() OVER (
					   PARTITION BY CAST(strftime('%s', timestamp) AS INTEGER) / ?
					   ORDER BY timestamp DESC
				   ) AS sample_rank
				FROM per_ts
			)
			SELECT datetime(bucket * ?, 'unixepoch'), requests_total, requests_2xx, requests_3xx,
			       requests_4xx, requests_5xx, bytes_in, bytes_out
			FROM (SELECT bucket, requests_total, requests_2xx, requests_3xx, requests_4xx, requests_5xx, bytes_in, bytes_out
			      FROM ranked WHERE sample_rank = 1 ORDER BY bucket DESC LIMIT ?) ORDER BY bucket
		`, interval, bucketSeconds, bucketSeconds, bucketSeconds, metricsHistoryMaxBuckets)
	}

	if err != nil {
		c.JSON(http.StatusInternalServerError, models.APIResponse{Code: 500, Message: "数据库错误"})
		return
	}
	defer rows.Close()

	type MetricRow struct {
		Timestamp     time.Time `json:"timestamp"`
		RequestsTotal int64     `json:"requests_total"`
		Status2xx     int64     `json:"status_2xx"`
		Status3xx     int64     `json:"status_3xx"`
		Status4xx     int64     `json:"status_4xx"`
		Status5xx     int64     `json:"status_5xx"`
		BytesIn       int64     `json:"bytes_in"`
		BytesOut      int64     `json:"bytes_out"`
	}

	// 空结果必须是 []（同族列表端点与 OpenAPI 契约）——nil slice
	// 序列化为 null 会让客户端额外处理 null 形状。
	metrics := make([]MetricRow, 0)
	for rows.Next() {
		var m MetricRow
		var ts string
		if err := rows.Scan(&ts, &m.RequestsTotal, &m.Status2xx, &m.Status3xx,
			&m.Status4xx, &m.Status5xx, &m.BytesIn, &m.BytesOut); err != nil {
			c.JSON(http.StatusInternalServerError, models.APIResponse{Code: 500, Message: "读取指标历史失败: " + err.Error()})
			return
		}
		parsed, err := time.ParseInLocation("2006-01-02 15:04:05", ts, time.UTC)
		if err != nil {
			c.JSON(http.StatusInternalServerError, models.APIResponse{Code: 500, Message: "解析历史指标时间失败: " + err.Error()})
			return
		}
		m.Timestamp = parsed
		metrics = append(metrics, m)
	}

	if err := rows.Err(); err != nil {
		c.JSON(http.StatusInternalServerError, models.APIResponse{Code: 500, Message: "读取指标历史失败: " + err.Error()})
		return
	}

	c.JSON(http.StatusOK, models.APIResponse{Code: 0, Data: metrics})
}

func (h *Handlers) GetCaddyMetrics(c *gin.Context) {
	body, err := fetchCaddyMetrics(c.Request.Context(), h.cfg.CaddyMetricsURL)
	if err != nil {
		caddyMetricsError(c, err)
		return
	}
	metrics, err := parsePrometheusMetrics(string(body))
	if err != nil {
		caddyMetricsError(c, err)
		return
	}

	c.JSON(http.StatusOK, models.APIResponse{Code: 0, Data: metrics})
}

func (h *Handlers) GetHostMetrics(c *gin.Context) {
	body, err := fetchCaddyMetrics(c.Request.Context(), h.cfg.CaddyMetricsURL)
	if err != nil {
		caddyMetricsError(c, err)
		return
	}
	metrics, err := parseHostMetrics(string(body))
	if err != nil {
		caddyMetricsError(c, err)
		return
	}

	c.JSON(http.StatusOK, models.APIResponse{Code: 0, Data: metrics})
}

func loadRuleUpstreams(ruleID string) ([]models.Upstream, error) {
	rows, err := db.DB.Query(`
		SELECT COALESCE(id,0), COALESCE(rule_id,''), COALESCE(host,''), COALESCE(port,0), COALESCE(weight,0),
		       COALESCE(dynamic_dns,0), COALESCE(enabled,0), COALESCE(protocol,''),
		       COALESCE(max_connections,0)
		FROM upstreams WHERE rule_id = ? AND enabled = 1
	`, ruleID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var upstreams []models.Upstream
	for rows.Next() {
		var u models.Upstream
		if err := rows.Scan(&u.ID, &u.RuleID, &u.Host, &u.Port, &u.Weight, &u.DynamicDNS, &u.Enabled, &u.Protocol, &u.MaxConnections); err != nil {
			return nil, err
		}
		upstreams = append(upstreams, u)
	}
	return upstreams, rows.Err()
}
