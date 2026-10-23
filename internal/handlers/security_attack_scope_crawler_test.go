package handlers

// 攻击口径（爬虫放行不计入攻击）在全部消费面的钉测：分钟 rollup 固化、
// 旧口径固化行重固、大屏同屏维度、事件流/弹框、安全总览。
// 事件列表/审计面保持放行可见可查（口径只管「攻击面」取数）。

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/gin-gonic/gin"

	"lazy-balancer-v2/internal/config"
	"lazy-balancer-v2/internal/db"
	"lazy-balancer-v2/internal/models"
	"lazy-balancer-v2/internal/services"
)

// 爬虫放行族规则 id 取自编码公式（geoipCrawlerRuleBase+policyID*16+引擎序号）。
const (
	crawlerExemptRulePass = "810016" // policyID=1, engine 0
	crawlerExemptRuleLate = "810032" // policyID=2, engine 0
)

func newAttackScopeRouter(t *testing.T) *gin.Engine {
	t.Helper()
	fakeCaddy := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	t.Cleanup(fakeCaddy.Close)
	gin.SetMode(gin.TestMode)
	h := &Handlers{
		cfg:          &config.Config{CaddyMetricsURL: newThreatMetricsServer(t).URL},
		caddyService: services.NewCaddyService(fakeCaddy.URL),
	}
	router := gin.New()
	router.GET("/security/overview/threat-screen", h.GetSecurityThreatScreen)
	router.GET("/security/overview", h.GetSecurityOverview)
	router.GET("/security/events/feed", h.GetSecurityEventFeed)
	router.GET("/security/events/toast-summary", h.GetSecurityEventToastSummary)
	router.GET("/security/events", h.ListSecurityEvents)
	return router
}

// seedAttackScopeEvent 播种带规则归属的事件（目标维度 rollup 需要 rule_caddy_id）。
func seedAttackScopeEvent(t *testing.T, eventTime, clientIP, ruleTriggered, ruleMsg, action, ruleCaddyID string) {
	t.Helper()
	if _, err := db.MetricsDB.Exec(`INSERT INTO security_events (event_time, client_ip, method, uri, event_type, rule_triggered, rule_msg, action, rule_name, rule_caddy_id)
		VALUES (?, ?, 'GET', '/a', 'crs', ?, ?, ?, '测试规则', ?)`,
		eventTime, clientIP, ruleTriggered, ruleMsg, action, ruleCaddyID); err != nil {
		t.Fatalf("seed event: %v", err)
	}
}

// 分钟固化：爬虫放行的 logged 事件不入维度/目标两张 rollup，归因放行规则的
// blocked 事件仍计入（不隐藏真实拦截）；事件表原样保留。
func TestThreatRollup_excludesCrawlerExemptPassEvents(t *testing.T) {
	setupSecurityPolicyTestDB(t)
	installThreatClock(t, time.Date(2026, 10, 19, 12, 0, 30, 0, time.UTC))
	minuteStr := "2026-10-19 11:59"

	seedAttackScopeEvent(t, "2026-10-19 11:59:10", "93.184.216.7", crawlerExemptRulePass, "爬虫验证通过", "logged", "lb_scope")
	seedAttackScopeEvent(t, "2026-10-19 11:59:20", "93.184.216.8", crawlerExemptRuleLate, "爬虫验证通过", "blocked", "lb_scope")
	seedAttackScopeEvent(t, "2026-10-19 11:59:30", "93.184.216.9", "942100", "SQL Injection", "blocked", "lb_scope")

	if err := ensureThreatRollup(24); err != nil {
		t.Fatalf("ensure rollup: %v", err)
	}

	var loggedRows int
	if err := db.MetricsDB.QueryRow(`SELECT COUNT(*) FROM security_event_rollup WHERE minute=? AND action='logged'`, minuteStr).Scan(&loggedRows); err != nil {
		t.Fatal(err)
	}
	if loggedRows != 0 {
		t.Fatalf("维度 rollup logged 行=%d, want 0（爬虫放行不入攻击面）", loggedRows)
	}
	var blockedTotal int
	if err := db.MetricsDB.QueryRow(`SELECT COALESCE(SUM(count),0) FROM security_event_rollup WHERE minute=? AND action='blocked'`, minuteStr).Scan(&blockedTotal); err != nil {
		t.Fatal(err)
	}
	if blockedTotal != 2 {
		t.Fatalf("维度 rollup blocked 总量=%d, want 2（放行族被后续策略拦截仍计入）", blockedTotal)
	}
	var targetTotal int
	if err := db.MetricsDB.QueryRow(`SELECT COALESCE(SUM(count),0) FROM security_event_target_rollup WHERE minute=?`, minuteStr).Scan(&targetTotal); err != nil {
		t.Fatal(err)
	}
	if targetTotal != 2 {
		t.Fatalf("目标 rollup 总量=%d, want 2（放行行不得计入被攻击目标）", targetTotal)
	}
	var eventRows int
	if err := db.MetricsDB.QueryRow(`SELECT COUNT(*) FROM security_events`).Scan(&eventRows); err != nil {
		t.Fatal(err)
	}
	if eventRows != 3 {
		t.Fatalf("事件表行数=%d, want 3（原始事件仍完整保留）", eventRows)
	}
}

// 口径升级前的固化行（原始事件已被裁剪）在代际重固后必须被丢弃：谓词代际
// 从旧值触发重固，放行行不得继续计入，被裁剪的拦截历史必须保留。
func TestThreatRollup_rebuildDropsLegacyCrawlerExemptRows(t *testing.T) {
	setupSecurityPolicyTestDB(t)
	installThreatClock(t, time.Date(2026, 10, 19, 12, 0, 30, 0, time.UTC))
	minuteStr := "2026-10-19 11:59"

	// 旧口径固化行：放行族 logged 1 条 + 正常 blocked 2 条；原始事件已裁剪。
	if _, err := db.MetricsDB.Exec(`INSERT INTO security_event_rollup (minute, country, province, family, rule, action, count) VALUES
		(?, '', '', '其他', ?, 'logged', 1),
		(?, '', '', 'SQL注入', '942100', 'blocked', 2)`,
		minuteStr, crawlerExemptRulePass, minuteStr); err != nil {
		t.Fatalf("seed legacy rollup: %v", err)
	}
	if _, err := db.MetricsDB.Exec(`INSERT INTO security_event_target_rollup (minute, rule_caddy_id, count) VALUES (?, 'lb_scope', 2)`, minuteStr); err != nil {
		t.Fatalf("seed legacy target rollup: %v", err)
	}
	// 覆盖状态看似完整、谓词代际为旧值（=口径升级前固化）。
	if _, err := db.MetricsDB.Exec(`INSERT INTO metrics_state (key, value) VALUES
		(?, '2026-10-19 11:00'), (?, '2026-10-19 11:58'), (?, '2026-10-19 11:59'),
		(?, ?), (?, ?), (?, '1'), (?, ?)
		ON CONFLICT(key) DO UPDATE SET value=excluded.value`,
		threatRollupCoveredFromKey, threatRollupWatermarkKey, threatRollupTargetReadyKey,
		threatRollupGeoIPGenerationKey, strconv.FormatInt(services.GeoIPDataGeneration(), 10),
		threatRollupClassifierVersionKey, threatRollupClassifierVersion,
		threatRollupPredicateVersionKey,
		threatRollupActionEnumVersionKey, threatRollupActionEnumVersion); err != nil {
		t.Fatalf("seed rollup state: %v", err)
	}

	if err := ensureThreatRollup(1); err != nil {
		t.Fatalf("ensure rollup: %v", err)
	}

	var gen string
	if err := db.MetricsDB.QueryRow(`SELECT value FROM metrics_state WHERE key=?`, threatRollupPredicateVersionKey).Scan(&gen); err != nil {
		t.Fatal(err)
	}
	if gen != threatRollupPredicateVersion {
		t.Fatalf("谓词代际=%q, want %q（重固后回写当前口径）", gen, threatRollupPredicateVersion)
	}
	var loggedRows int
	if err := db.MetricsDB.QueryRow(`SELECT COUNT(*) FROM security_event_rollup WHERE minute=? AND action='logged'`, minuteStr).Scan(&loggedRows); err != nil {
		t.Fatal(err)
	}
	if loggedRows != 0 {
		t.Fatalf("旧口径放行行残留 %d 条, want 0", loggedRows)
	}
	var blockedTotal int
	if err := db.MetricsDB.QueryRow(`SELECT COALESCE(SUM(count),0) FROM security_event_rollup WHERE minute=? AND action='blocked'`, minuteStr).Scan(&blockedTotal); err != nil {
		t.Fatal(err)
	}
	if blockedTotal != 2 {
		t.Fatalf("被裁剪的拦截历史=%d, want 2（重固不得丢已裁剪历史）", blockedTotal)
	}
}

// 大屏同屏维度：总量/拦截率分母/攻击族/Top 规则/活跃源均不含爬虫放行。
func TestThreatScreen_attackScopeExcludesCrawlerExemptPassEvents(t *testing.T) {
	setupSecurityPolicyTestDB(t)
	t.Cleanup(resetThreatScreenCachesForTest)
	router := newAttackScopeRouter(t)
	seedAttackScopeEvent(t, utcStringAgo(3*time.Minute), "93.184.216.7", crawlerExemptRulePass, "爬虫验证通过", "logged", "lb_scope")
	seedAttackScopeEvent(t, utcStringAgo(2*time.Minute), "93.184.216.8", "942100", "SQL Injection", "blocked", "lb_scope")
	seedAttackScopeEvent(t, utcStringAgo(time.Minute), "93.184.216.9", "941100", "XSS", "logged", "lb_scope")

	recorder := getRequest(t, router, "/security/overview/threat-screen")
	if recorder.Code != http.StatusOK {
		t.Fatalf("status=%d body=%s", recorder.Code, recorder.Body.String())
	}
	var payload threatScreenPayload
	if err := json.Unmarshal(recorder.Body.Bytes(), &payload); err != nil {
		t.Fatal(err)
	}
	data := payload.Data
	if data.TotalEvents != 2 || data.BlockedEvents != 1 {
		t.Fatalf("total/blocked=(%d,%d), want (2,1)（放行不计入攻击面）", data.TotalEvents, data.BlockedEvents)
	}
	if data.ActiveSources != 2 {
		t.Fatalf("active_sources=%d, want 2（放行源不得计入活跃攻击源）", data.ActiveSources)
	}
	for _, entry := range data.TopAttackTypes {
		if strings.Contains(entry.Name, "爬虫") {
			t.Fatalf("top_attack_types 含放行族 %q", entry.Name)
		}
	}
	for _, entry := range data.TopRules {
		if strings.Contains(entry.Name, "爬虫") {
			t.Fatalf("top_rules 含放行规则 %q", entry.Name)
		}
	}
}

// 事件流/弹框：放行事件不进大屏 feed 与弹框摘要（游标照常推进），
// 事件列表仍完整可见（放行可查）。
func TestGetSecurityEventStreams_excludeCrawlerExemptPassEvents(t *testing.T) {
	setupSecurityPolicyTestDB(t)
	t.Cleanup(resetThreatScreenCachesForTest)
	router := newAttackScopeRouter(t)
	seedAttackScopeEvent(t, utcStringAgo(3*time.Minute), "93.184.216.7", crawlerExemptRulePass, "爬虫验证通过", "logged", "lb_scope")
	seedAttackScopeEvent(t, utcStringAgo(2*time.Minute), "93.184.216.8", "942100", "SQL Injection", "blocked", "lb_scope")
	seedAttackScopeEvent(t, utcStringAgo(time.Minute), "93.184.216.9", "941100", "XSS", "logged", "lb_scope")
	var maxID int64
	if err := db.MetricsDB.QueryRow(`SELECT MAX(id) FROM security_events`).Scan(&maxID); err != nil {
		t.Fatal(err)
	}

	// feed：首屏不含放行行，游标推进到本批最大 id。
	recorder := getRequest(t, router, "/security/events/feed?since_id=0&limit=50")
	if recorder.Code != http.StatusOK {
		t.Fatalf("feed status=%d body=%s", recorder.Code, recorder.Body.String())
	}
	var feed struct {
		Data struct {
			Events      []models.SecurityEventFeedItem `json:"events"`
			NextSinceID int64                          `json:"next_since_id"`
		} `json:"data"`
	}
	if err := json.Unmarshal(recorder.Body.Bytes(), &feed); err != nil {
		t.Fatal(err)
	}
	if len(feed.Data.Events) != 2 {
		t.Fatalf("feed 事件数=%d, want 2（放行行被跳过）", len(feed.Data.Events))
	}
	for _, event := range feed.Data.Events {
		if event.ClientIP == "93.184.216.7" {
			t.Fatalf("feed 含爬虫放行事件: %+v", event)
		}
	}
	if feed.Data.NextSinceID != maxID {
		t.Fatalf("next_since_id=%d, want %d（游标须照常推进）", feed.Data.NextSinceID, maxID)
	}

	// 弹框摘要：放行 IP 不得出现在分组里。
	recorder = getRequest(t, router, "/security/events/toast-summary?since_id=0&limit=20")
	if recorder.Code != http.StatusOK {
		t.Fatalf("toast status=%d body=%s", recorder.Code, recorder.Body.String())
	}
	var toast struct {
		Data struct {
			Groups []struct {
				ClientIP string `json:"client_ip"`
			} `json:"groups"`
		} `json:"data"`
	}
	if err := json.Unmarshal(recorder.Body.Bytes(), &toast); err != nil {
		t.Fatal(err)
	}
	if len(toast.Data.Groups) == 0 {
		t.Fatal("弹框摘要分组为空（应含 2 条攻击面事件）")
	}
	for _, group := range toast.Data.Groups {
		if group.ClientIP == "93.184.216.7" {
			t.Fatalf("弹框含爬虫放行分组: %+v", group)
		}
	}

	// 事件列表：放行行仍可见（口径只管攻击面取数，不隐藏事件）。
	recorder = getRequest(t, router, "/security/events?page=1&page_size=20")
	if recorder.Code != http.StatusOK {
		t.Fatalf("list status=%d body=%s", recorder.Code, recorder.Body.String())
	}
	var list struct {
		Data struct {
			Total int `json:"total"`
		} `json:"data"`
	}
	if err := json.Unmarshal(recorder.Body.Bytes(), &list); err != nil {
		t.Fatal(err)
	}
	if list.Data.Total != 3 {
		t.Fatalf("事件列表 total=%d, want 3（放行事件必须可查）", list.Data.Total)
	}
}

// 安全总览：今日拦截/检测、7 日趋势、Top IP、攻击类型均不含爬虫放行。
func TestSecurityOverview_attackScopeExcludesCrawlerExemptPassEvents(t *testing.T) {
	setupSecurityPolicyTestDB(t)
	t.Cleanup(resetSecurityOverviewAggCacheForTest)
	t.Cleanup(resetThreatScreenCachesForTest)
	router := newAttackScopeRouter(t)
	seedAttackScopeEvent(t, utcStringAgo(3*time.Minute), "93.184.216.7", crawlerExemptRulePass, "爬虫验证通过", "logged", "lb_scope")
	seedAttackScopeEvent(t, utcStringAgo(2*time.Minute), "93.184.216.8", "942100", "SQL Injection", "blocked", "lb_scope")

	recorder := getRequest(t, router, "/security/overview")
	if recorder.Code != http.StatusOK {
		t.Fatalf("status=%d body=%s", recorder.Code, recorder.Body.String())
	}
	var resp struct {
		Code int `json:"code"`
		Data struct {
			TodayBlocked  int                         `json:"today_blocked"`
			TodayDetected int                         `json:"today_detected"`
			Trend         []models.SecurityTrendPoint `json:"trend"`
			TopIPs        []models.SecurityTopIP      `json:"top_ips"`
			AttackTypes   []models.SecurityAttackType `json:"attack_types"`
		} `json:"data"`
	}
	if err := json.Unmarshal(recorder.Body.Bytes(), &resp); err != nil {
		t.Fatal(err)
	}
	if resp.Data.TodayBlocked != 1 || resp.Data.TodayDetected != 0 {
		t.Fatalf("today=(%d,%d), want (1,0)（放行不计入检测数）", resp.Data.TodayBlocked, resp.Data.TodayDetected)
	}
	if len(resp.Data.Trend) == 0 {
		t.Fatal("trend 为空")
	}
	today := resp.Data.Trend[len(resp.Data.Trend)-1]
	if today.Blocked != 1 || today.Detected != 0 {
		t.Fatalf("趋势今日=(%d,%d), want (1,0)", today.Blocked, today.Detected)
	}
	if len(resp.Data.TopIPs) != 1 || resp.Data.TopIPs[0].IP != "93.184.216.8" {
		t.Fatalf("top_ips=%+v, want 仅 93.184.216.8（放行源不计入）", resp.Data.TopIPs)
	}
	for _, entry := range resp.Data.AttackTypes {
		if strings.Contains(entry.Name, "爬虫") {
			t.Fatalf("attack_types 含放行族 %q", entry.Name)
		}
	}
}
