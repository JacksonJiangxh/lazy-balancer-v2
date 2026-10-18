package handlers

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/gin-gonic/gin"

	"lazy-balancer-v2/internal/config"
	"lazy-balancer-v2/internal/db"
	"lazy-balancer-v2/internal/models"
	"lazy-balancer-v2/internal/services"
)

// 威胁大屏（threat-screen）端点钉测：聚合形状（国家计数 map/总量/拦截率/
// Top5）与 feed 游标（since_id 递增无重无漏）。两端点均为只读、不挂
// requireMaster（从节点可读，与大屏展示场景一致）。

func newThreatScreenRouter(t *testing.T, metricsURL string) *gin.Engine {
	t.Helper()
	gin.SetMode(gin.TestMode)
	h := &Handlers{cfg: &config.Config{CaddyMetricsURL: metricsURL}}
	router := gin.New()
	router.GET("/security/overview/threat-screen", h.GetSecurityThreatScreen)
	router.GET("/security/events/feed", h.GetSecurityEventFeed)
	return router
}

func newThreatMetricsServer(t *testing.T) *httptest.Server {
	t.Helper()
	metrics := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(rateLimitBlocksMetricsFixture))
	}))
	t.Cleanup(metrics.Close)
	return metrics
}

func seedThreatScreenEvent(t *testing.T, eventTime, clientIP, ruleTriggered, ruleMsg, action string) {
	t.Helper()
	if _, err := db.MetricsDB.Exec(`INSERT INTO security_events (event_time, client_ip, method, uri, event_type, rule_triggered, rule_msg, action, rule_name)
		VALUES (?, ?, 'GET', '/a', 'crs', ?, ?, ?, '测试规则')`,
		eventTime, clientIP, ruleTriggered, ruleMsg, action); err != nil {
		t.Fatalf("seed event: %v", err)
	}
}

func utcStringAgo(d time.Duration) string {
	return time.Now().UTC().Add(-d).Truncate(time.Second).Format("2006-01-02 15:04:05")
}

type threatScreenPayload struct {
	Code int `json:"code"`
	Data struct {
		Hours           int                         `json:"hours"`
		WindowStart     string                      `json:"window_start"`
		TotalEvents     int                         `json:"total_events"`
		BlockedEvents   int                         `json:"blocked_events"`
		BlockRate       float64                     `json:"block_rate"`
		RatelimitBlocks float64                     `json:"ratelimit_blocks"`
		ActiveSources   int                         `json:"active_sources"`
		Countries       map[string]int              `json:"countries"`
		ChinaProvinces  map[string]int              `json:"china_provinces"`
		TopCountries    []models.SecurityAttackType `json:"top_countries"`
		TopAttackTypes  []models.SecurityAttackType `json:"top_attack_types"`
		TopRules        []models.SecurityAttackType `json:"top_rules"`
		HourlyHist      []models.SecurityAttackType `json:"hourly_hist"`
		AttackTypeShare []models.SecurityAttackType `json:"attack_type_share"`
		RecentRate      float64                     `json:"recent_rate"`
		// v2.4.x 大屏加固：logged=total-blocked（夹 >=0）、限流可用性位、
		// 被攻击目标 Top5（name/domain/value）
		LoggedEvents       int  `json:"logged_events"`
		RatelimitAvailable bool `json:"ratelimit_available"`
		TopTargets         []struct {
			Name   string `json:"name"`
			Domain string `json:"domain"`
			Value  int    `json:"value"`
		} `json:"top_targets"`
	} `json:"data"`
}

func TestGetSecurityThreatScreen_reservedIPsExcludedEverywhere(t *testing.T) {
	// Given: 公网与保留/私网事件并存（::1 回环、192.168.x、10.x 私网）
	setupSecurityPolicyTestDB(t)
	router := newThreatScreenRouter(t, newThreatMetricsServer(t).URL)
	// 公网：2 blocked + 1 logged，两个 IP（其一在活跃窗）
	seedThreatScreenEvent(t, utcStringAgo(10*time.Minute), "203.0.113.7", "942100", "SQL Injection", "blocked")
	seedThreatScreenEvent(t, utcStringAgo(9*time.Minute), "203.0.113.7", "942100", "SQL Injection", "blocked")
	seedThreatScreenEvent(t, utcStringAgo(8*time.Minute), "198.51.100.5", "941100", "XSS", "logged")
	// 保留/私网：3 条（不计总量/拦截/活跃源/国家/攻击族）
	seedThreatScreenEvent(t, utcStringAgo(7*time.Minute), "192.168.1.5", "942100", "SQL Injection", "blocked")
	seedThreatScreenEvent(t, utcStringAgo(6*time.Minute), "10.0.0.8", "941100", "XSS", "blocked")
	seedThreatScreenEvent(t, utcStringAgo(5*time.Minute), "::1", "932100", "RCE", "blocked")

	// When
	recorder := getRequest(t, router, "/security/overview/threat-screen")

	// Then: 全部统计口径一致排除保留地址（大屏不展示内网噪声，v4 裁定）
	if recorder.Code != http.StatusOK {
		t.Fatalf("status=%d body=%s", recorder.Code, recorder.Body.String())
	}
	var payload threatScreenPayload
	if err := json.Unmarshal(recorder.Body.Bytes(), &payload); err != nil {
		t.Fatal(err)
	}
	if payload.Data.TotalEvents != 3 {
		t.Errorf("total_events=%d, want 3（保留地址不计）", payload.Data.TotalEvents)
	}
	if payload.Data.BlockedEvents != 2 {
		t.Errorf("blocked_events=%d, want 2", payload.Data.BlockedEvents)
	}
	// 2/3 → 66.7%
	if payload.Data.BlockRate < 66.6 || payload.Data.BlockRate > 66.8 {
		t.Errorf("block_rate=%v, want 66.7", payload.Data.BlockRate)
	}
	if payload.Data.ActiveSources != 2 {
		t.Errorf("active_sources=%d, want 2（私网 IP 不是活跃攻击源）", payload.Data.ActiveSources)
	}
	if payload.Data.TopAttackTypes[0].Name != "SQL注入" || payload.Data.TopAttackTypes[0].Value != 2 {
		t.Errorf("top_attack_types[0]=%+v, want {SQL注入 2}（私网事件不计入攻击族）", payload.Data.TopAttackTypes[0])
	}
}

func TestGetSecurityEventFeed_reservedIPsFiltered(t *testing.T) {
	// Given: 公网与保留事件交错落库
	setupSecurityPolicyTestDB(t)
	router := newThreatScreenRouter(t, newThreatMetricsServer(t).URL)
	seedThreatScreenEvent(t, utcStringAgo(3*time.Second), "203.0.113.7", "942100", "SQL Injection", "blocked")
	seedThreatScreenEvent(t, utcStringAgo(2*time.Second), "192.168.1.5", "941100", "XSS", "blocked")
	seedThreatScreenEvent(t, utcStringAgo(1*time.Second), "203.0.113.9", "941100", "XSS", "logged")

	// When
	recorder := getRequest(t, router, "/security/events/feed")

	// Then: 保留地址事件不出现在事件流（游标语义不变——公网事件无重无漏）
	if recorder.Code != http.StatusOK {
		t.Fatalf("status=%d body=%s", recorder.Code, recorder.Body.String())
	}
	var payload feedPayload
	if err := json.Unmarshal(recorder.Body.Bytes(), &payload); err != nil {
		t.Fatal(err)
	}
	if len(payload.Data.Events) != 2 {
		t.Fatalf("events=%d, want 2（192.168.1.5 被过滤）", len(payload.Data.Events))
	}
	for _, ev := range payload.Data.Events {
		if ev.ClientIP == "192.168.1.5" {
			t.Fatalf("保留地址事件泄漏到事件流: %+v", ev)
		}
	}
}

func TestGetSecurityThreatScreen_aggregateShape(t *testing.T) {
	// Given: 近 24h 六条事件（4 blocked + 1 logged + 1 跨越 24h 窗口的旧事件），
	// 其中两条落在近 10 分钟活跃窗内；Caddy metrics 提供 429 计数 12。
	setupSecurityPolicyTestDB(t)
	router := newThreatScreenRouter(t, newThreatMetricsServer(t).URL)

	seedThreatScreenEvent(t, utcStringAgo(time.Hour), "203.0.113.7", "942100", "SQL Injection", "blocked")
	seedThreatScreenEvent(t, utcStringAgo(2*time.Hour), "203.0.113.7", "942100", "SQL Injection", "blocked")
	seedThreatScreenEvent(t, utcStringAgo(30*time.Minute), "198.51.100.5", "941100", "XSS", "logged")
	seedThreatScreenEvent(t, utcStringAgo(20*time.Minute), "198.51.100.5", "941100", "XSS", "blocked")
	seedThreatScreenEvent(t, utcStringAgo(5*time.Minute), "192.0.2.9", "942100", "SQL Injection", "blocked")
	seedThreatScreenEvent(t, utcStringAgo(8*time.Minute), "198.51.100.6", "932100", "RCE", "blocked")
	seedThreatScreenEvent(t, utcStringAgo(49*time.Hour), "203.0.113.7", "942100", "SQL Injection", "blocked")

	// When
	recorder := getRequest(t, router, "/security/overview/threat-screen")

	// Then: 窗口计数/拦截率/限流计数/活跃源/Top5 形状完整，49h 旧事件被窗口排除
	if recorder.Code != http.StatusOK {
		t.Fatalf("status=%d body=%s", recorder.Code, recorder.Body.String())
	}
	var payload threatScreenPayload
	if err := json.Unmarshal(recorder.Body.Bytes(), &payload); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if payload.Code != 0 {
		t.Fatalf("code=%d body=%s", payload.Code, recorder.Body.String())
	}
	if payload.Data.Hours != 24 {
		t.Errorf("hours=%d, want 24 (default)", payload.Data.Hours)
	}
	if payload.Data.TotalEvents != 6 {
		t.Errorf("total_events=%d, want 6 (49h old event excluded)", payload.Data.TotalEvents)
	}
	if payload.Data.BlockedEvents != 5 {
		t.Errorf("blocked_events=%d, want 5", payload.Data.BlockedEvents)
	}
	// 5/6 → 83.3%（一位小数）
	if payload.Data.BlockRate < 83.3 || payload.Data.BlockRate > 83.4 {
		t.Errorf("block_rate=%v, want 83.3", payload.Data.BlockRate)
	}
	// Caddy metrics fixture 总计 = 12
	if payload.Data.RatelimitBlocks != 12 {
		t.Errorf("ratelimit_blocks=%v, want 12 (Caddy metrics 429 total)", payload.Data.RatelimitBlocks)
	}
	// 限流可用性位：metrics 正常抓取 → true
	if !payload.Data.RatelimitAvailable {
		t.Errorf("ratelimit_available=false, want true（metrics 可达）")
	}
	// logged_events = total - blocked = 6-5 = 1
	if payload.Data.LoggedEvents != 1 {
		t.Errorf("logged_events=%d, want 1（total 6 - blocked 5）", payload.Data.LoggedEvents)
	}
	// 活跃源 = 近 10min 去重 client_ip：192.0.2.9 与 198.51.100.6
	if payload.Data.ActiveSources != 2 {
		t.Errorf("active_sources=%d, want 2", payload.Data.ActiveSources)
	}
	// 无 xdb：归属地全空 → 国家 map 为空对象（非 null），不报错
	if payload.Data.Countries == nil {
		t.Errorf("countries=%v, want empty map (no xdb in tests)", payload.Data.Countries)
	}
	// 国内省份计数 map 同形状常驻（无 xdb 时空对象，前端省级视图消费）
	if payload.Data.ChinaProvinces == nil {
		t.Errorf("china_provinces=%v, want empty map (no xdb in tests)", payload.Data.ChinaProvinces)
	}
	if len(payload.Data.TopCountries) != 0 {
		t.Errorf("top_countries=%+v, want empty without xdb", payload.Data.TopCountries)
	}
	// Top 攻击类型：categorizeAttack 家族单源——942100→SQL注入 ×3 居首，
	// 941100→XSS ×2 次之，932100→命令注入 ×1 第三
	if len(payload.Data.TopAttackTypes) != 3 {
		t.Fatalf("top_attack_types=%+v, want 3 families", payload.Data.TopAttackTypes)
	}
	if payload.Data.TopAttackTypes[0].Name != "SQL注入" || payload.Data.TopAttackTypes[0].Value != 3 {
		t.Errorf("top_attack_types[0]=%+v, want {SQL注入 3}", payload.Data.TopAttackTypes[0])
	}
	if payload.Data.TopAttackTypes[1].Name != "XSS" || payload.Data.TopAttackTypes[1].Value != 2 {
		t.Errorf("top_attack_types[1]=%+v, want {XSS 2}", payload.Data.TopAttackTypes[1])
	}
	if payload.Data.TopAttackTypes[2].Name != "命令注入" || payload.Data.TopAttackTypes[2].Value != 1 {
		t.Errorf("top_attack_types[2]=%+v, want {命令注入 1}", payload.Data.TopAttackTypes[2])
	}
}

func TestGetSecurityThreatScreen_hoursParam(t *testing.T) {
	// Given: 一条 2h 前事件
	setupSecurityPolicyTestDB(t)
	router := newThreatScreenRouter(t, newThreatMetricsServer(t).URL)
	seedThreatScreenEvent(t, utcStringAgo(2*time.Hour), "203.0.113.7", "942100", "SQL Injection", "blocked")

	// When/Then: hours=1 → 事件在窗外；缺省 → 计入；hours 非法/越界 → 回退默认 24
	if recorder := getRequest(t, router, "/security/overview/threat-screen?hours=1"); recorder.Code != http.StatusOK {
		t.Fatalf("hours=1 status=%d", recorder.Code)
	} else {
		var payload threatScreenPayload
		_ = json.Unmarshal(recorder.Body.Bytes(), &payload)
		if payload.Data.TotalEvents != 0 {
			t.Errorf("hours=1 total_events=%d, want 0", payload.Data.TotalEvents)
		}
		if payload.Data.Hours != 1 {
			t.Errorf("hours echo=%d, want 1", payload.Data.Hours)
		}
	}
	if recorder := getRequest(t, router, "/security/overview/threat-screen"); recorder.Code != http.StatusOK {
		t.Fatalf("default status=%d", recorder.Code)
	} else {
		var payload threatScreenPayload
		_ = json.Unmarshal(recorder.Body.Bytes(), &payload)
		if payload.Data.TotalEvents != 1 {
			t.Errorf("default total_events=%d, want 1", payload.Data.TotalEvents)
		}
	}
	for _, raw := range []string{"?hours=abc", "?hours=0", "?hours=-5", "?hours=99999"} {
		recorder := getRequest(t, router, "/security/overview/threat-screen"+raw)
		if recorder.Code != http.StatusOK {
			t.Fatalf("%s status=%d body=%s", raw, recorder.Code, recorder.Body.String())
		}
		var payload threatScreenPayload
		_ = json.Unmarshal(recorder.Body.Bytes(), &payload)
		if payload.Data.Hours != 24 {
			t.Errorf("%s hours=%d, want fallback 24", raw, payload.Data.Hours)
		}
	}
}

func TestGetSecurityThreatScreen_metricsScrapeFailureDegrades(t *testing.T) {
	// Given: Caddy metrics 不可达 + 窗口内 1 条事件
	setupSecurityPolicyTestDB(t)
	router := newThreatScreenRouter(t, "http://127.0.0.1:1/metrics")
	seedThreatScreenEvent(t, utcStringAgo(time.Hour), "203.0.113.7", "942100", "SQL Injection", "blocked")

	// When/Then: 不再整卡 500——ratelimit_blocks=0、ratelimit_available=false，
	// 其余维度照常 200（大屏 30s 轮询容忍限流指标瞬时不可达，可用性位披露）
	recorder := getRequest(t, router, "/security/overview/threat-screen")
	if recorder.Code != http.StatusOK {
		t.Fatalf("status=%d body=%s, want 200 降级", recorder.Code, recorder.Body.String())
	}
	var payload threatScreenPayload
	if err := json.Unmarshal(recorder.Body.Bytes(), &payload); err != nil {
		t.Fatal(err)
	}
	if payload.Data.RatelimitAvailable || payload.Data.RatelimitBlocks != 0 {
		t.Fatalf("ratelimit_available=%v ratelimit_blocks=%v, want false/0", payload.Data.RatelimitAvailable, payload.Data.RatelimitBlocks)
	}
	if payload.Data.TotalEvents != 1 || payload.Data.BlockedEvents != 1 {
		t.Fatalf("total=%d blocked=%d, want 1/1（其余维度照常）", payload.Data.TotalEvents, payload.Data.BlockedEvents)
	}
}

func TestGetSecurityThreatScreen_metricsDBNilReturnsZeroShape(t *testing.T) {
	// Given: MetricsDB 未装配（历史问题 家族口径）
	setupSecurityPolicyTestDB(t)
	saved := db.MetricsDB
	db.MetricsDB = nil
	t.Cleanup(func() { db.MetricsDB = saved })
	router := newThreatScreenRouter(t, newThreatMetricsServer(t).URL)

	// When/Then: 200 零值形状而非 panic
	recorder := getRequest(t, router, "/security/overview/threat-screen")
	if recorder.Code != http.StatusOK {
		t.Fatalf("status=%d body=%s", recorder.Code, recorder.Body.String())
	}
	var payload threatScreenPayload
	if err := json.Unmarshal(recorder.Body.Bytes(), &payload); err != nil {
		t.Fatal(err)
	}
	if payload.Data.TotalEvents != 0 || payload.Data.ActiveSources != 0 || payload.Data.Countries == nil || payload.Data.ChinaProvinces == nil {
		t.Fatalf("零值形状应完整: %+v", payload.Data)
	}
	var raw struct {
		Data map[string]json.RawMessage `json:"data"`
	}
	if err := json.Unmarshal(recorder.Body.Bytes(), &raw); err != nil {
		t.Fatal(err)
	}
	for _, key := range []string{"rollup_ready", "rollup_stale", "rollup_last_success", "logged_events", "ratelimit_available", "top_rules", "top_targets", "hourly_hist", "attack_type_share", "recent_rate"} {
		if _, ok := raw.Data[key]; !ok {
			t.Fatalf("zero response missing key %q: %s", key, recorder.Body.String())
		}
	}
}

func TestGetSecurityThreatScreen_histogramKeepsPreBucketPrefix(t *testing.T) {
	setupSecurityPolicyTestDB(t)
	base := time.Date(2026, 10, 18, 12, 30, 0, 0, time.UTC)
	installThreatClock(t, base)
	seedThreatScreenEvent(t, "2026-10-16 14:00:10", "203.0.113.7", "942100", "SQL Injection", "blocked")
	router := newThreatScreenRouter(t, newThreatMetricsServer(t).URL)
	var payload threatScreenR79Payload
	for range 3 {
		payload = getThreatScreenR79(t, router, "/security/overview/threat-screen?hours=48")
		if payload.Data.TotalEvents == 1 {
			break
		}
	}
	if payload.Data.TotalEvents != 1 {
		t.Fatalf("total_events=%d, want 1", payload.Data.TotalEvents)
	}
	var raw struct {
		Data struct {
			Hourly []struct {
				Value int `json:"value"`
			} `json:"hourly_hist"`
		} `json:"data"`
	}
	if err := json.Unmarshal(getRequest(t, router, "/security/overview/threat-screen?hours=48").Body.Bytes(), &raw); err != nil {
		t.Fatal(err)
	}
	sum := 0
	for _, bucket := range raw.Data.Hourly {
		sum += bucket.Value
	}
	if sum != payload.Data.TotalEvents {
		t.Fatalf("hourly sum=%d, want total_events=%d (oldest bucket absorbs prefix)", sum, payload.Data.TotalEvents)
	}
}

func TestTopThreatEntries_sortedDescWithStableTiebreak(t *testing.T) {
	// Given: 同计数并列（XSS=SQL注入=2）
	counts := map[string]int{"SQL注入": 2, "XSS": 2, "文件包含": 5}

	// When
	entries := topThreatEntries(counts, 5)

	// Then: 计数降序；同计数按名称升序（确定性输出，前端轮询渲染不抖动）
	if len(entries) != 3 {
		t.Fatalf("entries=%+v, want 3", entries)
	}
	if entries[0].Name != "文件包含" || entries[0].Value != 5 {
		t.Errorf("entries[0]=%+v, want {文件包含 5}", entries[0])
	}
	if entries[1].Name != "SQL注入" || entries[2].Name != "XSS" {
		t.Errorf("tie order=%+v, want SQL注入 before XSS (byte-asc: 'S'<'X')", entries)
	}

	// Top5 截断：7 项取前 5
	big := map[string]int{"a": 7, "b": 6, "c": 5, "d": 4, "e": 3, "f": 2, "g": 1}
	if got := topThreatEntries(big, 5); len(got) != 5 || got[0].Name != "a" || got[4].Name != "e" {
		t.Fatalf("top5=%+v, want a..e", got)
	}
}

type feedPayload struct {
	Code int `json:"code"`
	Data struct {
		Events []struct {
			ID         int    `json:"id"`
			EventTime  string `json:"event_time"`
			ClientIP   string `json:"client_ip"`
			IPLocation string `json:"ip_location"`
			Action     string `json:"action"`
			RuleName   string `json:"rule_name"`
			AttackType string `json:"attack_type"`
		} `json:"events"`
		SinceID     int   `json:"since_id"`
		NextSinceID int64 `json:"next_since_id"`
		Limit       int   `json:"limit"`
		HasMore     bool  `json:"has_more"`
	} `json:"data"`
}

// 大屏事件流升序无漏语义：since_id=0 首屏返回最新 limit 条（响应仍按 id
// 升序，next_since_id=返回集最大 id，has_more=false——首屏不回溯更老）；
// since_id>0 增量升序、>limit 积压分多次拉取无重无漏，has_more 披露
// 「本页填满且可能还有更新未返回」。
func TestGetSecurityEventFeed_ascendingNoLossAndFirstScreenLatest(t *testing.T) {
	// Given: 210 条事件（超过单页 clamp 上限 200）
	setupSecurityPolicyTestDB(t)
	router := newThreatScreenRouter(t, newThreatMetricsServer(t).URL)
	base := time.Now().UTC().Add(-24 * time.Hour)
	for i := range 210 {
		ts := base.Add(time.Duration(i) * time.Second).Format("2006-01-02 15:04:05")
		triggered, msg := "942100", "SQL Injection"
		if i == 0 {
			triggered, msg = "941100", "XSS"
		}
		seedThreatScreenEvent(t, ts, fmt.Sprintf("203.0.113.%d", i%200+1), triggered, msg, "blocked")
	}

	fetch := func(query string) feedPayload {
		recorder := getRequest(t, router, "/security/events/feed"+query)
		if recorder.Code != http.StatusOK {
			t.Fatalf("feed status=%d body=%s", recorder.Code, recorder.Body.String())
		}
		var payload feedPayload
		if err := json.Unmarshal(recorder.Body.Bytes(), &payload); err != nil {
			t.Fatalf("decode: %v", err)
		}
		prev := -1
		for _, ev := range payload.Data.Events {
			if ev.ID <= prev {
				t.Fatalf("feed not id-ascending: %v after %v", ev.ID, prev)
			}
			prev = ev.ID
			if ev.ClientIP == "" || ev.Action != "blocked" || ev.EventTime == "" || ev.RuleName != "测试规则" {
				t.Fatalf("feed event missing enrichment fields: %+v", ev)
			}
		}
		return payload
	}

	// 首屏（since_id=0, limit=200）：最新 200 条（ids 11..210）升序，
	// next_since_id=210、has_more=false（不回溯更老的 ids 1..10）
	first := fetch("?since_id=0&limit=200")
	if len(first.Data.Events) != 200 || first.Data.Limit != 200 {
		t.Fatalf("first screen: %d events (limit=%d), want 200/200", len(first.Data.Events), first.Data.Limit)
	}
	if first.Data.Events[0].ID != 11 || first.Data.Events[199].ID != 210 {
		t.Fatalf("first screen ids [%d..%d], want [11..210]（最新 200 条）", first.Data.Events[0].ID, first.Data.Events[199].ID)
	}
	if first.Data.NextSinceID != 210 || first.Data.HasMore {
		t.Fatalf("first screen next_since_id=%d has_more=%v, want 210/false", first.Data.NextSinceID, first.Data.HasMore)
	}

	// 积压消费（since_id=1, limit=100）：209 条分三拉无重无漏
	seen := map[int]bool{}
	pull := func(since int64, wantN int, wantHasMore bool) feedPayload {
		p := fetch(fmt.Sprintf("?since_id=%d&limit=100", since))
		if len(p.Data.Events) != wantN {
			t.Fatalf("pull since=%d: %d events, want %d", since, len(p.Data.Events), wantN)
		}
		if p.Data.HasMore != wantHasMore {
			t.Fatalf("pull since=%d: has_more=%v, want %v", since, p.Data.HasMore, wantHasMore)
		}
		for _, ev := range p.Data.Events {
			if seen[ev.ID] {
				t.Fatalf("duplicate id %d across pulls", ev.ID)
			}
			seen[ev.ID] = true
			if int64(ev.ID) <= since {
				t.Fatalf("event id %d <= cursor %d（重复消费已见 id）", ev.ID, since)
			}
		}
		return p
	}
	p1 := pull(1, 100, true)
	if p1.Data.NextSinceID != 101 {
		t.Fatalf("pull1 next_since_id=%d, want 101（本批实际扫描最大 id）", p1.Data.NextSinceID)
	}
	p2 := pull(p1.Data.NextSinceID, 100, true)
	p3 := pull(p2.Data.NextSinceID, 9, false)
	if p3.Data.NextSinceID != 210 {
		t.Fatalf("pull3 next_since_id=%d, want 210", p3.Data.NextSinceID)
	}
	if len(seen) != 209 {
		t.Fatalf("unique ids=%d, want 209（ids 2..210 无重无漏）", len(seen))
	}

	// 游标之后新落库的事件全部被增量拉到（无漏）
	for i := range 3 {
		seedThreatScreenEvent(t, utcStringAgo(0), fmt.Sprintf("198.51.100.%d", i+1), "930100", "LFI", "blocked")
	}
	inc := fetch("?since_id=210&limit=100")
	if len(inc.Data.Events) != 3 || inc.Data.HasMore {
		t.Fatalf("incremental=%d events has_more=%v, want 3/false", len(inc.Data.Events), inc.Data.HasMore)
	}

	// 家族归因单源：首屏最新 200 条（3 条 LFI 落库后 = ids 14..213：
	// XSS 事件 id=1 在窗外）——942100→SQL注入 ×197、无 XSS
	recorder := getRequest(t, router, "/security/events/feed?limit=200")
	var full feedPayload
	_ = json.Unmarshal(recorder.Body.Bytes(), &full)
	sqlCount, xssCount := 0, 0
	for _, ev := range full.Data.Events {
		switch ev.AttackType {
		case "SQL注入":
			sqlCount++
		case "XSS":
			xssCount++
		}
	}
	if sqlCount != 197 || xssCount != 0 {
		t.Fatalf("attack_type attribution=%d/%d, want 197/0", sqlCount, xssCount)
	}
}

func TestGetSecurityEventFeed_defaultsAndNewEventsAfterCursor(t *testing.T) {
	// Given: 3 条事件
	setupSecurityPolicyTestDB(t)
	router := newThreatScreenRouter(t, newThreatMetricsServer(t).URL)
	seedThreatScreenEvent(t, utcStringAgo(3*time.Second), "203.0.113.7", "942100", "SQL Injection", "blocked")
	seedThreatScreenEvent(t, utcStringAgo(2*time.Second), "203.0.113.8", "941100", "XSS", "logged")
	seedThreatScreenEvent(t, utcStringAgo(1*time.Second), "203.0.113.9", "942100", "SQL Injection", "blocked")

	// When/Then: 缺省 since_id=0/limit=50 → 全量返回
	recorder := getRequest(t, router, "/security/events/feed")
	if recorder.Code != http.StatusOK {
		t.Fatalf("status=%d body=%s", recorder.Code, recorder.Body.String())
	}
	var payload feedPayload
	if err := json.Unmarshal(recorder.Body.Bytes(), &payload); err != nil {
		t.Fatal(err)
	}
	if len(payload.Data.Events) != 3 || payload.Data.SinceID != 0 || payload.Data.Limit != 50 {
		t.Fatalf("defaults: %+v", payload.Data)
	}
	// 升序：末条即最大 id；首屏 has_more=false
	if payload.Data.HasMore {
		t.Fatalf("first screen has_more=true, want false")
	}
	maxID := payload.Data.Events[len(payload.Data.Events)-1].ID
	if int64(maxID) != payload.Data.NextSinceID {
		t.Fatalf("next_since_id=%d, want %d（返回集最大 id）", payload.Data.NextSinceID, maxID)
	}

	// 游标之后新落库的事件可被增量拉到（不重不漏的增量语义）
	seedThreatScreenEvent(t, utcStringAgo(0), "203.0.113.10", "930100", "LFI", "blocked")
	recorder = getRequest(t, router, fmt.Sprintf("/security/events/feed?since_id=%d", maxID))
	if err := json.Unmarshal(recorder.Body.Bytes(), &payload); err != nil {
		t.Fatal(err)
	}
	if len(payload.Data.Events) != 1 || payload.Data.Events[0].ID <= maxID {
		t.Fatalf("incremental fetch=%+v, want exactly the new event", payload.Data.Events)
	}
}

func TestGetSecurityEventFeed_metricsDBNilReturnsEmptyList(t *testing.T) {
	// Given: MetricsDB 未装配（历史问题 家族口径，键形状与成功路径一致）
	setupSecurityPolicyTestDB(t)
	saved := db.MetricsDB
	db.MetricsDB = nil
	t.Cleanup(func() { db.MetricsDB = saved })
	router := newThreatScreenRouter(t, newThreatMetricsServer(t).URL)

	// When/Then
	recorder := getRequest(t, router, "/security/events/feed")
	if recorder.Code != http.StatusOK {
		t.Fatalf("status=%d body=%s", recorder.Code, recorder.Body.String())
	}
	if !strings.Contains(recorder.Body.String(), `"events":[]`) {
		t.Fatalf("body=%s, want empty events list", recorder.Body.String())
	}
}

func TestGetSecurityThreatScreen_contentCards(t *testing.T) {
	// Given: 公网与保留事件并存（内容卡三件套 = top_rules/hourly_hist/
	// attack_type_share 与 recent_rate，v7 右列扩展；保留地址全口径排除）
	setupSecurityPolicyTestDB(t)
	router := newThreatScreenRouter(t, newThreatMetricsServer(t).URL)
	// 3×rule_name「SQL注入检测」（blocked）+ 1×rule_name 空（回退 rule_triggered）
	seedRuleNamed := func(minutes int, ip, ruleName string) {
		if _, err := db.MetricsDB.Exec(`INSERT INTO security_events (event_time, client_ip, method, uri, event_type, rule_triggered, rule_msg, action, rule_name)
			VALUES (?, ?, 'GET', '/a', 'crs', '942100', 'SQL 注入攻击头', 'blocked', ?)`,
			utcStringAgo(time.Duration(minutes)*time.Minute), ip, ruleName); err != nil {
			t.Fatalf("seed rule-named event: %v", err)
		}
	}
	seedRuleNamed(30, "203.0.113.7", "SQL注入检测")
	seedRuleNamed(29, "203.0.113.7", "SQL注入检测")
	seedRuleNamed(28, "198.51.100.5", "SQL注入检测")
	// rule_name 空行：rule_triggered=2 黑名单（空名回退 rule_triggered 形态）
	if _, err := db.MetricsDB.Exec(`INSERT INTO security_events (event_time, client_ip, method, uri, event_type, rule_triggered, rule_msg, action, rule_name)
		VALUES (?, '203.0.113.9', 'GET', '/a', 'stage1', '2', 'IP 黑名单命中', 'blocked', '')`,
		utcStringAgo(27*time.Minute)); err != nil {
		t.Fatalf("seed empty-name event: %v", err)
	}
	// 保留地址：不计入任何内容卡
	seedRuleNamed(26, "192.168.1.5", "SQL注入检测")

	// When
	recorder := getRequest(t, router, "/security/overview/threat-screen")
	if recorder.Code != http.StatusOK {
		t.Fatalf("status=%d body=%s", recorder.Code, recorder.Body.String())
	}
	var payload threatScreenPayload
	if err := json.Unmarshal(recorder.Body.Bytes(), &payload); err != nil {
		t.Fatal(err)
	}

	// Then: top_rules——rule_name 优先、空名回退 rule_triggered，保留地址排除
	if len(payload.Data.TopRules) != 2 {
		t.Fatalf("top_rules=%+v, want 2 项（SQL注入检测 ×3 + 回退规则 2）", payload.Data.TopRules)
	}
	if payload.Data.TopRules[0].Name != "SQL注入检测" || payload.Data.TopRules[0].Value != 3 {
		t.Errorf("top_rules[0]=%+v, want {SQL注入检测 3}", payload.Data.TopRules[0])
	}
	if payload.Data.TopRules[1].Name != "2" || payload.Data.TopRules[1].Value != 1 {
		t.Errorf("top_rules[1]=%+v, want {2 1}（rule_name 空回退 rule_triggered）", payload.Data.TopRules[1])
	}

	// hourly_hist：恒 24 槽（hour 0-23 升序），命中槽计数、空槽零填；
	// 时区按配置时区偏移（默认 Asia/Shanghai +8）
	if len(payload.Data.HourlyHist) != 24 {
		t.Fatalf("hourly_hist=%d 槽, want 24", len(payload.Data.HourlyHist))
	}
	// 时区换算由 tzModifier 与 GetSecurityOverview 同源；种子全在近 24h
	// 同一小时簇内，按总量断言（具体槽位随时钟漂移不稳定）
	total := 0
	for _, slot := range payload.Data.HourlyHist {
		if slot.Value < 0 {
			t.Errorf("负计数槽: %+v", slot)
		}
		total += slot.Value
	}
	if total != 4 {
		t.Errorf("hourly 总计=%d, want 4（保留地址不计）", total)
	}

	// attack_type_share：与 top_attack_types 同源家族计数（SQL注入 ×3 + 回退黑名单
	// rule_triggered=2 → 攻击族 IP 访问控制 ×1）
	foundSQL, foundACL := false, false
	for _, item := range payload.Data.AttackTypeShare {
		if item.Name == "SQL注入" && item.Value == 3 {
			foundSQL = true
		}
		if item.Name == "IP 访问控制" && item.Value == 1 {
			foundACL = true
		}
	}
	if !foundSQL || !foundACL {
		t.Fatalf("attack_type_share 缺家族: %+v", payload.Data.AttackTypeShare)
	}

	// recent_rate：近 5min 无 blocked 事件 → 0（种子均在 27-30min 前）
	if payload.Data.RecentRate != 0 {
		t.Errorf("recent_rate=%v, want 0", payload.Data.RecentRate)
	}
}

func TestGetSecurityThreatScreen_recentRate(t *testing.T) {
	// Given: 近 5 分钟 3 条 blocked + 1 条 logged（blocked 3 条/5min = 0.6/min）
	setupSecurityPolicyTestDB(t)
	router := newThreatScreenRouter(t, newThreatMetricsServer(t).URL)
	seedThreatScreenEvent(t, utcStringAgo(1*time.Minute), "203.0.113.7", "942100", "SQL 注入攻击头", "blocked")
	seedThreatScreenEvent(t, utcStringAgo(2*time.Minute), "203.0.113.7", "942100", "SQL 注入攻击头", "blocked")
	seedThreatScreenEvent(t, utcStringAgo(3*time.Minute), "198.51.100.5", "941100", "XSS 脚本标签探测", "blocked")
	seedThreatScreenEvent(t, utcStringAgo(4*time.Minute), "198.51.100.5", "941100", "XSS 脚本标签探测", "logged")
	seedThreatScreenEvent(t, utcStringAgo(2*time.Minute), "10.0.0.8", "941100", "XSS 脚本标签探测", "blocked")

	// When
	recorder := getRequest(t, router, "/security/overview/threat-screen")
	var payload threatScreenPayload
	if err := json.Unmarshal(recorder.Body.Bytes(), &payload); err != nil {
		t.Fatal(err)
	}

	// Then: 3 blocked/5min = 0.6（保留地址不计；logged 不计）
	if payload.Data.RecentRate != 0.6 {
		t.Errorf("recent_rate=%v, want 0.6", payload.Data.RecentRate)
	}
}

// TestThreatScreenRollup_fixationIdempotentAndEquivalent（v2.3.8 性能工程）
// Given: 原始事件在窗口内；When: 两次请求端点（懒固化的幂等性）且清空原始表后再请求
// Then: rollup 行数不翻倍；清空原始表后聚合数值不变（聚合与原始表规模解耦的等价性证明）
func TestThreatScreenRollup_fixationIdempotentAndEquivalent(t *testing.T) {
	setupSecurityPolicyTestDB(t)
	router := newThreatScreenRouter(t, newThreatMetricsServer(t).URL)
	seedThreatScreenEvent(t, utcStringAgo(10*time.Minute), "203.0.113.7", "942100", "SQL Injection", "blocked")
	seedThreatScreenEvent(t, utcStringAgo(9*time.Minute), "203.0.113.7", "942100", "SQL Injection", "blocked")
	seedThreatScreenEvent(t, utcStringAgo(8*time.Minute), "198.51.100.5", "941100", "XSS", "logged")

	first := getRequest(t, router, "/security/overview/threat-screen")
	if first.Code != http.StatusOK {
		t.Fatalf("first status=%d body=%s", first.Code, first.Body.String())
	}
	// 幂等：再请求一次，rollup 计数不得翻倍
	second := getRequest(t, router, "/security/overview/threat-screen")
	if second.Code != http.StatusOK {
		t.Fatalf("second status=%d", second.Code)
	}
	var rollCount int
	if err := db.MetricsDB.QueryRow(`SELECT COALESCE(SUM(count),0) FROM security_event_rollup`).Scan(&rollCount); err != nil {
		t.Fatal(err)
	}
	if rollCount != 3 {
		t.Errorf("rollup sum=%d, want 3（幂等固化，不随请求次数翻倍）", rollCount)
	}
	// 等价性：清空原始表（模拟原始表被保留策略裁剪/规模解耦），聚合仍来自 rollup
	if _, err := db.MetricsDB.Exec(`DELETE FROM security_events`); err != nil {
		t.Fatal(err)
	}
	third := getRequest(t, router, "/security/overview/threat-screen")
	if third.Code != http.StatusOK {
		t.Fatalf("third status=%d body=%s", third.Code, third.Body.String())
	}
	var p1, p3 threatScreenPayload
	if err := json.Unmarshal(first.Body.Bytes(), &p1); err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(third.Body.Bytes(), &p3); err != nil {
		t.Fatal(err)
	}
	if p3.Data.TotalEvents != p1.Data.TotalEvents || p3.Data.TotalEvents != 3 {
		t.Errorf("total after raw wipe=%d (first=%d), want 3（rollup 等价承载）", p3.Data.TotalEvents, p1.Data.TotalEvents)
	}
	if p3.Data.BlockedEvents != 2 {
		t.Errorf("blocked after raw wipe=%d, want 2", p3.Data.BlockedEvents)
	}
	// 国家维度依赖 xdb 归属（测试环境无 xdb → country 空），只验计数等价；
	// 国家/省产出在 rollup 行中有独立断言（下）。
	if rollCount == 0 {
		t.Errorf("rollup empty")
	}
}

func TestTriggerTypeForRule_fullTaxonomy(t *testing.T) {
	cases := map[string]string{
		"429":     "限流",
		"2":       "IP 访问控制",
		"4":       "IP 访问控制",
		"7":       "IP 访问控制",
		"8":       "地域拦截",
		"12":      "信任名单",
		"14":      "威胁情报库",
		"11":      "请求体异常",
		"800007":  "地域拦截",
		"810016":  "爬虫Bot",
		"850003":  "爬虫Bot",
		"942100":  "WAF·CRS",
		"10001":   "WAF·自定义",
		"1000001": "WAF·自定义",
		"999999":  "WAF·CRS",
	}
	for id, want := range cases {
		if got := triggerTypeForRule(id); got != want {
			t.Errorf("triggerTypeForRule(%q)=%q, want %q", id, got, want)
		}
	}
}

func TestAttackFamily_sixDigitCustomIDs(t *testing.T) {
	for _, id := range []string{"100000", "199999", "700000", "799999"} {
		if got := categorizeAttack(id, ""); got != "自定义规则" {
			t.Fatalf("categorizeAttack(%s)=%q, want 自定义规则", id, got)
		}
		if got := stageCategorizeAttack(id, ""); got != "WAF" {
			t.Fatalf("stageCategorizeAttack(%s)=%q, want WAF", id, got)
		}
	}
	if !strings.Contains(customRuleFamilyCondition, "[1-7][0-9][0-9][0-9][0-9][0-9]") {
		t.Fatalf("custom SQL family must cover 1xxxxx-7xxxxx: %s", customRuleFamilyCondition)
	}
	// 8xxxxx 仍由地域/爬虫段独占，9xxxxx 仍是 CRS。
	for id, want := range map[string]string{"800000": "地域拦截", "899999": "爬虫Bot", "900000": "其他"} {
		if got := categorizeAttack(id, ""); got != want {
			t.Fatalf("categorizeAttack(%s)=%q, want %q", id, got, want)
		}
	}
}

func TestThreatFixMinute_groupByUsesExpressions(t *testing.T) {
	raw, err := os.ReadFile("security_threat_screen.go")
	if err != nil {
		t.Fatal(err)
	}
	source := string(raw)
	start := strings.Index(source, "func threatFixMinute(")
	if start < 0 {
		t.Fatal("threatFixMinute not found")
	}
	body := source[start:]
	if end := strings.Index(body, "\nfunc threatLocationParts("); end > 0 {
		body = body[:end]
	}
	if strings.Contains(body, "GROUP BY client_ip, 2,") {
		t.Fatal("rollup GROUP BY must not depend on select-list ordinals")
	}
	if !strings.Contains(body, "GROUP BY client_ip, COALESCE(NULLIF(rule_name,''), COALESCE(rule_triggered,''))") {
		t.Fatal("rollup GROUP BY must repeat the normalized rule-name expression")
	}
}

// ---- 历史 A 域：RG-TS-ROLLUP-WATERMARK / RG-TS-ERROR-PATH / RG-FEED-CURSOR ----

func installThreatClock(t *testing.T, now time.Time) {
	t.Helper()
	old := threatScreenNow
	threatScreenNow = func() time.Time { return now }
	t.Cleanup(func() { threatScreenNow = old })
}

func threatRollupWatermarkForTest(t *testing.T) string {
	t.Helper()
	var raw string
	if err := db.MetricsDB.QueryRow(`SELECT value FROM metrics_state WHERE key=?`, threatRollupWatermarkKey).Scan(&raw); err != nil {
		t.Fatalf("read rollup watermark: %v", err)
	}
	return raw
}

func threatRollupCoveredFromForTest(t *testing.T) string {
	t.Helper()
	var raw string
	if err := db.MetricsDB.QueryRow(`SELECT value FROM metrics_state WHERE key=?`, threatRollupCoveredFromKey).Scan(&raw); err != nil {
		t.Fatalf("read rollup covered_from: %v", err)
	}
	return raw
}

func threatRollupCountForMinute(t *testing.T, minute string) int {
	t.Helper()
	var count int
	if err := db.MetricsDB.QueryRow(`SELECT COALESCE(SUM(count),0) FROM security_event_rollup WHERE minute=?`, minute).Scan(&count); err != nil {
		t.Fatal(err)
	}
	return count
}

func TestThreatRollup_previousMinuteFinalizedAfterLateWrites(t *testing.T) {
	setupSecurityPolicyTestDB(t)
	base := time.Date(2026, 10, 18, 12, 0, 30, 0, time.UTC)
	installThreatClock(t, base)
	seedThreatScreenEvent(t, "2026-10-18 12:00:05", "203.0.113.7", "942100", "SQL Injection", "blocked")

	// 首次固化：当前分钟（12:00）被写入。
	if err := ensureThreatRollup(24); err != nil {
		t.Fatalf("first rollup: %v", err)
	}
	// 12:00 内后段迟到写入（首次固化之后到达），并推进时钟到 12:01:30：
	// lastComplete=12:00 必须被再次终固，否则该事件永久丢失。
	seedThreatScreenEvent(t, "2026-10-18 12:00:40", "203.0.113.7", "942100", "SQL Injection", "blocked")
	oldClock := threatScreenNow
	threatScreenNow = func() time.Time { return base.Add(time.Minute) }
	t.Cleanup(func() { threatScreenNow = oldClock })
	if err := ensureThreatRollup(24); err != nil {
		t.Fatalf("second rollup: %v", err)
	}
	if got := threatRollupCountForMinute(t, "2026-10-18 12:00"); got != 2 {
		t.Fatalf("rollup 12:00 count=%d, want 2 (late write must be finalized, no doubling)", got)
	}
	// 幂等：再固化一次不翻倍。
	if err := ensureThreatRollup(24); err != nil {
		t.Fatalf("third rollup: %v", err)
	}
	if got := threatRollupCountForMinute(t, "2026-10-18 12:00"); got != 2 {
		t.Fatalf("rollup 12:00 count=%d after re-fix, want 2", got)
	}
}

func TestThreatRollup_watermarkAdvancesOnEmptyAndClamps(t *testing.T) {
	base := time.Date(2026, 10, 18, 12, 0, 30, 0, time.UTC)

	t.Run("empty minutes advance and the window is bounded", func(t *testing.T) {
		setupSecurityPolicyTestDB(t)
		installThreatClock(t, base)
		// 3 小时前的公网事件 + 同分钟的全私网事件（私网不进 rollup）。
		seedThreatScreenEvent(t, "2026-10-18 09:00:10", "203.0.113.7", "942100", "SQL Injection", "blocked")
		seedThreatScreenEvent(t, "2026-10-18 10:00:10", "10.0.0.8", "942100", "SQL Injection", "blocked")

		if err := ensureThreatRollup(24); err != nil {
			t.Fatalf("first rollup: %v", err)
		}
		first := threatRollupWatermarkForTest(t)
		if first != "2026-10-18 11:58" {
			t.Fatalf("first watermark=%q, want 11:58 (24h window fits the per-call batch budget)", first)
		}
		if err := ensureThreatRollup(24); err != nil {
			t.Fatalf("second rollup: %v", err)
		}
		if got := threatRollupWatermarkForTest(t); got != "2026-10-18 11:58" {
			t.Fatalf("second watermark=%q, want 11:58 (coverage complete, no drift)", got)
		}
		if got := threatRollupCountForMinute(t, "2026-10-18 09:00"); got != 1 {
			t.Fatalf("public event minute count=%d, want 1", got)
		}
		if got := threatRollupCountForMinute(t, "2026-10-18 10:00"); got != 0 {
			t.Fatalf("private-only minute count=%d, want 0", got)
		}
		if err := ensureThreatRollup(24); err != nil {
			t.Fatalf("third rollup: %v", err)
		}
		if got := threatRollupWatermarkForTest(t); got != "2026-10-18 11:58" {
			t.Fatalf("steady-state watermark=%q, want 11:58 (no drift backwards)", got)
		}
	})

	t.Run("stale watermark is clamped to the backfill horizon", func(t *testing.T) {
		setupSecurityPolicyTestDB(t)
		installThreatClock(t, base)
		stale := base.AddDate(0, 0, -40).Format("2006-01-02 15:04")
		if _, err := db.MetricsDB.Exec(`INSERT INTO metrics_state (key, value) VALUES (?, ?)`, threatRollupWatermarkKey, stale); err != nil {
			t.Fatal(err)
		}
		if err := ensureThreatRollup(24); err != nil {
			t.Fatalf("rollup with stale watermark: %v", err)
		}
		got := threatRollupWatermarkForTest(t)
		if got != "2026-10-18 11:58" {
			t.Fatalf("watermark after clamp=%q, want 11:58 (clamped to 24h horizon)", got)
		}
	})
}

func TestThreatRollup_backfillHonorsRequestedHours(t *testing.T) {
	base := time.Date(2026, 10, 18, 12, 0, 30, 0, time.UTC)
	eventMinute := base.Add(-36 * time.Hour).Truncate(time.Minute).Format("2006-01-02 15:04")
	eventTime := base.Add(-36 * time.Hour).Format("2006-01-02 15:04:05")
	lastCompleteMinute := base.Add(-time.Minute).Truncate(time.Minute)
	wantCoveredFrom := lastCompleteMinute.Add(-time.Duration(48) * time.Hour).Format("2006-01-02 15:04")

	settle := func(t *testing.T, hours int, wantFrom string) {
		t.Helper()
		for i := 0; i < 8; i++ {
			if err := ensureThreatRollup(hours); err != nil {
				t.Fatalf("rollup(hours=%d): %v", hours, err)
			}
			if threatRollupCoveredFromForTest(t) >= wantFrom {
				return
			}
		}
		t.Fatalf("rollup(hours=%d) did not converge to coverage from %s (got %s)", hours, wantFrom, threatRollupCoveredFromForTest(t))
	}
	t.Run("48h window backfills 36h-old events", func(t *testing.T) {
		setupSecurityPolicyTestDB(t)
		installThreatClock(t, base)
		seedThreatScreenEvent(t, eventTime, "203.0.113.7", "942100", "SQL Injection", "blocked")
		if err := ensureThreatRollup(48); err != nil {
			t.Fatal(err)
		}
		if got := threatRollupCoveredFromForTest(t); got <= wantCoveredFrom {
			t.Fatalf("48h backfill must span more than one transaction (covered_from=%q already reached %q)", got, wantCoveredFrom)
		}
		settle(t, 48, wantCoveredFrom)
		if got := threatRollupCountForMinute(t, eventMinute); got != 1 {
			t.Fatalf("36h-old event count=%d at %s, want 1", got, eventMinute)
		}
	})

	t.Run("24h window does not backfill older events", func(t *testing.T) {
		setupSecurityPolicyTestDB(t)
		installThreatClock(t, base)
		seedThreatScreenEvent(t, eventTime, "203.0.113.7", "942100", "SQL Injection", "blocked")
		settle(t, 24, lastCompleteMinute.Add(-24*time.Hour).Format("2006-01-02 15:04"))
		if got := threatRollupCountForMinute(t, eventMinute); got != 0 {
			t.Fatalf("36h-old event backfilled under 24h window (count=%d), want 0", got)
		}
	})
}

func TestEnsureThreatRollup_backfillBatchedNoLockStarvation(t *testing.T) {
	setupSecurityPolicyTestDB(t)
	installThreatClock(t, time.Date(2026, 10, 18, 12, 0, 30, 0, time.UTC))

	stop := make(chan struct{})
	insertErrs := make(chan error, 1)
	go func() {
		var firstErr error
		for {
			select {
			case <-stop:
				insertErrs <- firstErr
				return
			default:
			}
			if _, err := db.MetricsDB.Exec(`INSERT INTO security_events (event_time, client_ip, rule_triggered, action) VALUES (?, '203.0.113.9', '942100', 'blocked')`, "2026-10-18 11:59:30"); err != nil && firstErr == nil {
				firstErr = err
			}
			time.Sleep(time.Millisecond)
		}
	}()
	err := ensureThreatRollup(48) // 48h 回填跨多批（单请求预算不足以完成）
	close(stop)
	if ierr := <-insertErrs; ierr != nil {
		t.Fatalf("concurrent ingestion hit a database error during rollup backfill: %v", ierr)
	}
	if err != nil {
		t.Fatalf("rollup backfill failed under concurrent ingestion: %v", err)
	}
	// 有界分批：首次调用不得在一个事务里跑完全部回填。
	if got := threatRollupWatermarkForTest(t); got == "2026-10-18 11:59" {
		t.Fatalf("backfill was not batched (watermark reached the tail in one call)")
	}
}

func TestThreatScreen_lastSumQueryFailure_returns500(t *testing.T) {
	setupSecurityPolicyTestDB(t)
	router := newThreatScreenRouter(t, newThreatMetricsServer(t).URL)
	old := queryThreatRecentBlocked
	queryThreatRecentBlocked = func(string) (int, error) { return 0, fmt.Errorf("injected sum failure") }
	t.Cleanup(func() { queryThreatRecentBlocked = old })

	recorder := getRequest(t, router, "/security/overview/threat-screen")
	if recorder.Code != http.StatusInternalServerError {
		t.Fatalf("recent_rate SUM failure status=%d body=%s, want 500", recorder.Code, recorder.Body.String())
	}
}

type feedCursorPayload struct {
	Data struct {
		Events      []models.SecurityEventFeedItem `json:"events"`
		SinceID     int64                          `json:"since_id"`
		NextSinceID int64                          `json:"next_since_id"`
		Limit       int                            `json:"limit"`
		HasMore     bool                           `json:"has_more"`
	} `json:"data"`
}

func TestSecurityEventFeed_reservedOnlyPageAdvancesCursor(t *testing.T) {
	setupSecurityPolicyTestDB(t)
	router := newThreatScreenRouter(t, newThreatMetricsServer(t).URL)
	// 60 条公网（较老）+ 50 条保留地址（最新）——首页整页被过滤。
	for i := 0; i < 60; i++ {
		seedThreatScreenEvent(t, utcStringAgo(30*time.Minute), "203.0.113.10", "942100", "SQL Injection", "blocked")
	}
	for i := 0; i < 50; i++ {
		seedThreatScreenEvent(t, utcStringAgo(20*time.Minute), "10.0.0.8", "942100", "SQL Injection", "blocked")
	}
	recorder := getRequest(t, router, "/security/events/feed?limit=50")
	if recorder.Code != http.StatusOK {
		t.Fatalf("feed status=%d body=%s", recorder.Code, recorder.Body.String())
	}
	var payload feedCursorPayload
	if err := json.Unmarshal(recorder.Body.Bytes(), &payload); err != nil {
		t.Fatal(err)
	}
	if len(payload.Data.Events) != 50 {
		t.Fatalf("events=%d, want 50 (scan must continue past reserved-only page)", len(payload.Data.Events))
	}
	if payload.Data.NextSinceID != 110 {
		t.Fatalf("next_since_id=%d, want 110 (max id actually scanned)", payload.Data.NextSinceID)
	}
	// 首屏契约：升序输出（ids 11..60）、has_more=false（不回溯更老）
	if payload.Data.HasMore {
		t.Fatalf("first screen has_more=true, want false")
	}
	if payload.Data.Events[0].ID != 11 || payload.Data.Events[49].ID != 60 {
		t.Fatalf("first screen ids [%d..%d], want ascending [11..60]", payload.Data.Events[0].ID, payload.Data.Events[49].ID)
	}
	// 用返回的高水位再请求：不得重复返回已扫描行。
	recorder = getRequest(t, router, fmt.Sprintf("/security/events/feed?limit=50&since_id=%d", payload.Data.NextSinceID))
	var next feedCursorPayload
	if err := json.Unmarshal(recorder.Body.Bytes(), &next); err != nil {
		t.Fatal(err)
	}
	if len(next.Data.Events) != 0 {
		t.Fatalf("cursor advanced but feed returned %d duplicates", len(next.Data.Events))
	}
	if next.Data.NextSinceID < payload.Data.NextSinceID {
		t.Fatalf("cursor went backwards: %d -> %d", payload.Data.NextSinceID, next.Data.NextSinceID)
	}
}

func TestSecurityEventFeed_mixedPageHighWater(t *testing.T) {
	setupSecurityPolicyTestDB(t)
	router := newThreatScreenRouter(t, newThreatMetricsServer(t).URL)
	for i := 0; i < 50; i++ {
		seedThreatScreenEvent(t, utcStringAgo(30*time.Minute), "203.0.113.10", "942100", "SQL Injection", "blocked")
	}
	for i := 0; i < 10; i++ {
		seedThreatScreenEvent(t, utcStringAgo(20*time.Minute), "192.168.1.5", "942100", "SQL Injection", "blocked")
	}
	recorder := getRequest(t, router, "/security/events/feed?limit=50")
	var payload feedCursorPayload
	if err := json.Unmarshal(recorder.Body.Bytes(), &payload); err != nil {
		t.Fatal(err)
	}
	if len(payload.Data.Events) != 50 {
		t.Fatalf("events=%d, want 50 across a mixed page", len(payload.Data.Events))
	}
	if payload.Data.NextSinceID != 60 {
		t.Fatalf("next_since_id=%d, want 60", payload.Data.NextSinceID)
	}
	// 升序输出（ids 1..50）
	if payload.Data.Events[0].ID != 1 || payload.Data.Events[49].ID != 50 {
		t.Fatalf("mixed page ids [%d..%d], want ascending [1..50]", payload.Data.Events[0].ID, payload.Data.Events[49].ID)
	}
}

func TestThreatRollup_longGapDoesNotFakeContinuousCoverage(t *testing.T) {
	base := time.Date(2026, 10, 18, 12, 0, 30, 0, time.UTC)
	setupSecurityPolicyTestDB(t)
	installThreatClock(t, base)
	eventMinute := base.Add(-36 * time.Hour).Truncate(time.Minute).Format("2006-01-02 15:04")
	seedThreatScreenEvent(t, base.Add(-36*time.Hour).Format("2006-01-02 15:04:05"), "203.0.113.7", "942100", "SQL Injection", "blocked")

	// 双水位均有效但停在很久以前：窗口起点与已覆盖末端之间存在长缺口。
	covered := base.AddDate(0, 0, -30).Format("2006-01-02 15:04")
	lastFixed := base.Add(-40 * time.Hour).Format("2006-01-02 15:04")
	for key, value := range map[string]string{
		threatRollupCoveredFromKey: covered,
		threatRollupWatermarkKey:   lastFixed,
	} {
		if _, err := db.MetricsDB.Exec(`INSERT INTO metrics_state (key, value) VALUES (?, ?) ON CONFLICT(key) DO UPDATE SET value=excluded.value`, key, value); err != nil {
			t.Fatal(err)
		}
	}

	if err := ensureThreatRollup(24); err != nil {
		t.Fatalf("narrow rollup: %v", err)
	}
	for i := 0; i < 8; i++ {
		if err := ensureThreatRollup(48); err != nil {
			t.Fatalf("wide rollup %d: %v", i, err)
		}
	}
	if got := threatRollupCountForMinute(t, eventMinute); got != 1 {
		t.Fatalf("gap minute count=%d, want 1 (长缺口事件必须被更宽窗口回填)", got)
	}
}

// ---- v2.4.x 大屏加固：top_targets / rollup warmer / hourly_hist 滑动窗口 ----

// seedThreatRuleEvent 带 rule_caddy_id 的事件种子（top_targets 数据源）。
func seedThreatRuleEvent(t *testing.T, eventTime, clientIP, ruleCaddyID, action string) {
	t.Helper()
	if _, err := db.MetricsDB.Exec(`INSERT INTO security_events (event_time, client_ip, method, uri, event_type, rule_triggered, rule_msg, action, rule_name, rule_caddy_id)
		VALUES (?, ?, 'GET', '/a', 'stage1', '2', 'IP 黑名单命中', ?, '', ?)`,
		eventTime, clientIP, action, ruleCaddyID); err != nil {
		t.Fatalf("seed rule event: %v", err)
	}
}

func seedThreatLBRule(t *testing.T, caddyID, name, domain string) {
	t.Helper()
	if _, err := db.DB.Exec(`INSERT INTO lb_rules (caddy_id, name, protocol, listen_port, domain) VALUES (?, ?, 'http', 80, ?)`,
		caddyID, name, domain); err != nil {
		t.Fatalf("seed lb_rule: %v", err)
	}
}

func TestGetSecurityThreatScreen_topTargets(t *testing.T) {
	// Given: 主库两条规则 + 窗口内事件（lb_aaa ×3 blocked、lb_bbb ×1 logged、
	// 已删除规则 lb_gone ×2、空 rule_caddy_id 事件 ×1）
	setupSecurityPolicyTestDB(t)
	t.Cleanup(resetThreatScreenCachesForTest)
	router := newThreatScreenRouter(t, newThreatMetricsServer(t).URL)
	seedThreatLBRule(t, "lb_aaa", "API 服务", "api.example.com")
	seedThreatLBRule(t, "lb_bbb", "官网", "www.example.com")
	for i := 0; i < 3; i++ {
		seedThreatRuleEvent(t, utcStringAgo(time.Duration(i+1)*time.Minute), "203.0.113.7", "lb_aaa", "blocked")
	}
	seedThreatRuleEvent(t, utcStringAgo(time.Minute), "203.0.113.8", "lb_bbb", "logged")
	for i := 0; i < 2; i++ {
		seedThreatRuleEvent(t, utcStringAgo(time.Duration(i+1)*time.Minute), "203.0.113.9", "lb_gone", "blocked")
	}
	seedThreatScreenEvent(t, utcStringAgo(time.Minute), "203.0.113.10", "942100", "SQL Injection", "blocked")

	// When
	recorder := getRequest(t, router, "/security/overview/threat-screen")
	if recorder.Code != http.StatusOK {
		t.Fatalf("status=%d body=%s", recorder.Code, recorder.Body.String())
	}
	var payload threatScreenPayload
	if err := json.Unmarshal(recorder.Body.Bytes(), &payload); err != nil {
		t.Fatal(err)
	}

	// Then: top_targets 按计数降序取前 5；已删除规则跳过；空 rule_caddy_id 排除
	targets := payload.Data.TopTargets
	if len(targets) != 2 {
		t.Fatalf("top_targets=%+v, want 2 项（lb_gone 无 lb_rules 行跳过、空 id 排除）", targets)
	}
	if targets[0].Name != "API 服务" || targets[0].Domain != "api.example.com" || targets[0].Value != 3 {
		t.Errorf("top_targets[0]=%+v, want {API 服务 api.example.com 3}", targets[0])
	}
	if targets[1].Name != "官网" || targets[1].Domain != "www.example.com" || targets[1].Value != 1 {
		t.Errorf("top_targets[1]=%+v, want {官网 www.example.com 1}（logged 也计入分组计数）", targets[1])
	}
}

func TestGetSecurityThreatScreen_topTargetsCached(t *testing.T) {
	// Given: 一条规则 + 1 条窗口内事件
	setupSecurityPolicyTestDB(t)
	t.Cleanup(resetThreatScreenCachesForTest)
	router := newThreatScreenRouter(t, newThreatMetricsServer(t).URL)
	seedThreatLBRule(t, "lb_aaa", "API 服务", "api.example.com")
	seedThreatRuleEvent(t, utcStringAgo(time.Minute), "203.0.113.7", "lb_aaa", "blocked")

	get := func() int {
		recorder := getRequest(t, router, "/security/overview/threat-screen")
		if recorder.Code != http.StatusOK {
			t.Fatalf("status=%d body=%s", recorder.Code, recorder.Body.String())
		}
		var payload threatScreenPayload
		if err := json.Unmarshal(recorder.Body.Bytes(), &payload); err != nil {
			t.Fatal(err)
		}
		if len(payload.Data.TopTargets) != 1 {
			t.Fatalf("top_targets=%+v, want 1 项", payload.Data.TopTargets)
		}
		return payload.Data.TopTargets[0].Value
	}

	// When/Then: 首查 value=1；缓存窗口（5min TTL）内再落 2 条事件后第二查
	// 仍返回 1（进程内缓存命中——大屏 30s 轮询不再每轮扫原始表）
	if got := get(); got != 1 {
		t.Fatalf("first value=%d, want 1", got)
	}
	seedThreatRuleEvent(t, utcStringAgo(30*time.Second), "203.0.113.7", "lb_aaa", "blocked")
	seedThreatRuleEvent(t, utcStringAgo(20*time.Second), "203.0.113.7", "lb_aaa", "blocked")
	if got := get(); got != 1 {
		t.Fatalf("cached value=%d, want 1（TTL 内缓存命中）", got)
	}
	// reset 后重新查询生效
	resetThreatScreenCachesForTest()
	if got := get(); got != 3 {
		t.Fatalf("after reset value=%d, want 3", got)
	}
}

func TestGetSecurityThreatScreen_topTargetsQueryFailureReturns500(t *testing.T) {
	// Given: lb_rules 表缺失（主库查询失败）+ 一条带 rule_caddy_id 的事件
	setupSecurityPolicyTestDB(t)
	t.Cleanup(resetThreatScreenCachesForTest)
	router := newThreatScreenRouter(t, newThreatMetricsServer(t).URL)
	seedThreatRuleEvent(t, utcStringAgo(time.Minute), "203.0.113.7", "lb_aaa", "blocked")
	if _, err := db.DB.Exec(`DROP TABLE lb_rules`); err != nil {
		t.Fatal(err)
	}

	// When/Then: top_targets 查询失败保持整卡 500（与现有错误口径一致）
	recorder := getRequest(t, router, "/security/overview/threat-screen")
	if recorder.Code != http.StatusInternalServerError {
		t.Fatalf("status=%d body=%s, want 500", recorder.Code, recorder.Body.String())
	}
}

func TestStartThreatRollupWarmer_takesOverFixation(t *testing.T) {
	// Given: 窗口内 1 条事件；warmer 以已取消 ctx 启动（立即退出不执行固化，
	// 但启动标志置位）；幂等二次启动不 panic。
	// 历史 历史问题：启动标志 ≠ 已有可用覆盖——首轮从未成功时请求路径必须
	// 沿用懒固化（不得返回全零「无攻击」大屏）。
	setupSecurityPolicyTestDB(t)
	t.Cleanup(resetThreatRollupWarmerForTest)
	router := newThreatScreenRouter(t, newThreatMetricsServer(t).URL)
	seedThreatScreenEvent(t, utcStringAgo(5*time.Minute), "203.0.113.7", "942100", "SQL Injection", "blocked")
	ctx, cancel := context.WithCancel(context.Background())
	cancel() // 已取消：warmer 立即退出（不执行固化），仅置启动标志
	StartThreatRollupWarmer(ctx)
	StartThreatRollupWarmer(ctx) // 幂等：CAS 标志，重复启动为空操作
	threatRollupWarmerWg.Wait()  // 确认协程已退出（后续请求路径断言无并发固化）

	// When/Then: warmer 未完成首轮 → 请求路径懒固化兜底（total=1）
	recorder := getRequest(t, router, "/security/overview/threat-screen")
	if recorder.Code != http.StatusOK {
		t.Fatalf("status=%d body=%s", recorder.Code, recorder.Body.String())
	}
	var payload threatScreenPayload
	if err := json.Unmarshal(recorder.Body.Bytes(), &payload); err != nil {
		t.Fatal(err)
	}
	if payload.Data.TotalEvents != 1 {
		t.Fatalf("total_events=%d, want 1（首轮未完成时请求路径须懒固化兜底）", payload.Data.TotalEvents)
	}

	// 模拟「warmer 已成功固化且新鲜」：再落一条最新分钟事件——常规请求不再
	// 懒固化（total 保持 1）；复位后请求懒固化重固末两分钟 → 2。
	markThreatRollupSuccess()
	seedThreatScreenEvent(t, utcStringAgo(10*time.Second), "203.0.113.8", "942100", "SQL Injection", "blocked")
	recorder = getRequest(t, router, "/security/overview/threat-screen")
	if err := json.Unmarshal(recorder.Body.Bytes(), &payload); err != nil {
		t.Fatal(err)
	}
	if payload.Data.TotalEvents != 1 {
		t.Fatalf("total_events=%d, want 1（warmer 已就绪且新鲜时请求路径不再懒固化）", payload.Data.TotalEvents)
	}

	// 复位启动标志（测试/旧路径）→ 请求懒固化恢复
	resetThreatRollupWarmerForTest()
	recorder = getRequest(t, router, "/security/overview/threat-screen")
	if err := json.Unmarshal(recorder.Body.Bytes(), &payload); err != nil {
		t.Fatal(err)
	}
	if payload.Data.TotalEvents != 2 {
		t.Fatalf("total_events=%d, want 2（未启动 warmer 时保持懒固化）", payload.Data.TotalEvents)
	}
}

func TestStartThreatRollupWarmer_runsImmediately(t *testing.T) {
	// Given: 窗口内 1 条事件
	setupSecurityPolicyTestDB(t)
	t.Cleanup(resetThreatRollupWarmerForTest)
	seedThreatScreenEvent(t, utcStringAgo(2*time.Minute), "203.0.113.7", "942100", "SQL Injection", "blocked")
	ctx, cancel := context.WithCancel(context.Background())
	// 先取消并等待协程退出，再让 DB 清理运行（cleanup LIFO：本注册晚于
	// setupSecurityPolicyTestDB 的换库清理，故先于其执行）。
	t.Cleanup(func() {
		cancel()
		threatRollupWarmerWg.Wait()
	})

	// When
	StartThreatRollupWarmer(ctx)

	// Then: 启动即固化一次（不等首个 60s tick）——轮询等待 rollup 行出现
	deadline := time.Now().Add(2 * time.Second)
	for {
		var n int
		if err := db.MetricsDB.QueryRow(`SELECT COALESCE(SUM(count),0) FROM security_event_rollup`).Scan(&n); err == nil && n >= 1 {
			return
		}
		if time.Now().After(deadline) {
			t.Fatalf("warmer 未在启动后立即固化（rollup 仍为空）")
		}
		time.Sleep(10 * time.Millisecond)
	}
}

func TestGetSecurityThreatScreen_hourlyHistSlidingHours(t *testing.T) {
	// Given: 30 分钟前与 90 分钟前各 1 条事件
	setupSecurityPolicyTestDB(t)
	router := newThreatScreenRouter(t, newThreatMetricsServer(t).URL)
	now := time.Now()
	seedThreatScreenEvent(t, now.UTC().Add(-30*time.Minute).Truncate(time.Second).Format("2006-01-02 15:04:05"), "203.0.113.7", "942100", "SQL Injection", "blocked")
	seedThreatScreenEvent(t, now.UTC().Add(-90*time.Minute).Truncate(time.Second).Format("2006-01-02 15:04:05"), "203.0.113.8", "941100", "XSS", "blocked")

	// When: hours=3
	recorder := getRequest(t, router, "/security/overview/threat-screen?hours=3")
	if recorder.Code != http.StatusOK {
		t.Fatalf("status=%d body=%s", recorder.Code, recorder.Body.String())
	}
	var payload threatScreenPayload
	if err := json.Unmarshal(recorder.Body.Bytes(), &payload); err != nil {
		t.Fatal(err)
	}

	// Then: 滑动窗口分桶——3 槽（min(hours,24)）、名称 HH:00、末槽=当前
	// 小时（配置时区），不再按本地固定 0..23 小时折叠
	hist := payload.Data.HourlyHist
	if len(hist) != 3 {
		t.Fatalf("hourly_hist=%d 槽, want 3（hours=3 滑动窗口）", len(hist))
	}
	loc := services.CurrentLocation()
	lastHour := time.Now().In(loc).Truncate(time.Hour)
	for i, slot := range hist {
		want := lastHour.Add(-time.Duration(len(hist)-1-i) * time.Hour)
		if slot.Name != fmt.Sprintf("%02d:00", want.Hour()) {
			t.Fatalf("hist[%d].Name=%q, want %02d:00（末槽为当前小时，逐槽回溯）", i, slot.Name, want.Hour())
		}
	}
	// 事件按本地小时落槽（总量守恒）
	byName := map[string]int{}
	total := 0
	for _, slot := range hist {
		byName[slot.Name] += slot.Value
		total += slot.Value
	}
	if total != 2 {
		t.Fatalf("hourly 总计=%d, want 2", total)
	}
	slot30 := fmt.Sprintf("%02d:00", now.Add(-30*time.Minute).In(loc).Hour())
	slot90 := fmt.Sprintf("%02d:00", now.Add(-90*time.Minute).In(loc).Hour())
	if byName[slot30] != 1 || byName[slot90] != 1 {
		t.Fatalf("落槽=%v, want %s=1 且 %s=1", byName, slot30, slot90)
	}
}

func TestGetSecurityThreatScreen_hourlyHistDayBuckets(t *testing.T) {
	// Given: 30 小时前与 2 小时前各 1 条事件
	setupSecurityPolicyTestDB(t)
	router := newThreatScreenRouter(t, newThreatMetricsServer(t).URL)
	now := time.Now()
	seedThreatScreenEvent(t, now.UTC().Add(-30*time.Hour).Truncate(time.Second).Format("2006-01-02 15:04:05"), "203.0.113.7", "942100", "SQL Injection", "blocked")
	seedThreatScreenEvent(t, now.UTC().Add(-2*time.Hour).Truncate(time.Second).Format("2006-01-02 15:04:05"), "203.0.113.8", "941100", "XSS", "blocked")

	// When: hours=72（rollup 回填跨多次请求续做——单请求批预算 24h）
	var payload threatScreenPayload
	for i := 0; i < 6; i++ {
		recorder := getRequest(t, router, "/security/overview/threat-screen?hours=72")
		if recorder.Code != http.StatusOK {
			t.Fatalf("status=%d body=%s", recorder.Code, recorder.Body.String())
		}
		if err := json.Unmarshal(recorder.Body.Bytes(), &payload); err != nil {
			t.Fatal(err)
		}
	}

	// Then: 24h 日桶——ceil(72/24)=3 槽、名称 MM-DD、末槽=今天
	hist := payload.Data.HourlyHist
	if len(hist) != 3 {
		t.Fatalf("hourly_hist=%d 槽, want 3（ceil(72/24) 日桶）", len(hist))
	}
	loc := services.CurrentLocation()
	today := time.Now().In(loc)
	for i, slot := range hist {
		want := today.AddDate(0, 0, -(len(hist) - 1 - i))
		if slot.Name != want.Format("01-02") {
			t.Fatalf("hist[%d].Name=%q, want %s（末槽为今天，逐日回溯）", i, slot.Name, want.Format("01-02"))
		}
	}
	byName := map[string]int{}
	total := 0
	for _, slot := range hist {
		byName[slot.Name] += slot.Value
		total += slot.Value
	}
	if total != 2 {
		t.Fatalf("hourly 总计=%d, want 2", total)
	}
	day30 := now.Add(-30 * time.Hour).In(loc).Format("01-02")
	day2 := now.Add(-2 * time.Hour).In(loc).Format("01-02")
	if byName[day30] != 1 || byName[day2] != 1 {
		t.Fatalf("落桶=%v, want %s=1 且 %s=1", byName, day30, day2)
	}

	// hours=720（30 天上限）→ 日桶上限 30 槽
	recorder := getRequest(t, router, "/security/overview/threat-screen?hours=720")
	if recorder.Code != http.StatusOK {
		t.Fatalf("hours=720 status=%d body=%s", recorder.Code, recorder.Body.String())
	}
	if err := json.Unmarshal(recorder.Body.Bytes(), &payload); err != nil {
		t.Fatal(err)
	}
	if len(payload.Data.HourlyHist) != 30 {
		t.Fatalf("hours=720 hourly_hist=%d 槽, want 30（日桶上限）", len(payload.Data.HourlyHist))
	}
}
