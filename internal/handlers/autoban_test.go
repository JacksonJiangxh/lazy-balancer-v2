package handlers

// 自动封禁（F73-A）端点与预置名单例外钉：
//   GET/PUT /security/autoban 六项配置（校验/审计）
//   POST /security/autoban/run 立即执行（引擎门）
//   GET  /security/autoban/status 运行态+今日封禁+名单数+观察建议+引用状态
//   预置「自动封禁名单」（system=1）删 400/条目可改 200/手动解封写抑制表/导出 TXT

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/gin-gonic/gin"

	"lazy-balancer-v2/internal/db"
	"lazy-balancer-v2/internal/models"
	"lazy-balancer-v2/internal/services"
)

// newAutobanTestEnv：DB 夹具 + 裸路由（镜像 securityiplists_test 形态——
// 名单写路径经 finishTxApply，需要可用 caddyService）。
func newAutobanTestEnv(t *testing.T) *gin.Engine {
	t.Helper()
	oldDB, oldMetricsDB, oldAuditDB := db.DB, db.MetricsDB, db.AuditDB
	if err := db.Initialize(t.TempDir()); err != nil {
		t.Fatalf("initialize: %v", err)
	}
	t.Cleanup(func() {
		_ = db.Close()
		db.DB, db.MetricsDB, db.AuditDB = oldDB, oldMetricsDB, oldAuditDB
	})
	fakeCaddy := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	t.Cleanup(fakeCaddy.Close)
	gin.SetMode(gin.TestMode)
	h := &Handlers{caddyService: services.NewCaddyService(fakeCaddy.URL)}
	router := gin.New()
	router.GET("/security/autoban", h.GetAutobanConfig)
	router.PUT("/security/autoban", h.UpdateAutobanConfig)
	router.POST("/security/autoban/run", h.RunAutobanNow)
	router.GET("/security/autoban/status", h.GetAutobanStatus)
	router.GET("/security/ip-lists/:id/export", h.ExportIPList)
	router.PUT("/security/ip-lists/:id", h.UpdateIPList)
	router.DELETE("/security/ip-lists/:id", h.DeleteIPList)
	router.POST("/security/ip-lists/:id/ips", h.AddIPToList)
	router.POST("/security/ip-lists/:id/remove-ip", h.RemoveIPFromList)
	return router
}

func autobanPresetID(t *testing.T) int {
	t.Helper()
	var id int
	if err := db.DB.QueryRow(`SELECT id FROM security_ip_lists WHERE name=?`, services.AutobanPresetListName).Scan(&id); err != nil {
		t.Fatalf("preset list missing: %v", err)
	}
	return id
}

func seedAutobanListEntries(t *testing.T, entriesJSON string) {
	t.Helper()
	if _, err := db.DB.Exec(`UPDATE security_ip_lists SET entries=? WHERE name=?`, entriesJSON, services.AutobanPresetListName); err != nil {
		t.Fatalf("seed entries: %v", err)
	}
}

func readAutobanListEntries(t *testing.T, id int) []models.IPListEntry {
	t.Helper()
	var raw string
	if err := db.DB.QueryRow(`SELECT COALESCE(entries,'[]') FROM security_ip_lists WHERE id=?`, id).Scan(&raw); err != nil {
		t.Fatalf("read entries: %v", err)
	}
	var entries []models.IPListEntry
	if err := json.Unmarshal([]byte(raw), &entries); err != nil {
		t.Fatalf("parse entries %q: %v", raw, err)
	}
	return entries
}

func countAuditRows(t *testing.T, action, resource string) int {
	t.Helper()
	var n int
	if err := db.AuditDB.QueryRow(`SELECT COUNT(*) FROM audit_log WHERE action=? AND resource=?`, action, resource).Scan(&n); err != nil {
		t.Fatalf("count audit: %v", err)
	}
	return n
}

// ---- 配置读写 ----

func TestAutobanConfig_getDefaults(t *testing.T) {
	router := newAutobanTestEnv(t)
	rec := getRequest(t, router, "/security/autoban")
	if rec.Code != http.StatusOK {
		t.Fatalf("status=%d body=%s", rec.Code, rec.Body.String())
	}
	var cfg services.AutobanConfig
	if err := json.Unmarshal(rec.Body.Bytes(), &cfg); err != nil {
		t.Fatalf("decode: %v body=%s", err, rec.Body.String())
	}
	if cfg.Enabled || !cfg.DryRun || cfg.Threshold != 100 || cfg.WindowMinutes != 5 || cfg.Duration != "1h" || cfg.Scope != "all" {
		t.Fatalf("默认配置失真: %+v", cfg)
	}
}

func TestAutobanConfig_putValidRoundtrip(t *testing.T) {
	router := newAutobanTestEnv(t)
	body := map[string]any{"enabled": true, "threshold": 50, "window_minutes": 10, "duration": "6h", "scope": "blocked", "dry_run": false}
	rec := putJSON(t, router, "/security/autoban", body)
	if rec.Code != http.StatusOK {
		t.Fatalf("status=%d body=%s", rec.Code, rec.Body.String())
	}
	var got services.AutobanConfig
	if err := json.Unmarshal(getRequest(t, router, "/security/autoban").Body.Bytes(), &got); err != nil {
		t.Fatal(err)
	}
	if !got.Enabled || got.DryRun || got.Threshold != 50 || got.WindowMinutes != 10 || got.Duration != "6h" || got.Scope != "blocked" {
		t.Fatalf("回读失真: %+v", got)
	}
	if n := countAuditRows(t, "更新", "自动封禁"); n != 1 {
		t.Fatalf("更新审计=%d, want 1", n)
	}
}

func TestAutobanConfig_putRejectsInvalid(t *testing.T) {
	router := newAutobanTestEnv(t)
	cases := []map[string]any{
		{"threshold": 0},
		{"threshold": 10001},
		{"window_minutes": 0},
		{"window_minutes": 61},
		{"duration": "2h"},
		{"scope": "deny"},
	}
	for _, body := range cases {
		rec := putJSON(t, router, "/security/autoban", body)
		if rec.Code != http.StatusBadRequest {
			t.Fatalf("body=%v status=%d, want 400", body, rec.Code)
		}
	}
}

// ---- 立即执行 ----

func TestAutobanRun_requiresEngine(t *testing.T) {
	router := newAutobanTestEnv(t)
	if rec := postJSON(t, router, "/security/autoban/run", map[string]any{}); rec.Code != http.StatusServiceUnavailable {
		t.Fatalf("无引擎 status=%d, want 503", rec.Code)
	}
}

func TestAutobanRun_triggersEngine(t *testing.T) {
	router := newAutobanTestEnv(t)
	services.SetConfigLoadRerun(func(operator string) error { return nil })
	t.Cleanup(func() { services.SetConfigLoadRerun(nil) })
	te := services.InitTaskEngine("", t.TempDir()+"/app.log")
	t.Cleanup(te.Stop)

	rec := postJSON(t, router, "/security/autoban/run", map[string]any{})
	if rec.Code != http.StatusOK {
		t.Fatalf("status=%d body=%s", rec.Code, rec.Body.String())
	}
	if !strings.Contains(rec.Body.String(), "running") {
		t.Fatalf("响应应含 running: %s", rec.Body.String())
	}
	if n := countAuditRows(t, "触发", "自动封禁"); n != 1 {
		t.Fatalf("触发审计=%d, want 1", n)
	}
}

// servicesAutobanTodayStr 构造「配置时区的今天」的 created_at（UTC 墙钟串）：
// loc 今天正午 → 转 UTC 存储。
func servicesAutobanTodayStr(t *testing.T) string {
	t.Helper()
	loc := services.CurrentLocation()
	now := time.Now().In(loc)
	noon := time.Date(now.Year(), now.Month(), now.Day(), 12, 0, 0, 0, loc)
	return noon.UTC().Format("2006-01-02 15:04:05")
}

// ---- 状态 ----

func TestAutobanStatus_shape(t *testing.T) {
	router := newAutobanTestEnv(t)
	seedAutobanListEntries(t, `[{"value":"198.51.100.1","remark":"自动封禁","created_at":"`+servicesAutobanTodayStr(t)+`"},{"value":"198.51.100.2","remark":"事件处置"}]`)
	rec := getRequest(t, router, "/security/autoban/status")
	if rec.Code != http.StatusOK {
		t.Fatalf("status=%d body=%s", rec.Code, rec.Body.String())
	}
	var resp struct {
		Data struct {
			Enabled        bool                         `json:"enabled"`
			DryRun         bool                         `json:"dry_run"`
			Threshold      int                          `json:"threshold"`
			WindowMinutes  int                          `json:"window_minutes"`
			Duration       string                       `json:"duration"`
			Scope          string                       `json:"scope"`
			BannedToday    int                          `json:"banned_today"`
			ListEntries    int                          `json:"list_entries"`
			ListReferenced bool                         `json:"list_referenced"`
			TrackedIPs     int                          `json:"tracked_ips"`
			Suggestions    []services.AutobanSuggestion `json:"suggestions"`
			Running        bool                         `json:"running"`
			LastRun        string                       `json:"last_run"`
			LastStatus     string                       `json:"last_status"`
		} `json:"data"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatalf("decode: %v body=%s", err, rec.Body.String())
	}
	s := resp.Data
	if s.BannedToday != 1 || s.ListEntries != 2 {
		t.Fatalf("今日封禁/名单数=%d/%d, want 1/2", s.BannedToday, s.ListEntries)
	}
	if s.ListReferenced {
		t.Fatal("无引用策略时 list_referenced 应为 false（黄条判据）")
	}
	if s.Running {
		t.Fatal("无引擎/未运行时 running 应为 false")
	}
	if !s.DryRun || s.Enabled {
		t.Fatalf("默认观察态失真: enabled=%v dry_run=%v", s.Enabled, s.DryRun)
	}
}

// ---- 预置名单例外 ----

func TestAutobanPreset_deleteRejected(t *testing.T) {
	router := newAutobanTestEnv(t)
	rec := deleteRequest(t, router, fmt.Sprintf("/security/ip-lists/%d", autobanPresetID(t)))
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("status=%d body=%s, want 400（预置名单禁删）", rec.Code, rec.Body.String())
	}
}

func TestAutobanPreset_updateEntriesAllowed(t *testing.T) {
	router := newAutobanTestEnv(t)
	id := autobanPresetID(t)
	rec := putJSON(t, router, fmt.Sprintf("/security/ip-lists/%d", id), map[string]any{
		"entries": `[{"value":"198.51.100.9","remark":"手动封禁"}]`,
	})
	if rec.Code != http.StatusOK {
		t.Fatalf("条目修改 status=%d body=%s, want 200", rec.Code, rec.Body.String())
	}
	entries := readAutobanListEntries(t, id)
	if len(entries) != 1 || entries[0].Value != "198.51.100.9" {
		t.Fatalf("条目修改未落库: %+v", entries)
	}
	// 改名拒绝（任务按名定位预置行）
	rec = putJSON(t, router, fmt.Sprintf("/security/ip-lists/%d", id), map[string]any{"name": "改名"})
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("改名 status=%d, want 400", rec.Code)
	}
}

func TestAutobanPreset_addAndRemoveManageSuppression(t *testing.T) {
	router := newAutobanTestEnv(t)
	id := autobanPresetID(t)
	rec := postJSON(t, router, fmt.Sprintf("/security/ip-lists/%d/ips", id), map[string]any{"value": "203.0.113.5"})
	if rec.Code != http.StatusOK {
		t.Fatalf("追加 status=%d body=%s, want 200", rec.Code, rec.Body.String())
	}
	entries := readAutobanListEntries(t, id)
	if len(entries) != 1 || entries[0].Value != "203.0.113.5" || entries[0].Remark != services.AutobanManualUnbanRemark {
		t.Fatalf("追加后条目=%+v（remark 须为手动封禁）", entries)
	}
	// 解封 → removed:true + 抑制表 30 天行
	rec = postJSON(t, router, fmt.Sprintf("/security/ip-lists/%d/remove-ip", id), map[string]any{"value": "203.0.113.5"})
	if rec.Code != http.StatusOK {
		t.Fatalf("移除 status=%d body=%s, want 200", rec.Code, rec.Body.String())
	}
	var until string
	err := db.DB.QueryRow(`SELECT suppressed_until FROM autoban_suppressed WHERE ip='203.0.113.5'`).Scan(&until)
	if err != nil {
		t.Fatalf("解封必须写抑制表: %v", err)
	}
	ts, perr := time.ParseInLocation("2006-01-02 15:04:05", until, time.UTC)
	if perr != nil || !ts.After(time.Now().UTC().Add(29*24*time.Hour)) {
		t.Fatalf("suppressed_until=%q, want ≈now+30d", until)
	}
}

// 威胁名单（system=1 非自动封禁）保持只读——既有门不因例外放宽。
func TestAutobanPreset_threatListsStayReadOnly(t *testing.T) {
	router := newAutobanTestEnv(t)
	var threatID int
	if err := db.DB.QueryRow(`SELECT id FROM security_ip_lists WHERE system=1 AND name<>?`, services.AutobanPresetListName).Scan(&threatID); err != nil {
		t.Fatalf("threat list missing: %v", err)
	}
	if rec := putJSON(t, router, fmt.Sprintf("/security/ip-lists/%d", threatID), map[string]any{"entries": "[]"}); rec.Code != http.StatusBadRequest {
		t.Fatalf("threat update status=%d, want 400", rec.Code)
	}
	if rec := postJSON(t, router, fmt.Sprintf("/security/ip-lists/%d/ips", threatID), map[string]any{"value": "1.2.3.4"}); rec.Code != http.StatusBadRequest {
		t.Fatalf("threat add status=%d, want 400", rec.Code)
	}
	if rec := postJSON(t, router, fmt.Sprintf("/security/ip-lists/%d/remove-ip", threatID), map[string]any{"value": "1.2.3.4"}); rec.Code != http.StatusBadRequest {
		t.Fatalf("threat remove status=%d, want 400", rec.Code)
	}
}

// ---- 导出 ----

func TestExportIPList_txtLines(t *testing.T) {
	router := newAutobanTestEnv(t)
	id := autobanPresetID(t)
	seedAutobanListEntries(t, `[{"value":"198.51.100.1","remark":"自动封禁"},{"value":"198.51.100.2","remark":""}]`)
	rec := getRequest(t, router, fmt.Sprintf("/security/ip-lists/%d/export", id))
	if rec.Code != http.StatusOK {
		t.Fatalf("status=%d body=%s", rec.Code, rec.Body.String())
	}
	if ct := rec.Header().Get("Content-Type"); !strings.Contains(ct, "text/plain") {
		t.Fatalf("content-type=%q, want text/plain", ct)
	}
	body := rec.Body.String()
	if !strings.Contains(body, "198.51.100.1 自动封禁") || !strings.Contains(body, "198.51.100.2") {
		t.Fatalf("导出内容失真:\n%s", body)
	}
}

func TestExportIPList_missing404(t *testing.T) {
	router := newAutobanTestEnv(t)
	if rec := getRequest(t, router, "/security/ip-lists/424242/export"); rec.Code != http.StatusNotFound {
		t.Fatalf("status=%d, want 404", rec.Code)
	}
}

// ---- 上限常量契约钉 ----

func TestAutobanListEntryCap_matchesHandlerCap(t *testing.T) {
	if services.AutobanListEntryCap != ipListMaxEntries {
		t.Fatalf("services.AutobanListEntryCap=%d != handlers ipListMaxEntries=%d（两值漂移会让任务写入被校验拒绝）",
			services.AutobanListEntryCap, ipListMaxEntries)
	}
}
