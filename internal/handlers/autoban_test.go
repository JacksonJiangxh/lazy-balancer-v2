package handlers

// 自动封禁（F73-A）端点与预置名单例外钉：
//   GET/PUT /security/autoban 六项配置（校验/审计；保存联动调度启停）
//   POST /security/autoban/run 已废除（2026-10-14 裁定：调度唯一前提=启用）
//   GET  /security/autoban/status 运行态+今日封禁+名单数+观察建议+引用状态
//   预置「自动封禁名单」（system=1）删 400/条目可改 200/删除条目即解封/导出 TXT

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

// ---- 保存联动调度（2026-10-14 用户裁定：调度唯一前提=业务启用） ----

// Given 引擎装配+PUT /security/autoban 保存。
// When enabled=true / enabled=false。
// Then 联动启停 autoban 循环调度（loop_on 跟随业务开关）。
func TestAutobanConfig_putTogglesLoopScheduling(t *testing.T) {
	router := newAutobanTestEnv(t)
	services.SetConfigLoadRerun(func(operator string) error { return nil })
	t.Cleanup(func() { services.SetConfigLoadRerun(nil) })
	te := services.InitTaskEngine("", t.TempDir()+"/app.log")
	t.Cleanup(te.Stop)

	base := map[string]any{"threshold": 100, "window_minutes": 5, "duration": "1h", "scope": "all", "dry_run": true}
	body := func(enabled bool) map[string]any {
		m := map[string]any{}
		for k, v := range base {
			m[k] = v
		}
		m["enabled"] = enabled
		return m
	}
	if rec := putJSON(t, router, "/security/autoban", body(true)); rec.Code != http.StatusOK {
		t.Fatalf("启用保存 status=%d body=%s", rec.Code, rec.Body.String())
	}
	if m, _ := te.Lookup(services.AutobanTaskID); !m.LoopOn {
		t.Fatal("enabled=true 保存应联动开启调度（StartLoop）")
	}
	if rec := putJSON(t, router, "/security/autoban", body(false)); rec.Code != http.StatusOK {
		t.Fatalf("禁用保存 status=%d body=%s", rec.Code, rec.Body.String())
	}
	if m, _ := te.Lookup(services.AutobanTaskID); m.LoopOn {
		t.Fatal("enabled=false 保存应联动停止调度（StopLoop）")
	}
}

// Given /security/autoban/run 端点已废除（前端无入口+手动执行语义收编进
// 「启用后按配置调度」模型）。
// When POST 该路径。
// Then 404。
func TestAutobanRun_endpointRemoved(t *testing.T) {
	router := newAutobanTestEnv(t)
	if rec := postJSON(t, router, "/security/autoban/run", map[string]any{}); rec.Code != http.StatusNotFound {
		t.Fatalf("status=%d, want 404（端点已删除）", rec.Code)
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
	// 今日封禁=审计事件计数（2026-10-15 用户裁定）：与名单条目现状解耦——
	// 种一条今日「自动封禁」审计行，名单条目（含已封禁形态）不再参与计数。
	if _, err := db.AuditDB.Exec(`INSERT INTO audit_log (username, action, resource, detail, ip_address, created_at) VALUES ('system', ?, 'IP 地址列表', 'IP：198.51.100.1', '', ?)`,
		services.AutobanAuditAction, servicesAutobanTodayStr(t)); err != nil {
		t.Fatal(err)
	}
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

func TestAutobanPreset_addAndRemoveEntries(t *testing.T) {
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
	// 删除条目即解封（2026-10-15 用户裁定）：removed:true + 条目离开名单，
	// 无抑制表写入——IP 重新达标会被再次封禁。
	rec = postJSON(t, router, fmt.Sprintf("/security/ip-lists/%d/remove-ip", id), map[string]any{"value": "203.0.113.5"})
	if rec.Code != http.StatusOK {
		t.Fatalf("移除 status=%d body=%s, want 200", rec.Code, rec.Body.String())
	}
	if body := rec.Body.String(); !strings.Contains(body, `"removed":true`) {
		t.Fatalf("移除响应须 removed:true, body=%s", body)
	}
	if entries := readAutobanListEntries(t, id); len(entries) != 0 {
		t.Fatalf("移除后条目应清空, 得到 %+v", entries)
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

// ---- AU-6（第 74 轮）：内置名单引用门提示语按名单名分流 ----

// Given 自动封禁预置名单（system=1，非威胁情报源）。
// When 信任名单引用它（内置名单引用门拒绝的唯一非法形态之一）。
// Then 400 提示语称「内置自动封禁名单」，不得误称「威胁情报名单」。
func TestCreatePolicy_builtinAutobanListRefMessageNamesAutoban(t *testing.T) {
	h := newBackupTestHandlers(t)
	gin.SetMode(gin.TestMode)
	router := gin.New()
	router.POST("/security/policies", h.CreateSecurityPolicy)
	var autobanID int64
	if err := db.DB.QueryRow(`SELECT id FROM security_ip_lists WHERE name=?`, services.AutobanPresetListName).Scan(&autobanID); err != nil {
		t.Fatalf("自动封禁预置名单缺失: %v", err)
	}
	body := fmt.Sprintf(`{"name":"au6","policy_type":"stage0","ip_whitelist_refs":"[%d]"}`, autobanID)
	req := httptest.NewRequest(http.MethodPost, "/security/policies", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	resp := httptest.NewRecorder()
	router.ServeHTTP(resp, req)
	if resp.Code != http.StatusBadRequest {
		t.Fatalf("status=%d body=%s, want 400", resp.Code, resp.Body.String())
	}
	if !strings.Contains(resp.Body.String(), "内置自动封禁名单") {
		t.Fatalf("提示语应按名单名分流（内置自动封禁名单）: %s", resp.Body.String())
	}
	if strings.Contains(resp.Body.String(), "威胁情报") {
		t.Fatalf("自动封禁名单不得被称作威胁情报名单: %s", resp.Body.String())
	}
}

// ---- AU-8/D5（第 74 轮）：PUT 禁用路径收尾接线 ----

// Given 名单含已到期自动条目+未到期自动条目；重载回调间谍。
// When PUT enabled=false（禁用保存）。
// Then 禁用收尾立即清除已到期条目并触发重载（禁用后无循环 flush 点）；未到期
// 条目保留；调度照常联动停止。
func TestAutobanConfig_putDisableFlushesExpiredEntries(t *testing.T) {
	router := newAutobanTestEnv(t)
	services.SetConfigLoadRerun(func(operator string) error { return nil })
	t.Cleanup(func() { services.SetConfigLoadRerun(nil) })
	te := services.InitTaskEngine("", t.TempDir()+"/app.log")
	t.Cleanup(te.Stop)
	id := autobanPresetID(t)
	seedAutobanListEntries(t, `[
		{"value":"198.51.100.1","remark":"自动封禁","created_at":"2026-10-13 10:00:00","expires_at":"2020-01-01 00:00:00"},
		{"value":"198.51.100.2","remark":"自动封禁","created_at":"2026-10-14 09:30:00","expires_at":"2099-01-01 00:00:00"}]`)
	reloads := 0
	services.SetAutobanReloader(func() error { reloads++; return nil })
	t.Cleanup(func() { services.SetAutobanReloader(nil) })

	body := map[string]any{"enabled": false, "threshold": 100, "window_minutes": 5, "duration": "1h", "scope": "all", "dry_run": true}
	if rec := putJSON(t, router, "/security/autoban", body); rec.Code != http.StatusOK {
		t.Fatalf("禁用保存 status=%d body=%s", rec.Code, rec.Body.String())
	}
	entries := readAutobanListEntries(t, id)
	if len(entries) != 1 || entries[0].Value != "198.51.100.2" {
		t.Fatalf("禁用收尾必须清除已到期条目并保留未到期条目: %+v", entries)
	}
	if reloads == 0 {
		t.Fatal("到期清理产生的名单变化必须触发重载（禁用后无循环 flush 点）")
	}
	if m, _ := te.Lookup(services.AutobanTaskID); m.LoopOn {
		t.Fatal("禁用保存仍应联动停止调度")
	}
}

// ---- 预置名单三字段锁定（2026-10-14 用户裁定：名称/分类/描述禁改） ----

// Given 预置「自动封禁名单」（名称已禁改）。
// When PUT 变更分类/描述。
// Then 400（文案与名称同款）；同值提交不受影响（仅「变更」被拦）。
func TestAutobanPreset_categoryDescriptionLocked(t *testing.T) {
	router := newAutobanTestEnv(t)
	id := autobanPresetID(t)

	rec := putJSON(t, router, fmt.Sprintf("/security/ip-lists/%d", id), map[string]any{"category": "自定义分类"})
	if rec.Code != http.StatusBadRequest || !strings.Contains(rec.Body.String(), "分类不可修改") {
		t.Fatalf("变更分类 status=%d body=%s, want 400+分类不可修改", rec.Code, rec.Body.String())
	}
	rec = putJSON(t, router, fmt.Sprintf("/security/ip-lists/%d", id), map[string]any{"description": "自定义描述"})
	if rec.Code != http.StatusBadRequest || !strings.Contains(rec.Body.String(), "描述不可修改") {
		t.Fatalf("变更描述 status=%d body=%s, want 400+描述不可修改", rec.Code, rec.Body.String())
	}

	// 回归形状：同值提交（分类/描述与种子一致）放行
	rec = putJSON(t, router, fmt.Sprintf("/security/ip-lists/%d", id), map[string]any{
		"category":    "自动封禁",
		"description": "自动封禁命中 IP（自动封禁任务维护；可手动追加或删除条目）",
	})
	if rec.Code != http.StatusOK {
		t.Fatalf("同值提交 status=%d body=%s, want 200（仅拦「变更」）", rec.Code, rec.Body.String())
	}
}
