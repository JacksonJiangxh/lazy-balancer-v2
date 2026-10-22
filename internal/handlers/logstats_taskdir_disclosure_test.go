package handlers

// 日志统计读路径的口径契约：
//   - 三库更新行的 tasks 目录取引擎实际装配目录（taskengine.LogDir），不再
//     按运行日志目录自行推导（「日志写入器打开失败」时两者不同源 → 恒 0B）；
//   - 行数读取失败时显式披露 rows_unavailable（前端据此保持条数口径）；
//   - 聚合与单文件口径在「无 base、仅剩轮转副本」时一致（虚拟基名归并）。

import (
	"database/sql"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"

	"github.com/gin-gonic/gin"

	"lazy-balancer-v2/internal/db"
	"lazy-balancer-v2/internal/taskengine"
)

type logStatsRowsOnlyResponse struct {
	Data struct {
		Logs []struct {
			Key             string `json:"key"`
			SizeBytes       int64  `json:"size_bytes"`
			RotatedBytes    int64  `json:"rotated_bytes"`
			RotatedCount    int    `json:"rotated_count"`
			Rows            *int64 `json:"rows"`
			RowsUnavailable bool   `json:"rows_unavailable"`
		} `json:"logs"`
	} `json:"data"`
}

func fetchLogStatsRows(t *testing.T, handler gin.HandlerFunc, query string) logStatsRowsOnlyResponse {
	t.Helper()
	gin.SetMode(gin.TestMode)
	router := gin.New()
	router.GET("/logs/stats", handler)
	rec := httptest.NewRecorder()
	router.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/logs/stats"+query, nil))
	if rec.Code != http.StatusOK {
		t.Fatalf("status=%d body=%s", rec.Code, rec.Body.String())
	}
	var resp logStatsRowsOnlyResponse
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatalf("decode: %v body=%s", err, rec.Body.String())
	}
	return resp
}

func logStatsRowByKey(resp logStatsRowsOnlyResponse, key string) (int64, int64, int, bool) {
	for _, row := range resp.Data.Logs {
		if row.Key == key {
			return row.SizeBytes, row.RotatedBytes, row.RotatedCount, true
		}
	}
	return 0, 0, 0, false
}

// 三库更新行的目录必须与写入端（引擎装配目录）同源——自定义 LOG_FILE 且
// 日志写入器打开失败时，引擎按 /app/logs/tasks 回落，而统计侧若仍按
// dir(LOG_FILE)/tasks 推导会读错目录、恒 0B（同响应内逐任务行却有值）。
func TestGetLogStats_threeUpdateRowsFollowTaskEngineLogDir(t *testing.T) {
	h := newBackupTestHandlers(t)
	engineTasks := filepath.Join(t.TempDir(), "engine-tasks")
	oldLogDir := taskengine.LogDir()
	taskengine.SetLogDir(engineTasks)
	t.Cleanup(func() { taskengine.SetLogDir(oldLogDir) })
	// 运行日志目录与引擎任务目录不同源（模拟 fallback 形态）。
	h.cfg.LogFile = filepath.Join(t.TempDir(), "other-logs", "lazy-balancer.log")
	if err := os.MkdirAll(engineTasks, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(engineTasks, "crs.log"), make([]byte, 42), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(engineTasks, "threat.log"), make([]byte, 17), 0o644); err != nil {
		t.Fatal(err)
	}

	resp := fetchLogStatsRows(t, h.GetLogStats, "?keys=crs_update,threat_update")
	if size, _, _, ok := logStatsRowByKey(resp, "crs_update"); !ok || size != 42 {
		t.Fatalf("crs_update size=%d found=%v, want 42（目录须取 taskengine.LogDir）", size, ok)
	}
	if size, _, _, ok := logStatsRowByKey(resp, "threat_update"); !ok || size != 17 {
		t.Fatalf("threat_update size=%d found=%v, want 17", size, ok)
	}
}

// 行数计数失败时响应必须显式披露（rows 缺席 + rows_unavailable=true），
// 不得只留空值让前端静默退回字节口径。
func TestGetLogStats_disclosesRowsUnavailableOnCountFailure(t *testing.T) {
	h := newBackupTestHandlers(t)
	resetLogStatsRowCountCacheForTest()
	t.Cleanup(resetLogStatsRowCountCacheForTest)

	healthy := db.MetricsDB
	broken, err := sql.Open("sqlite", filepath.Join(t.TempDir(), "no-security-events.db"))
	if err != nil {
		t.Fatalf("open broken metrics db: %v", err)
	}
	db.MetricsDB = broken
	t.Cleanup(func() {
		db.MetricsDB = healthy
		_ = broken.Close()
	})

	resp := fetchLogStatsRows(t, h.GetLogStats, "?keys=security_events")
	var row *struct {
		Rows            *int64
		RowsUnavailable bool
	}
	for i := range resp.Data.Logs {
		if resp.Data.Logs[i].Key == "security_events" {
			row = &struct {
				Rows            *int64
				RowsUnavailable bool
			}{Rows: resp.Data.Logs[i].Rows, RowsUnavailable: resp.Data.Logs[i].RowsUnavailable}
		}
	}
	if row == nil {
		t.Fatalf("security_events 行缺失: %s", "response")
	}
	if row.Rows != nil {
		t.Fatalf("rows=%v, want 缺席（失败不以 0 冒充）", *row.Rows)
	}
	if !row.RowsUnavailable {
		t.Fatal("rows_unavailable=false, want true（计数失败须披露）")
	}
}

// 聚合口径与单文件口径在「base 已缺席、仅剩 .N 副本」时一致。
func TestAggregateDirStats_countsRotationCopiesWithMissingBase(t *testing.T) {
	dir := t.TempDir()
	// Given：caddy.log 已被删除/改名，只剩 .1/.2 移位副本。
	if err := os.WriteFile(filepath.Join(dir, "caddy.log.1"), make([]byte, 30), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "caddy.log.2"), make([]byte, 20), 0o644); err != nil {
		t.Fatal(err)
	}
	// 兄弟文件的副本不得被吞入（caddy-tls 与 caddy 是不同基名）。
	if err := os.WriteFile(filepath.Join(dir, "caddy-tls.log.1"), make([]byte, 7), 0o644); err != nil {
		t.Fatal(err)
	}

	stats := aggregateDirStats(dir, caddyLogFamilyMatch)
	caddy := stats["caddy.log"]
	if caddy.Active != 0 || caddy.Rotated != 50 || caddy.RotCount != 2 {
		t.Fatalf("aggregate caddy.log=%+v, want Active=0 Rotated=50 RotCount=2", caddy)
	}

	// Then：与单文件 dirBytes 口径一致（同一响应内两行不得分叉）。
	active, rotated, count := dirBytes(filepath.Join(dir, "caddy.log"))
	if active != caddy.Active || rotated != caddy.Rotated || count != caddy.RotCount {
		t.Fatalf("dirBytes=(%d,%d,%d) vs aggregate=(%d,%d,%d), 两套口径分叉",
			active, rotated, count, caddy.Active, caddy.Rotated, caddy.RotCount)
	}
	if tls := stats["caddy-tls.log"]; tls.Rotated != 7 || tls.RotCount != 1 {
		t.Fatalf("aggregate caddy-tls.log=%+v, want Rotated=7 RotCount=1", tls)
	}
}

// timberjack 时间戳副本在 base 缺席时同样归到派生基名。
func TestAggregateDirStats_countsTimberjackCopyWithMissingBase(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "certjob-lb_x-20261018-101500-64-size.log"), make([]byte, 12), 0o644); err != nil {
		t.Fatal(err)
	}
	stats := aggregateDirStats(dir, isCertJobLogName)
	entry := stats["certjob-lb_x.log"]
	if entry.Rotated != 12 || entry.RotCount != 1 {
		t.Fatalf("aggregate=%+v, want Rotated=12 RotCount=1（base 缺席时按派生基名归并）", entry)
	}
	active, rotated, count := dirBytes(filepath.Join(dir, "certjob-lb_x.log"))
	if active != entry.Active || rotated != entry.Rotated || count != entry.RotCount {
		t.Fatalf("dirBytes=(%d,%d,%d) vs aggregate=(%d,%d,%d), 两套口径分叉",
			active, rotated, count, entry.Active, entry.Rotated, entry.RotCount)
	}
}
