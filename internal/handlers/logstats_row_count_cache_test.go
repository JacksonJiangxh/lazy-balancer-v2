package handlers

// 日志统计全表 COUNT(*) 的节流与失败可见性：5s 进程内缓存让连续全量请求只付
// 一次全表计数；读失败不缓存（下一请求重试）且留痕（首报 warn、恢复 info），
// 不再把「行数缺失」与「表为空」在响应中混为一谈。

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/gin-gonic/gin"

	"lazy-balancer-v2/internal/db"
)

type logStatsResponseRows struct {
	Data struct {
		Logs []struct {
			Key  string `json:"key"`
			Rows *int64 `json:"rows"`
		} `json:"logs"`
	} `json:"data"`
}

func fetchLogStats(t *testing.T, handler gin.HandlerFunc, query string) logStatsResponseRows {
	t.Helper()
	gin.SetMode(gin.TestMode)
	router := gin.New()
	router.GET("/logs/stats", handler)
	recorder := httptest.NewRecorder()
	router.ServeHTTP(recorder, httptest.NewRequest(http.MethodGet, "/logs/stats"+query, nil))
	if recorder.Code != http.StatusOK {
		t.Fatalf("status=%d body=%s", recorder.Code, recorder.Body.String())
	}
	var response logStatsResponseRows
	if err := json.Unmarshal(recorder.Body.Bytes(), &response); err != nil {
		t.Fatalf("decode response: %v body=%s", err, recorder.Body.String())
	}
	return response
}

func formatRowCount(rows *int64) string {
	if rows == nil {
		return "缺席"
	}
	return itoa64(*rows)
}

func auditRowCountFromLogStats(t *testing.T, response logStatsResponseRows) *int64 {
	t.Helper()
	for i := range response.Data.Logs {
		if response.Data.Logs[i].Key == "audit" {
			return response.Data.Logs[i].Rows
		}
	}
	t.Fatalf("响应缺少 audit 行: %+v", response.Data.Logs)
	return nil
}

func seedAuditRows(t *testing.T, count int) {
	t.Helper()
	for i := range count {
		if _, err := db.AuditDB.Exec(`INSERT INTO audit_log (username, action, resource, detail) VALUES ('tester','测试','测试',?)`, "seed-"+itoa64(int64(i))); err != nil {
			t.Fatalf("seed audit row: %v", err)
		}
	}
}

func TestGetLogStats_auditRowCountCachedAndFailureNotCached(t *testing.T) {
	h := newBackupTestHandlers(t)
	h.cfg.DataDir = t.TempDir()
	resetLogStatsRowCountCacheForTest()
	t.Cleanup(resetLogStatsRowCountCacheForTest)

	// Given 审计库 2 行，且本次请求族不含 audit 计数（未预热缓存）。
	seedAuditRows(t, 2)

	// When 审计表不可读（库故障形态）时请求 audit 行。
	if _, err := db.AuditDB.Exec(`ALTER TABLE audit_log RENAME TO audit_log_unavailable`); err != nil {
		t.Fatalf("simulate count failure: %v", err)
	}
	logs := captureLog(t)
	failed := fetchLogStats(t, h.GetLogStats, "?keys=audit")

	// Then 行数字段缺席（不再以「0 行」冒充空表），且留痕一次。
	if rows := auditRowCountFromLogStats(t, failed); rows != nil {
		t.Fatalf("COUNT 失败时 rows=%d, want 缺席", *rows)
	}
	if !strings.Contains(logs.String(), "logstats-audit-count") || !strings.Contains(logs.String(), "失败") {
		t.Fatalf("COUNT 失败未留痕: %s", logs.String())
	}

	// When 表恢复可读 → 下一请求必须重试（失败不被缓存）。
	if _, err := db.AuditDB.Exec(`ALTER TABLE audit_log_unavailable RENAME TO audit_log`); err != nil {
		t.Fatalf("restore audit table: %v", err)
	}
	recovered := fetchLogStats(t, h.GetLogStats, "?keys=audit")

	// Then 得到真实行数，并补一条恢复留痕。
	if rows := auditRowCountFromLogStats(t, recovered); rows == nil || *rows != 2 {
		t.Fatalf("恢复后 rows=%s, want 2", formatRowCount(rows))
	}
	if !strings.Contains(logs.String(), "已恢复") {
		t.Fatalf("恢复未留痕: %s", logs.String())
	}

	// When 写入 3 行后立刻再请求（TTL 窗口内）。
	seedAuditRows(t, 3)
	cached := fetchLogStats(t, h.GetLogStats, "?keys=audit")

	// Then 命中缓存：不重查全表（值仍为 2）。
	if rows := auditRowCountFromLogStats(t, cached); rows == nil || *rows != 2 {
		t.Fatalf("TTL 内 rows=%s, want 2（连续请求只打一次 COUNT）", formatRowCount(rows))
	}

	// Then 缓存清空后重新计数得到 5——证明上一步是缓存命中而非读错。
	resetLogStatsRowCountCacheForTest()
	fresh := fetchLogStats(t, h.GetLogStats, "?keys=audit")
	if rows := auditRowCountFromLogStats(t, fresh); rows == nil || *rows != 5 {
		t.Fatalf("清缓存后 rows=%s, want 5", formatRowCount(rows))
	}
}
