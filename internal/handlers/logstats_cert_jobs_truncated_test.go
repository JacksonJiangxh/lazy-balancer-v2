package handlers

// cert_jobs_truncated 契约：证书动态行触达上限时任务族清单被截断，单行与全量
// 响应都必须携带该标记（此前消费端直接丢弃，「列表少了」与「本来就没有」不可
// 区分）；未枚举任务族（单行非 task: 请求）时恒 false。

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/gin-gonic/gin"

	"lazy-balancer-v2/internal/db"
)

type logStatsTruncationResponse struct {
	Data struct {
		CertJobsTruncated bool `json:"cert_jobs_truncated"`
		Logs              []struct {
			Key string `json:"key"`
		} `json:"logs"`
	} `json:"data"`
}

func fetchLogStatsTruncation(t *testing.T, handler gin.HandlerFunc, query string) logStatsTruncationResponse {
	t.Helper()
	gin.SetMode(gin.TestMode)
	router := gin.New()
	router.GET("/logs/stats", handler)
	recorder := httptest.NewRecorder()
	router.ServeHTTP(recorder, httptest.NewRequest(http.MethodGet, "/logs/stats"+query, nil))
	if recorder.Code != http.StatusOK {
		t.Fatalf("status=%d body=%s", recorder.Code, recorder.Body.String())
	}
	var response logStatsTruncationResponse
	if err := json.Unmarshal(recorder.Body.Bytes(), &response); err != nil {
		t.Fatalf("decode response: %v body=%s", err, recorder.Body.String())
	}
	return response
}

func seedCertJobRows(t *testing.T, count int) {
	t.Helper()
	for i := range count {
		if _, err := db.DB.Exec(`INSERT INTO cert_jobs (rule_id, domain, status, created_at, updated_at) VALUES ('lb_trunc',?, 'issued', datetime('now'), datetime('now'))`,
			"trunc"+itoa64(int64(i))+".example.test"); err != nil {
			t.Fatalf("seed cert job %d: %v", i, err)
		}
	}
}

func TestGetLogStats_reportsCertJobTruncationInBothShapes(t *testing.T) {
	h := newBackupTestHandlers(t)
	initTaskEngineForTest(t)
	h.cfg.DataDir = t.TempDir()

	// Given 证书动态行超过任务视图上限（101 行 → 触达截断探针）。
	seedCertJobRows(t, 101)

	// When/Then 全量请求：携带截断标记，且动态行不多于上限。
	full := fetchLogStatsTruncation(t, h.GetLogStats, "")
	if !full.Data.CertJobsTruncated {
		t.Fatalf("全量请求 cert_jobs_truncated=false, want true（%d 行触达上限）", 101)
	}
	certJobRows := 0
	for _, row := range full.Data.Logs {
		if strings.HasPrefix(row.Key, "task:cert-job:") {
			certJobRows++
		}
	}
	if certJobRows > 100 {
		t.Fatalf("cert-job 日志行=%d, want ≤100（截断上限）", certJobRows)
	}

	// When/Then 单行 task: 请求：同样携带标记（同一枚举面）。
	var singleJobID int
	if err := db.DB.QueryRow(`SELECT id FROM cert_jobs ORDER BY id LIMIT 1`).Scan(&singleJobID); err != nil {
		t.Fatal(err)
	}
	single := fetchLogStatsTruncation(t, h.GetLogStats, "?keys=task:cert-job:"+itoa64(int64(singleJobID)))
	if !single.Data.CertJobsTruncated {
		t.Fatal("单行 task: 请求 cert_jobs_truncated=false, want true")
	}

	// Then 未枚举任务族的单行请求恒 false。
	noEnumeration := fetchLogStatsTruncation(t, h.GetLogStats, "?keys=runtime")
	if noEnumeration.Data.CertJobsTruncated {
		t.Fatal("未枚举任务族时 cert_jobs_truncated=true, want false")
	}

	// When 动态行回落到上限内。
	if _, err := db.DB.Exec(`DELETE FROM cert_jobs WHERE id NOT IN (SELECT id FROM cert_jobs ORDER BY id LIMIT 2)`); err != nil {
		t.Fatalf("shrink cert jobs: %v", err)
	}

	// Then 不再标记截断（不得恒真）。
	notTruncated := fetchLogStatsTruncation(t, h.GetLogStats, "")
	if notTruncated.Data.CertJobsTruncated {
		t.Fatal("行数未触顶时 cert_jobs_truncated=true, want false")
	}
}
