package handlers

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/gin-gonic/gin"

	"lazy-balancer-v2/internal/config"
	"lazy-balancer-v2/internal/db"
)

func TestGetSecurityEventToastSummary_groupsAllEventsSinceCursor(t *testing.T) {
	setupSecurityPolicyTestDB(t)
	now := time.Now().UTC().Truncate(time.Second)
	// 基线事件用于取得 >0 的起始游标；随后 120 条必须全部计入聚合。
	baseline, err := db.MetricsDB.Exec(`INSERT INTO security_events
		(event_time, client_ip, method, uri, event_type, rule_triggered, rule_msg, action, duration_us, rule_name)
		VALUES (?, '185.199.108.9', 'GET', '/baseline', 'crs', '942100', 'SQL Injection', 'blocked', 1000, 'SQL注入')`,
		now.Format("2006-01-02 15:04:05"))
	if err != nil {
		t.Fatalf("baseline: %v", err)
	}
	baselineID, _ := baseline.LastInsertId()
	for i := 0; i < 120; i++ {
		_, err := db.MetricsDB.Exec(`INSERT INTO security_events
			(event_time, client_ip, method, uri, event_type, rule_triggered, rule_msg, action, duration_us, rule_name)
			VALUES (?, '93.184.216.7', 'GET', '/a', 'crs', '942100', 'SQL Injection', 'blocked', 1200, 'SQL注入')`,
			now.Format("2006-01-02 15:04:05"))
		if err != nil {
			t.Fatalf("seed: %v", err)
		}
	}

	gin.SetMode(gin.TestMode)
	h := &Handlers{cfg: &config.Config{}}
	router := gin.New()
	router.GET("/security/events/toast-summary", h.GetSecurityEventToastSummary)

	// 首次（since_id=0）只给高水位，不回放历史。
	first := httptest.NewRecorder()
	router.ServeHTTP(first, httptest.NewRequest(http.MethodGet, "/security/events/toast-summary?since_id=0&baseline=1", nil))
	var initial struct {
		Data struct {
			Groups []any `json:"groups"`
			NextID int64 `json:"next_id"`
		} `json:"data"`
	}
	if err := json.Unmarshal(first.Body.Bytes(), &initial); err != nil {
		t.Fatalf("initial decode: %v body=%s", err, first.Body.String())
	}
	if len(initial.Data.Groups) != 0 || initial.Data.NextID == 0 {
		t.Fatalf("initial groups=%d next=%d, want empty/nonzero", len(initial.Data.Groups), initial.Data.NextID)
	}

	// 从基线游标扫描：120 条必须聚合为一组 count=120（不按最新窗口截断）。
	second := httptest.NewRecorder()
	router.ServeHTTP(second, httptest.NewRequest(http.MethodGet,
		"/security/events/toast-summary?since_id="+itoa(baselineID), nil))
	var payload struct {
		Data struct {
			Groups []struct {
				ClientIP string `json:"client_ip"`
				Count    int64  `json:"count"`
				LastID   int64  `json:"last_id"`
			} `json:"groups"`
			NextID int64 `json:"next_id"`
		} `json:"data"`
	}
	if err := json.Unmarshal(second.Body.Bytes(), &payload); err != nil {
		t.Fatalf("summary decode: %v body=%s", err, second.Body.String())
	}
	if len(payload.Data.Groups) != 1 || payload.Data.Groups[0].Count != 120 {
		t.Fatalf("groups=%+v, want one group count=120", payload.Data.Groups)
	}
	if payload.Data.NextID != payload.Data.Groups[0].LastID {
		t.Fatalf("next=%d last=%d", payload.Data.NextID, payload.Data.Groups[0].LastID)
	}
}

func TestGetSecurityEventToastSummary_capsAggregationAtDefaultBudget(t *testing.T) {
	setupSecurityPolicyTestDB(t)
	now := time.Now().UTC().Truncate(time.Second).Format("2006-01-02 15:04:05")
	baseline, err := db.MetricsDB.Exec(`INSERT INTO security_events
		(event_time, client_ip, method, uri, event_type, rule_triggered, rule_msg, action)
		VALUES (?, '185.199.108.9', 'GET', '/baseline', 'crs', '942100', 'SQL Injection', 'blocked')`, now)
	if err != nil {
		t.Fatalf("baseline: %v", err)
	}
	baselineID, _ := baseline.LastInsertId()
	tx, err := db.MetricsDB.Begin()
	if err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 1300; i++ {
		if _, err := tx.Exec(`INSERT INTO security_events
			(event_time, client_ip, method, uri, event_type, rule_triggered, rule_msg, action)
			VALUES (?, '93.184.216.7', 'GET', '/a', 'crs', '942100', 'SQL Injection', 'blocked')`, now); err != nil {
			_ = tx.Rollback()
			t.Fatalf("seed: %v", err)
		}
	}
	if err := tx.Commit(); err != nil {
		t.Fatal(err)
	}

	gin.SetMode(gin.TestMode)
	h := &Handlers{cfg: &config.Config{}}
	router := gin.New()
	router.GET("/security/events/toast-summary", h.GetSecurityEventToastSummary)
	rec := httptest.NewRecorder()
	router.ServeHTTP(rec, httptest.NewRequest(http.MethodGet,
		"/security/events/toast-summary?since_id="+itoa(baselineID)+"&limit=5", nil))
	var payload struct {
		Data struct {
			Groups []struct {
				Count int64 `json:"count"`
			} `json:"groups"`
			NextID int64 `json:"next_id"`
		} `json:"data"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &payload); err != nil {
		t.Fatalf("decode: %v body=%s", err, rec.Body.String())
	}
	if len(payload.Data.Groups) != 1 || payload.Data.Groups[0].Count != 1200 {
		t.Fatalf("groups=%+v, want one group count=1200（默认 400/s×3s 上限）", payload.Data.Groups)
	}
	if payload.Data.NextID == baselineID {
		t.Fatalf("next_id 未推进")
	}
}

func itoa(v int64) string {
	if v == 0 {
		return "0"
	}
	negative := v < 0
	if negative {
		v = -v
	}
	var buf [20]byte
	i := len(buf)
	for v > 0 {
		i--
		buf[i] = byte('0' + v%10)
		v /= 10
	}
	if negative {
		i--
		buf[i] = '-'
	}
	return string(buf[i:])
}
