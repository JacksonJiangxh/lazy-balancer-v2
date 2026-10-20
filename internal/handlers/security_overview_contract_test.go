package handlers

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"

	"github.com/gin-gonic/gin"

	"lazy-balancer-v2/internal/db"
)

// 历史修复1：规则近 24h 无任何事件时，耗时聚合的两个 COUNT 列为 SQL NULL——
// 正常空窗口不得被当成查询故障（修复前 Scan 失败 → warn + 全 0）。
func TestQueryRuleStageTimings_emptyWindowIsNotAnError(t *testing.T) {
	setupSecurityPolicyTestDB(t)
	// 规则存在但 24h 内零事件
	if _, err := db.MetricsDB.Exec(`INSERT INTO security_events (event_time, rule_caddy_id, action) VALUES (datetime('now','-40 day'),'lb_empty','blocked')`); err != nil {
		t.Fatal(err)
	}

	preAvg, preCnt, wafAvg, wafCnt, err := queryRuleStageTimings("lb_empty")
	if err != nil {
		t.Fatalf("空窗口不得报查询故障: %v", err)
	}
	if preAvg != 0 || preCnt != 0 || wafAvg != 0 || wafCnt != 0 {
		t.Fatalf("空窗口 timing=(%v,%d,%v,%d), want 全 0", preAvg, preCnt, wafAvg, wafCnt)
	}
}

// 历史修复1 回归：有事件时计数与均值照常。
func TestQueryRuleStageTimings_countsSamples(t *testing.T) {
	setupSecurityPolicyTestDB(t)
	if _, err := db.MetricsDB.Exec(`INSERT INTO security_events (event_time, rule_caddy_id, action, precheck_us, duration_us, rule_triggered) VALUES
		(datetime('now','-1 hour'),'lb_hot','blocked',100,0,'2'),
		(datetime('now','-1 hour'),'lb_hot','blocked',300,0,'2')`); err != nil {
		t.Fatal(err)
	}
	preAvg, preCnt, wafCnt := 0.0, 0, 0
	var wafAvg float64
	var err error
	preAvg, preCnt, wafAvg, wafCnt, err = queryRuleStageTimings("lb_hot")
	if err != nil {
		t.Fatal(err)
	}
	if preCnt != 2 || preAvg != 200 || wafCnt != 0 || wafAvg != 0 {
		t.Fatalf("timing=(%v,%d,%v,%d), want (200,2,0,0)", preAvg, preCnt, wafAvg, wafCnt)
	}
}

// 历史修复1：分页参数拼写错误必须 400（与同端点时间参数口径一致）；数值越界
// 仍按既有契约钳制/回落。
func TestListSecurityEvents_paginationRejectsNonNumeric(t *testing.T) {
	setupSecurityPolicyTestDB(t)
	router := newSecurityEventsRouter(t)

	for _, query := range []string{"page=abc", "page_size=xyz", "page=1.5", "page_size=2x"} {
		rec := httptest.NewRecorder()
		router.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/security/events?"+query, nil))
		if rec.Code != http.StatusBadRequest {
			t.Fatalf("query=%s status=%d body=%s, want 400", query, rec.Code, rec.Body.String())
		}
		if !strings.Contains(rec.Body.String(), "分页参数无效") {
			t.Fatalf("query=%s body=%s, want 分页参数无效", query, rec.Body.String())
		}
	}
	// 回归：缺省与数值形态仍正常
	for _, query := range []string{"", "page=2&page_size=50", "page_size=0", "page_size=150"} {
		rec := httptest.NewRecorder()
		router.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/security/events?"+query, nil))
		if rec.Code != http.StatusOK {
			t.Fatalf("query=%q status=%d body=%s, want 200", query, rec.Code, rec.Body.String())
		}
	}
}

// 第三方凭据头（x-api-key / x-auth-token / x-csrf-token /
// x-forwarded-access-token / x-amz-security-token）必须与非管理员掩码口径一致。
func TestListSecurityEvents_masksThirdPartyCredentialHeaders(t *testing.T) {
	setupSecurityPolicyTestDB(t)
	headers := `{"X-Api-Key":"api-secret","X-Auth-Token":"auth-secret","X-Csrf-Token":"csrf-secret","X-Forwarded-Access-Token":"fwd-secret","X-Amz-Security-Token":"amz-secret","X-Request-ID":"ok"}`
	if _, err := db.MetricsDB.Exec(`INSERT INTO security_events (event_time,client_ip,method,uri,event_type,rule_triggered,rule_msg,action,request_headers)
		VALUES ('2026-10-18 10:00:00','203.0.113.8','POST','/api','crs','942100','SQL Injection','blocked',?)`, headers); err != nil {
		t.Fatal(err)
	}
	router := gin.New()
	router.Use(func(c *gin.Context) {
		c.Set("role", "user")
		c.Set("auth_type", "jwt")
	})
	router.GET("/security/events", (&Handlers{}).ListSecurityEvents)

	rec := httptest.NewRecorder()
	router.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/security/events", nil))
	if rec.Code != http.StatusOK {
		t.Fatalf("status=%d body=%s", rec.Code, rec.Body.String())
	}
	var payload struct {
		Data struct {
			Events []struct {
				RequestHeaders string `json:"request_headers"`
			} `json:"events"`
		} `json:"data"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &payload); err != nil {
		t.Fatal(err)
	}
	if len(payload.Data.Events) != 1 {
		t.Fatalf("events=%d, want 1", len(payload.Data.Events))
	}
	got := payload.Data.Events[0].RequestHeaders
	for _, secret := range []string{"api-secret", "auth-secret", "csrf-secret", "fwd-secret", "amz-secret"} {
		if strings.Contains(got, secret) {
			t.Fatalf("凭据头原文泄露 (%s): %s", secret, got)
		}
	}
	if !strings.Contains(got, "X-Request-ID") {
		t.Fatalf("非敏感头名必须保留: %s", got)
	}
}

// 历史修复2：crs_rule_groups / crs_excluded_rules 旧格式单条校验单源——非法字符
// 文案一致，且 crs_rule_groups 的「形态优先于首尾空白」报错优先级保持。
func TestCRSLegacyEntryValidation_singleSourceOrdering(t *testing.T) {
	groups := `["94 2"]`
	if err := validateAndNormalizeCRSField("crs_rule_groups", &groups, false); err == nil || !strings.Contains(err.Error(), "非法字符") {
		t.Fatalf("crs_rule_groups err=%v, want 非法字符", err)
	}
	excluded := `["94 2"]`
	if err := validateAndNormalizeCRSField("crs_excluded_rules", &excluded, false); err == nil || !strings.Contains(err.Error(), "非法字符") {
		t.Fatalf("crs_excluded_rules err=%v, want 非法字符", err)
	}

	// 形态优先：「942 」先报组号形态，不是首尾空白（历史问题 口径）
	spaced := `["942 "]`
	err := validateAndNormalizeCRSField("crs_rule_groups", &spaced, false)
	if err == nil || !strings.Contains(err.Error(), "两位数字组号") {
		t.Fatalf("crs_rule_groups err=%v, want 组号形态错误优先", err)
	}
	// 排除项：首尾空白先于有效性检查（既有口径）
	excludedSpaced := `[" 942100"]`
	err = validateAndNormalizeCRSField("crs_excluded_rules", &excludedSpaced, false)
	if err == nil || !strings.Contains(err.Error(), "首尾空白") {
		t.Fatalf("crs_excluded_rules err=%v, want 首尾空白", err)
	}
}

// 历史修复5：已启用且 failed 的威胁源重复提交 update_enabled=true 不得只清文案
// 而保留 failed 状态（状态机归一对齐禁用分支）。
func TestUpdateThreatSourceFlags_enableStateMachineNormalized(t *testing.T) {
	router := newThreatTestRouter(t)
	var id int
	if err := db.DB.QueryRow(`SELECT id FROM security_threat_sources WHERE name='ustc'`).Scan(&id); err != nil {
		t.Fatal(err)
	}
	put := func() {
		rec := httptest.NewRecorder()
		req := httptest.NewRequest(http.MethodPut, "/security/threat-lib/"+strconv.Itoa(id)+"/flags", strings.NewReader(`{"update_enabled":true}`))
		req.Header.Set("Content-Type", "application/json")
		router.ServeHTTP(rec, req)
		if rec.Code != http.StatusOK {
			t.Fatalf("status=%d body=%s", rec.Code, rec.Body.String())
		}
	}

	// 已启用 + failed：保持 failed 与失败文案/计数（此前只清 message）
	if _, err := db.DB.Exec(`UPDATE security_threat_sources SET update_enabled=1, update_status='failed', message='boom', consecutive_failures=3 WHERE id=?`, id); err != nil {
		t.Fatal(err)
	}
	put()
	status, message, failures := threatRowState(t, id)
	if status != "failed" || message != "boom" || failures != 3 {
		t.Fatalf("already-enabled source state=(%s,%q,%d), want (failed,boom,3)（不得清文案留 failed）", status, message, failures)
	}

	// 关闭 → 启用：清失败态
	if _, err := db.DB.Exec(`UPDATE security_threat_sources SET update_enabled=0, update_status='idle', message='已关闭自动更新', consecutive_failures=2 WHERE id=?`, id); err != nil {
		t.Fatal(err)
	}
	put()
	status, message, failures = threatRowState(t, id)
	if status != "idle" || message != "" || failures != 0 {
		t.Fatalf("re-enabled source state=(%s,%q,%d), want (idle,\"\",0)", status, message, failures)
	}
}

func threatRowState(t *testing.T, id int) (string, string, int) {
	t.Helper()
	var status, message string
	var failures int
	if err := db.DB.QueryRow(`SELECT update_status, COALESCE(message,''), COALESCE(consecutive_failures,0) FROM security_threat_sources WHERE id=?`, id).Scan(&status, &message, &failures); err != nil {
		t.Fatal(err)
	}
	return status, message, failures
}
