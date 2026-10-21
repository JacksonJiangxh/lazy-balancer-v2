package handlers

//   归一 off，旧 `mode!='off'` 口径使纯 stage1/2 部署显示 0。

import (
	"encoding/json"
	"net/http"
	"strings"
	"testing"

	"lazy-balancer-v2/internal/db"
	"lazy-balancer-v2/internal/models"
)

func TestGetSecurityOverview_activePoliciesCountsFeatureBearingStages(t *testing.T) {
	setupSecurityPolicyTestDB(t)
	router := newSecurityEventsRouter(t)

	// Given：三条启用策略——stage1 纯 ACL、stage2 纯限流、stage3 WAF、
	// 另有一条无任何特征的 off 空策略（不应计入）
	seed := func(name string, acl int, aclList string, rl int, rps int, mode string, custom string) {
		if _, err := db.DB.Exec(`INSERT INTO security_policies (name, mode, enabled, ip_acl_enabled, ip_acl_list, rate_limit_enabled, rate_limit_rps, custom_rules, policy_type)
			VALUES (?, ?, 1, ?, ?, ?, ?, ?, '')`,
			name, mode, acl, aclList, rl, rps, custom); err != nil {
			t.Fatal(err)
		}
	}
	seed("s1-纯ACL", 1, `["1.1.1.1"]`, 0, 0, "off", "[]")
	seed("s2-纯限流", 0, "[]", 1, 100, "off", "[]")
	seed("s3-纯WAF", 0, "[]", 0, 0, "blocking", "[]")
	if _, err := db.DB.Exec(`INSERT INTO security_policies (name, mode, enabled, policy_type) VALUES ('空策略', 'off', 1, 'stage3')`); err != nil {
		t.Fatal(err)
	}

	recorder := getRequest(t, router, "/security/overview")
	if recorder.Code != http.StatusOK {
		t.Fatalf("overview status=%d body=%s", recorder.Code, recorder.Body.String())
	}
	var resp struct {
		Code int                     `json:"code"`
		Data models.SecurityOverview `json:"data"`
	}
	if err := json.Unmarshal(recorder.Body.Bytes(), &resp); err != nil {
		t.Fatal(err)
	}

	// Then：三条特征策略全部计入（旧口径 mode!='off' 只数到 s3 一条）
	if resp.Data.ActivePolicies != 3 {
		t.Fatalf("active_policies=%d, want 3（特征口径：stage1/2/3 各 1，空策略不计）", resp.Data.ActivePolicies)
	}
}

// 总量口径披露：今日拦截/检测、7 天趋势、Top IP 均**不排除**私网/保留地址
// 事件（与大屏排除口径不同）——响应必须携带 includes_reserved=true 供前端
// tooltip 消歧，nil metrics 零面板分支同键常驻。
func TestGetSecurityOverview_disclosesReservedInclusiveTotals(t *testing.T) {
	setupSecurityPolicyTestDB(t)
	router := newSecurityEventsRouter(t)

	recorder := getRequest(t, router, "/security/overview")
	if recorder.Code != http.StatusOK {
		t.Fatalf("overview status=%d body=%s", recorder.Code, recorder.Body.String())
	}
	var resp struct {
		Data struct {
			IncludesReserved bool `json:"includes_reserved"`
		} `json:"data"`
	}
	if err := json.Unmarshal(recorder.Body.Bytes(), &resp); err != nil {
		t.Fatal(err)
	}
	if !resp.Data.IncludesReserved {
		t.Fatalf("includes_reserved=false, want true（总量含私网/保留地址事件须披露）: %s", recorder.Body.String())
	}

	// nil metrics 分支同键（零面板也须披露口径）
	oldMetrics := db.MetricsDB
	db.MetricsDB = nil
	t.Cleanup(func() { db.MetricsDB = oldMetrics })
	recorder = getRequest(t, router, "/security/overview")
	if recorder.Code != http.StatusOK {
		t.Fatalf("nil-metrics overview status=%d body=%s", recorder.Code, recorder.Body.String())
	}
	if !strings.Contains(recorder.Body.String(), `"includes_reserved":true`) {
		t.Fatalf("nil-metrics body=%s, want includes_reserved:true 常驻", recorder.Body.String())
	}
}
