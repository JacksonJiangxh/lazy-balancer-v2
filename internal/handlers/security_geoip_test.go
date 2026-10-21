package handlers

import (
	"encoding/json"
	"lazy-balancer-v2/internal/services"
	"net/http"
	"strconv"
	"strings"
	"testing"
)

// TestCreateSecurityPolicy_geoipColumnsRoundTrip verifies that geoip_countries
// and geoip_mode are persisted on create and returned by GetSecurityPolicy.
func TestCreateSecurityPolicy_geoipColumnsRoundTrip(t *testing.T) {
	// 历史问题：地域条目（含海外）现要求 IP 库已装载——注入 live 省份
	// 模拟 xdb 在位（生产由 InitIP2Region 装载驱动）。
	services.SetIP2RegionLiveProvincesForTest([]string{"海外", "广东省", "北京市"})
	t.Cleanup(func() { services.SetIP2RegionLiveProvincesForTest(nil) })
	// Given a fresh database and a policy payload carrying geoip fields
	setupSecurityPolicyTestDB(t)
	router := newSecurityRouter(t)
	payload := map[string]any{
		"name":            "地理围栏策略",
		"mode":            "off",
		"geoip_countries": `["海外"]`,
		"geoip_mode":      "deny",
	}
	id := createTestPolicy(t, router, payload)

	// When the policy is read back
	recorder := getRequest(t, router, "/security/policies/"+strconv.Itoa(id))

	// Then the detail carries the geoip fields unchanged
	if recorder.Code != http.StatusOK {
		t.Fatalf("get policy status=%d body=%s", recorder.Code, recorder.Body.String())
	}
	var resp struct {
		Code int `json:"code"`
		Data struct {
			Policy map[string]any `json:"policy"`
		} `json:"data"`
	}
	if err := json.Unmarshal(recorder.Body.Bytes(), &resp); err != nil {
		t.Fatalf("parse get response: %v", err)
	}
	if got := resp.Data.Policy["geoip_countries"]; got != `["海外"]` {
		t.Fatalf("geoip_countries=%q, want %q", got, `["海外"]`)
	}
	if got := resp.Data.Policy["geoip_mode"]; got != "deny" {
		t.Fatalf("geoip_mode=%q, want deny", got)
	}
}

// TestCreateSecurityPolicy_geoipDefaults：省略 geoip 字段时名单落空、mode 落 off
// （历史修复 门：非 off + 空名单 = 「宣称启用但零强制」→ 400；缺省未显式
// 启用地域控制的创建因此归 off，与渲染端「条目非空才发射」等价）。
// 下方 TestCreateSecurityPolicy_geoipEnabledWithEmptyListRejected 钉住显式形态 400。
func TestCreateSecurityPolicy_geoipDefaults(t *testing.T) {
	// Given a fresh database and a policy payload without geoip fields
	setupSecurityPolicyTestDB(t)
	router := newSecurityRouter(t)
	id := createTestPolicy(t, router, map[string]any{"name": "无地理策略"})

	// When the policy is read back
	recorder := getRequest(t, router, "/security/policies/"+strconv.Itoa(id))

	// Then defaults are in place
	var resp struct {
		Code int `json:"code"`
		Data struct {
			Policy map[string]any `json:"policy"`
		} `json:"data"`
	}
	if err := json.Unmarshal(recorder.Body.Bytes(), &resp); err != nil {
		t.Fatalf("parse get response: %v", err)
	}
	if got := resp.Data.Policy["geoip_countries"]; got != "[]" {
		t.Fatalf("geoip_countries=%q, want []", got)
	}
	if got := resp.Data.Policy["geoip_mode"]; got != "off" {
		t.Fatalf("geoip_mode=%q, want off（空名单缺省不得宣称启用）", got)
	}
}

// TestCreateSecurityPolicy_geoipEnabledWithEmptyListRejected：显式 deny/allow +
// 空名单必须 400（历史修复 形态：落库后宣称仅允许所选地域但零发射）。
func TestCreateSecurityPolicy_geoipEnabledWithEmptyListRejected(t *testing.T) {
	setupSecurityPolicyTestDB(t)
	router := newSecurityRouter(t)
	recorder := postJSON(t, router, "/security/policies", map[string]any{
		"name":            "空名单策略",
		"geoip_mode":      "allow",
		"geoip_countries": "[]",
	})
	if recorder.Code != http.StatusBadRequest {
		t.Fatalf("mode=allow status=%d body=%s, want 400", recorder.Code, recorder.Body.String())
	}
	if !strings.Contains(recorder.Body.String(), "区域名单不能为空") {
		t.Fatalf("mode=allow body=%s, want 空名单门文案", recorder.Body.String())
	}
}

// TestUpdateSecurityPolicy_geoipMode_validatesEnum verifies that an invalid
// geoip_mode is rejected on update.
func TestUpdateSecurityPolicy_geoipMode_validatesEnum(t *testing.T) {
	// Given a fresh database with one policy
	setupSecurityPolicyTestDB(t)
	router := newSecurityRouter(t)
	id := createTestPolicy(t, router, map[string]any{"name": "待校验"})

	// When an update carries an invalid geoip_mode
	recorder := putJSON(t, router, "/security/policies/"+strconv.Itoa(id), map[string]any{
		"geoip_mode": "ban_all",
	})

	// Then it is rejected with 400
	if recorder.Code != http.StatusBadRequest {
		t.Fatalf("update status=%d, want 400: %s", recorder.Code, recorder.Body.String())
	}
	if !strings.Contains(recorder.Body.String(), "geoip_mode") {
		t.Fatalf("body=%s, want geoip_mode error", recorder.Body.String())
	}
}

// TestListSecurityPolicies_geoipSummary verifies the summary list exposes the
// geoip fields.
func TestListSecurityPolicies_geoipSummary(t *testing.T) {
	// 历史问题：地域条目（含海外）现要求 IP 库已装载——注入 live 省份
	// 模拟 xdb 在位（生产由 InitIP2Region 装载驱动）。
	services.SetIP2RegionLiveProvincesForTest([]string{"海外", "广东省", "北京市"})
	t.Cleanup(func() { services.SetIP2RegionLiveProvincesForTest(nil) })
	// Given a fresh database with a geoip policy
	setupSecurityPolicyTestDB(t)
	router := newSecurityRouter(t)
	createTestPolicy(t, router, map[string]any{
		"name":            "摘要地理",
		"geoip_countries": `["海外"]`,
		"geoip_mode":      "allow",
	})

	// When the list is fetched
	recorder := getRequest(t, router, "/security/policies")

	// Then the summary row carries the geoip fields
	if recorder.Code != http.StatusOK {
		t.Fatalf("list status=%d body=%s", recorder.Code, recorder.Body.String())
	}
	var resp struct {
		Code int              `json:"code"`
		Data []map[string]any `json:"data"`
	}
	if err := json.Unmarshal(recorder.Body.Bytes(), &resp); err != nil {
		t.Fatalf("parse list response: %v", err)
	}
	if len(resp.Data) == 0 {
		t.Fatal("list is empty")
	}
	if got := resp.Data[0]["geoip_countries"]; got != `["海外"]` {
		t.Fatalf("summary geoip_countries=%q, want [\"海外\"]", got)
	}
	if got := resp.Data[0]["geoip_mode"]; got != "allow" {
		t.Fatalf("summary geoip_mode=%q, want allow", got)
	}
}
