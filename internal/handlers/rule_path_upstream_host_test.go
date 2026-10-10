package handlers

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"lazy-balancer-v2/internal/db"
	"lazy-balancer-v2/internal/models"
)

// 自定义路由上游的回源 Host（2026-10-10 用户裁定）：自定义路由若选了「上游
// 服务器」，回源 Host 应遵循该上游自己配的回源 Host，为空才回退基础设置的
// 后端域名，再空才用回源域名（上游自身地址）。字段落在 path_rules.upstreams_json
// 的行内（同 upstreams 表列名 host_header），无需 DB 迁移。

// Given: 自定义路由上游携带 host_header
// When: 创建规则后读回
// Then: 值经 upstreams_json 完整往返（CreateRule → loadPathRulesBatch）
func TestCreateRule_pathUpstreamHostHeaderRoundTrips(t *testing.T) {
	router := newStaticResponseRouter(t)
	body := `{"name":"path-up-host","protocol":"http","domain":"path-up-host.test","listen_port":18591,` +
		`"custom_routes_enabled":true,"path_rules":[{"match_type":"prefix","path":"/api","sort_order":0,` +
		`"upstreams":[{"address":"127.0.0.1","port":9100,"weight":100,"protocol":"http","host_header":"api.internal"}]}],` +
		`"upstreams":[{"host":"127.0.0.1","port":9000,"enabled":true}]}`
	request := httptest.NewRequest(http.MethodPost, "/rules", strings.NewReader(body))
	request.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	router.ServeHTTP(rec, request)
	if rec.Code != http.StatusCreated && rec.Code != http.StatusOK {
		t.Fatalf("create status=%d body=%s", rec.Code, rec.Body.String())
	}

	var upstreamsJSON string
	if err := db.DB.QueryRow(`SELECT COALESCE(upstreams_json,'') FROM path_rules
		WHERE rule_id=(SELECT caddy_id FROM lb_rules WHERE name='path-up-host')`).Scan(&upstreamsJSON); err != nil {
		t.Fatalf("read persisted path rule: %v", err)
	}
	var stored []models.PathRuleUpstream
	if err := json.Unmarshal([]byte(upstreamsJSON), &stored); err != nil {
		t.Fatalf("decode upstreams_json: %v", err)
	}
	if len(stored) != 1 || stored[0].HostHeader != "api.internal" {
		t.Fatalf("upstreams_json=%s; want host_header=api.internal", upstreamsJSON)
	}

	// 读回路径（loadPathRulesBatch）同样还原该字段——前端编辑表单依赖它。
	rules, err := loadRulesForConfigValidation(context.Background(), "")
	if err != nil {
		t.Fatalf("loadRulesForConfigValidation: %v", err)
	}
	for _, rule := range rules {
		if rule.Name != "path-up-host" {
			continue
		}
		if len(rule.PathRules) != 1 || len(rule.PathRules[0].Upstreams) != 1 {
			t.Fatalf("loaded path rules=%+v", rule.PathRules)
		}
		if got := rule.PathRules[0].Upstreams[0].HostHeader; got != "api.internal" {
			t.Fatalf("loaded host_header=%q; want api.internal", got)
		}
		return
	}
	t.Fatal("created rule not found in loaded rules")
}

// Given: 自定义路由上游 host_header 传空白串（含首尾空格）
// When: 创建规则
// Then: 归一为去空格后的值（与主上游写侧 trim 同口径），不落库成「纯空白=已设置」的脏值
func TestCreateRule_pathUpstreamHostHeaderTrimmed(t *testing.T) {
	router := newStaticResponseRouter(t)
	body := `{"name":"path-up-host-trim","protocol":"http","domain":"path-up-host-trim.test","listen_port":18592,` +
		`"custom_routes_enabled":true,"path_rules":[{"match_type":"prefix","path":"/api","sort_order":0,` +
		`"upstreams":[{"address":"127.0.0.1","port":9100,"weight":100,"protocol":"http","host_header":"  api.internal  "}]}],` +
		`"upstreams":[{"host":"127.0.0.1","port":9000,"enabled":true}]}`
	request := httptest.NewRequest(http.MethodPost, "/rules", strings.NewReader(body))
	request.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	router.ServeHTTP(rec, request)
	if rec.Code != http.StatusCreated && rec.Code != http.StatusOK {
		t.Fatalf("create status=%d body=%s", rec.Code, rec.Body.String())
	}

	var upstreamsJSON string
	if err := db.DB.QueryRow(`SELECT COALESCE(upstreams_json,'') FROM path_rules
		WHERE rule_id=(SELECT caddy_id FROM lb_rules WHERE name='path-up-host-trim')`).Scan(&upstreamsJSON); err != nil {
		t.Fatalf("read persisted path rule: %v", err)
	}
	var stored []models.PathRuleUpstream
	if err := json.Unmarshal([]byte(upstreamsJSON), &stored); err != nil {
		t.Fatalf("decode upstreams_json: %v", err)
	}
	if len(stored) != 1 || stored[0].HostHeader != "api.internal" {
		t.Fatalf("upstreams_json=%s; want trimmed host_header=api.internal", upstreamsJSON)
	}
}
