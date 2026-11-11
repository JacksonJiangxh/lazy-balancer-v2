package handlers

// 自定义路由「直接返回/301 跳转」（2026-10-10 用户裁定）保存侧校验：
// response_mode ∈ {''转发, static 静态响应, redirect 301 跳转}。
//
// 2026-11-11 TASK-2026-1111-01 强健度改造后口径：
// static = 19 码白名单（含 3xx 与存量兼容的 201；选 3xx 须填跳转目标、该码不得带体）+ 响应体
// ≤4096 字符 + 控制字符门 + 格式 {plain/json/html} + 非 3xx 禁 redirect_to；
// redirect = 恒 301、目标必填（/ 开头相对路径或 http(s) 绝对 URL，不含空格与
// 控制字符），禁 body/上游。逐条判据见 rule_features_static_response_test.go。

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/gin-gonic/gin"

	"lazy-balancer-v2/internal/db"
)

func TestRulePayload_pathRuleResponseModeValidation(t *testing.T) {
	handler := newRuleFeatureTestHandlers(t)
	gin.SetMode(gin.TestMode)
	router := gin.New()
	router.POST("/rules", handler.CreateRule)

	longBody := strings.Repeat("x", 65)
	cases := []struct {
		name     string
		pathRule string
		wantCode int
		wantErr  string
		// 落库回读（0 = 该用例不做回读）：状态码 201 只证明校验放行，
		// 缺省归一是否真的写进了库要看列值——渲染侧直读库值。
		wantStatus      int
		wantContentType string
		wantBody        string
	}{
		// 合法形态（回归形）
		{"转发模式现状放行", `{"sort_order":0,"match_type":"prefix","path":"/api/","upstreams":null}`, http.StatusCreated, "", 200, "", ""},
		{"static 合法放行", `{"sort_order":0,"match_type":"exact","path":"/maint","response_mode":"static","response_status":503,"response_body":"维护中","response_content_type":"text/html"}`, http.StatusCreated, "", 503, "text/html", "维护中"},
		{"static 缺省状态码与格式放行", `{"sort_order":0,"match_type":"exact","path":"/ping","response_mode":"static","response_body":"pong"}`, http.StatusCreated, "", 200, "", "pong"},
		{"redirect 绝对 URL 放行", `{"sort_order":0,"match_type":"prefix","path":"/old/","response_mode":"redirect","redirect_to":"https://new.example.com/landing"}`, http.StatusCreated, "", 200, "", ""},
		{"redirect 相对路径放行", `{"sort_order":0,"match_type":"prefix","path":"/old/","response_mode":"redirect","redirect_to":"/new/"}`, http.StatusCreated, "", 200, "", ""},
		// 畸形形状
		{"未知模式拒绝", `{"sort_order":0,"match_type":"exact","path":"/x","response_mode":"bogus"}`, http.StatusBadRequest, "response_mode", 0, "", ""},
		{"static 非常用状态码拒绝", `{"sort_order":0,"match_type":"exact","path":"/x","response_mode":"static","response_status":299}`, http.StatusBadRequest, "状态码", 0, "", ""},
		// 2026-11-11 TASK-2026-1111-01：响应体上限 64 → 4096，65 字符已属合法；
		// 超限用例改按新界值构造（见下 4097 一条）。
		{"static 响应体 65 字符放行（新上限）", fmt.Sprintf(`{"sort_order":0,"match_type":"exact","path":"/x","response_mode":"static","response_body":%q}`, longBody), http.StatusCreated, "", 0, "", ""},
		{"static 响应体超 4096 字符拒绝", fmt.Sprintf(`{"sort_order":0,"match_type":"exact","path":"/x","response_mode":"static","response_body":%q}`, strings.Repeat("x", 4097)), http.StatusBadRequest, "4096", 0, "", ""},
		{"static 非法格式拒绝", `{"sort_order":0,"match_type":"exact","path":"/x","response_mode":"static","response_content_type":"text/xml"}`, http.StatusBadRequest, "格式", 0, "", ""},
		// 非 3xx 携带跳转目标：误配显性拒绝（文案自 2026-11-11 起点明状态码）
		{"static 带跳转目标拒绝", `{"sort_order":0,"match_type":"exact","path":"/x","response_mode":"static","redirect_to":"https://a.b"}`, http.StatusBadRequest, "不应填写跳转地址", 0, "", ""},
		{"static 带上游拒绝", `{"sort_order":0,"match_type":"exact","path":"/x","response_mode":"static","upstreams":[{"address":"127.0.0.1","port":9000}]}`, http.StatusBadRequest, "互斥", 0, "", ""},
		{"redirect 空目标拒绝", `{"sort_order":0,"match_type":"prefix","path":"/old/","response_mode":"redirect"}`, http.StatusBadRequest, "跳转地址", 0, "", ""},
		{"redirect CRLF 目标拒绝", `{"sort_order":0,"match_type":"prefix","path":"/old/","response_mode":"redirect","redirect_to":"https://a.b/\r\nX-Evil: 1"}`, http.StatusBadRequest, "跳转地址", 0, "", ""},
		// redirect 带响应体：301 属 3xx，按 RFC 9110 先命中「不得携带响应内容」
		// （比「互斥」更准确点出根因，2026-11-11 起）
		{"redirect 带响应体拒绝", `{"sort_order":0,"match_type":"prefix","path":"/old/","response_mode":"redirect","redirect_to":"https://a.b/","response_body":"x"}`, http.StatusBadRequest, "不得携带响应内容", 0, "", ""},
	}
	for i, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			domain := fmt.Sprintf("prresp-%d.test", i)
			body := fmt.Sprintf(`{"name":"prresp-%d","protocol":"http","domain":%q,"listen_port":%d,"custom_routes_enabled":true,`+
				`"health_check_interval":10,"health_check_timeout":2,"health_check_unhealthy_threshold":3,"health_check_healthy_threshold":2,`+
				`"upstreams":[{"host":"127.0.0.1","port":9000,"enabled":true}],"path_rules":[%s]}`, i, domain, 19100+i, tc.pathRule)
			request := httptest.NewRequest(http.MethodPost, "/rules", strings.NewReader(body))
			request.Header.Set("Content-Type", "application/json")
			response := httptest.NewRecorder()
			router.ServeHTTP(response, request)
			if response.Code != tc.wantCode {
				t.Fatalf("status=%d, want %d; body=%s", response.Code, tc.wantCode, response.Body.String())
			}
			if tc.wantErr != "" && !strings.Contains(response.Body.String(), tc.wantErr) {
				t.Fatalf("body must contain %q, got %s", tc.wantErr, response.Body.String())
			}
			if tc.wantStatus == 0 {
				return
			}
			// 回读落库列值：缺省归一（static 缺省码 200、格式空由渲染侧兜 text/plain）
			// 必须真的写进库，201 本身不区分「归一后写入」与「写 0 靠渲染兜底」。
			var status int
			var contentType, storedBody, mode string
			if err := db.DB.QueryRow(`SELECT p.response_status, p.response_content_type, p.response_body, p.response_mode
				FROM path_rules p JOIN lb_rules r ON r.caddy_id = p.rule_id WHERE r.domain = ? ORDER BY p.id DESC LIMIT 1`, domain).
				Scan(&status, &contentType, &storedBody, &mode); err != nil {
				t.Fatalf("回读 path_rules: %v", err)
			}
			if status != tc.wantStatus {
				t.Fatalf("落库 response_status=%d, want %d", status, tc.wantStatus)
			}
			if contentType != tc.wantContentType {
				t.Fatalf("落库 response_content_type=%q, want %q", contentType, tc.wantContentType)
			}
			if storedBody != tc.wantBody {
				t.Fatalf("落库 response_body=%q, want %q", storedBody, tc.wantBody)
			}
			if mode == "" && strings.Contains(tc.pathRule, `"response_mode":"static"`) {
				t.Fatalf("落库 response_mode 为空，static 模式丢失")
			}
		})
	}
}
