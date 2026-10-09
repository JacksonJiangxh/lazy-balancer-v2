package handlers

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/gin-gonic/gin"

	"lazy-balancer-v2/internal/db"
)

// newStaticResponseRouter 构造创建规则的测试路由（复用共享的测试 Handlers）。
func newStaticResponseRouter(t *testing.T) *gin.Engine {
	t.Helper()
	handler := newRuleFeatureTestHandlers(t)
	gin.SetMode(gin.TestMode)
	router := gin.New()
	router.POST("/rules", handler.CreateRule)
	return router
}

// createStaticResponseRule 提交带自定义路由的创建请求。
func createStaticResponseRule(t *testing.T, router *gin.Engine, pathRulesJSON string) *httptest.ResponseRecorder {
	t.Helper()
	body := `{"name":"static-resp","protocol":"http","domain":"static-response.test","listen_port":18590,` +
		`"custom_routes_enabled":true,"path_rules":` + pathRulesJSON + `,` +
		`"upstreams":[{"host":"127.0.0.1","port":9000,"enabled":true}]}`
	request := httptest.NewRequest(http.MethodPost, "/rules", strings.NewReader(body))
	request.Header.Set("Content-Type", "application/json")
	response := httptest.NewRecorder()
	router.ServeHTTP(response, request)
	return response
}

// Given: 静态响应路径规则（3xx + 目标 URL）
// When: 创建规则
// Then: 创建成功且响应字段完整落库（含预设语义字段）
func TestCreateRule_staticResponsePathRulePersists(t *testing.T) {
	router := newStaticResponseRouter(t)
	rec := createStaticResponseRule(t, router, `[{"match_type":"prefix","path":"/old","sort_order":0,"action":"respond","status_code":301,"redirect_url":"https://example.com/new"}]`)
	if rec.Code != http.StatusCreated && rec.Code != http.StatusOK {
		t.Fatalf("create status=%d body=%s", rec.Code, rec.Body.String())
	}

	var loaded struct {
		Action       string
		StatusCode   int
		RedirectURL  string
		ResponseBody string
		ContentType  string
	}
	if err := db.DB.QueryRow(`SELECT action, status_code, redirect_url, response_body, content_type FROM path_rules WHERE rule_id=(SELECT caddy_id FROM lb_rules WHERE name='static-resp')`).
		Scan(&loaded.Action, &loaded.StatusCode, &loaded.RedirectURL, &loaded.ResponseBody, &loaded.ContentType); err != nil {
		t.Fatalf("read persisted path rule: %v", err)
	}
	if loaded.Action != "respond" || loaded.StatusCode != 301 || loaded.RedirectURL != "https://example.com/new" {
		t.Fatalf("persisted=%+v, want respond/301/https://example.com/new", loaded)
	}
}

// Given: 各类非法静态响应载荷
// When: 创建规则
// Then: 按校验口径整组 400 拒绝
func TestCreateRule_staticResponseValidationRejects(t *testing.T) {
	router := newStaticResponseRouter(t)
	cases := []struct {
		name      string
		pathRules string
		wantMsg   string
	}{
		{
			name:      "3xx 未填重定向 URL",
			pathRules: `[{"match_type":"prefix","path":"/a","sort_order":0,"action":"respond","status_code":302}]`,
			wantMsg:   "必须填写重定向目标 URL",
		},
		{
			name:      "重定向 URL 形状非法",
			pathRules: `[{"match_type":"prefix","path":"/a","sort_order":0,"action":"respond","status_code":302,"redirect_url":"example.com"}]`,
			wantMsg:   "重定向目标 URL 无效",
		},
		{
			name:      "响应码不在预置集合",
			pathRules: `[{"match_type":"prefix","path":"/a","sort_order":0,"action":"respond","status_code":418}]`,
			wantMsg:   "不在支持范围内",
		},
		{
			name:      "静态响应携带上游",
			pathRules: `[{"match_type":"prefix","path":"/a","sort_order":0,"action":"respond","status_code":200,"upstreams":[{"address":"127.0.0.1","port":8080,"weight":1,"protocol":"http"}]}]`,
			wantMsg:   "不能配置上游服务器",
		},
		{
			name:      "非重定向却填了重定向 URL",
			pathRules: `[{"match_type":"prefix","path":"/a","sort_order":0,"action":"respond","status_code":404,"redirect_url":"https://example.com"}]`,
			wantMsg:   "不应填写重定向目标 URL",
		},
		{
			name:      "内容类型含控制字符",
			pathRules: `[{"match_type":"prefix","path":"/a","sort_order":0,"action":"respond","status_code":200,"content_type":"text/html\r\nX-Injected: 1"}]`,
			wantMsg:   "内容类型含非法字符",
		},
		{
			name:      "处理方式非法",
			pathRules: `[{"match_type":"prefix","path":"/a","sort_order":0,"action":"proxying","status_code":200}]`,
			wantMsg:   "处理方式只能是 proxy 或 respond",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			rec := createStaticResponseRule(t, router, tc.pathRules)
			if rec.Code != http.StatusBadRequest {
				t.Fatalf("status=%d body=%s, want 400", rec.Code, rec.Body.String())
			}
			if !strings.Contains(rec.Body.String(), tc.wantMsg) {
				t.Fatalf("body=%s, want contains %q", rec.Body.String(), tc.wantMsg)
			}
		})
	}
}

// Given: 库中存在静态响应路径规则
// When: 批量读取路径规则（列表/详情返回给前端的通道）
// Then: 静态响应字段随行返回，前端可正确回显
func TestLoadPathRulesBatch_returnsStaticResponseFields(t *testing.T) {
	database := initializeRuleFeatureTestDB(t)
	if _, err := database.Exec(`INSERT INTO lb_rules (caddy_id,name,protocol,listen_port,custom_routes_enabled) VALUES ('lb_sr','sr','http',8080,1)`); err != nil {
		t.Fatalf("seed rule: %v", err)
	}
	if _, err := database.Exec(`INSERT INTO path_rules (rule_id,sort_order,match_type,path,action,status_code,redirect_url,response_body,content_type)
		VALUES ('lb_sr',0,'exact','/go','respond',308,'/target','','')`); err != nil {
		t.Fatalf("seed path rule: %v", err)
	}

	loaded, err := loadPathRulesBatch(context.Background(), []string{"lb_sr"})
	if err != nil {
		t.Fatalf("loadPathRulesBatch: %v", err)
	}
	rules := loaded["lb_sr"]
	if len(rules) != 1 {
		t.Fatalf("loaded %d path rules, want 1", len(rules))
	}
	got := rules[0]
	if got.Action != "respond" || got.StatusCode != 308 || got.RedirectURL != "/target" {
		t.Fatalf("loaded=%+v, want respond/308//target", got)
	}
}

// Given: 历史形态（action 缺省）的路径规则
// When: 创建规则
// Then: 按 proxy 处理并成功落库（存量兼容）
func TestCreateRule_pathRuleActionDefaultsToProxy(t *testing.T) {
	router := newStaticResponseRouter(t)
	rec := createStaticResponseRule(t, router, `[{"match_type":"prefix","path":"/legacy","sort_order":0,"upstream_path":"/v2"}]`)
	if rec.Code != http.StatusCreated && rec.Code != http.StatusOK {
		t.Fatalf("create status=%d body=%s", rec.Code, rec.Body.String())
	}
	var action string
	if err := db.DB.QueryRow(`SELECT action FROM path_rules WHERE rule_id=(SELECT caddy_id FROM lb_rules WHERE name='static-resp')`).Scan(&action); err != nil {
		t.Fatalf("read action: %v", err)
	}
	if action != "proxy" {
		t.Fatalf("action=%q, want proxy (归一落库)", action)
	}
}
