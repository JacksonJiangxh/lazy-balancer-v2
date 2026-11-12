package handlers

// TLS 透传（JJC-20261112-01 S1-a）保存门钉测：
//   - validateRuleFeatures → validatePassthroughRule 域内单源（合法/拒绝全表）
//   - CreateRule/UpdateRule HTTP 链路（禁用态保存、TLS 字段拒绝、SNI/跨终结冲突）
//   - 存量零影响（无 passthrough 规则时既有 HTTP/TCP 保存行为不变——既有测试
//     全绿为证，此处另附一条直证）
// 渲染链（caddy.go Layer4 分流）由 S1-b 承担：本阶段透传规则恒禁用态保存。

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/gin-gonic/gin"

	"lazy-balancer-v2/internal/db"
	"lazy-balancer-v2/internal/services"
)

// passthroughFeatureInput 构造合法透传特性输入（逐测覆盖字段）。
func passthroughFeatureInput() ruleFeatureInput {
	return ruleFeatureInput{
		Protocol:            "passthrough",
		Domain:              "app.example.com",
		ListenPort:          services.DefaultHTTPSPort(),
		PassthroughUpstream: "10.0.0.5:10443",
		Strategy:            "weighted_round_robin",
	}
}

func TestPassthrough_valid_inputs_pass_save_gate(t *testing.T) {
	validCases := []struct {
		name   string
		mutate func(*ruleFeatureInput)
	}{
		{name: "exact SNI + ip upstream", mutate: func(i *ruleFeatureInput) {}},
		{name: "wildcard SNI", mutate: func(i *ruleFeatureInput) { i.Domain = "*.apps.example.com" }},
		{name: "hostname upstream", mutate: func(i *ruleFeatureInput) { i.PassthroughUpstream = "up.internal.example:8443" }},
		{name: "ip literal upstream bracketed v6", mutate: func(i *ruleFeatureInput) { i.PassthroughUpstream = "[fd00::5]:10443" }},
		{name: "l4 strategy least_conn", mutate: func(i *ruleFeatureInput) { i.Strategy = "least_conn" }},
		{name: "tcp reuse health fields", mutate: func(i *ruleFeatureInput) { i.TCPHealthCheckPort = 10443 }},
	}
	for _, testCase := range validCases {
		t.Run(testCase.name, func(t *testing.T) {
			input := passthroughFeatureInput()
			testCase.mutate(&input)
			if err := validateRuleFeatures(input); err != nil {
				t.Fatalf("validateRuleFeatures() error = %v, want nil", err)
			}
		})
	}
}

func TestPassthrough_rejection_matrix(t *testing.T) {
	tests := []struct {
		name      string
		mutate    func(*ruleFeatureInput)
		wantError string
	}{
		{
			name:      "missing SNI domain",
			mutate:    func(i *ruleFeatureInput) { i.Domain = "" },
			wantError: "SNI 域名必填",
		},
		{
			name:      "empty passthrough upstream",
			mutate:    func(i *ruleFeatureInput) { i.PassthroughUpstream = "" },
			wantError: "必填（host:port",
		},
		{
			name:      "upstream without port",
			mutate:    func(i *ruleFeatureInput) { i.PassthroughUpstream = "up.internal.example" },
			wantError: "host:port 形态",
		},
		{
			name:      "upstream port out of range",
			mutate:    func(i *ruleFeatureInput) { i.PassthroughUpstream = "10.0.0.5:70000" },
			wantError: "端口无效",
		},
		{
			name:      "upstream host invalid",
			mutate:    func(i *ruleFeatureInput) { i.PassthroughUpstream = "bad host:10443" },
			wantError: "主机无效",
		},
		{
			name:      "listen port differs from HTTPS default",
			mutate:    func(i *ruleFeatureInput) { i.ListenPort = services.DefaultHTTPSPort() + 1 },
			wantError: "HTTPS 默认口",
		},
		{
			name:      "enable_tls rejected",
			mutate:    func(i *ruleFeatureInput) { i.EnableTLS = true },
			wantError: "透传域名证书由上游管理",
		},
		{
			name:      "tls http redirect rejected",
			mutate:    func(i *ruleFeatureInput) { i.TLSHTTPRedirect = true },
			wantError: "透传域名证书由上游管理",
		},
		{
			name:      "http-only strategy cookie rejected",
			mutate:    func(i *ruleFeatureInput) { i.Strategy = "cookie" },
			wantError: "透传（passthrough）规则仅支持",
		},
		{
			name:      "chain fallback rejected",
			mutate:    func(i *ruleFeatureInput) { i.Strategy = "chain_fallback" },
			wantError: "透传（passthrough）规则仅支持",
		},
		{
			name:      "custom path rules rejected",
			mutate:    func(i *ruleFeatureInput) { i.CustomRoutesEnabled = true },
			wantError: "自定义路径规则",
		},
		{
			name:      "forward auth rejected",
			mutate:    func(i *ruleFeatureInput) { i.ForwardAuthEnabled = 1 },
			wantError: "认证网关",
		},
		{
			name:      "ntlm rejected",
			mutate:    func(i *ruleFeatureInput) { i.NTLMCompatible = 1 },
			wantError: "NTLM 兼容模式",
		},
		{
			name:      "dynamic dns rejected",
			mutate:    func(i *ruleFeatureInput) { i.DynamicDNS = true },
			wantError: "动态上游",
		},
		{
			name:      "dns server rejected",
			mutate:    func(i *ruleFeatureInput) { i.EnableDnsServer = true },
			wantError: "DNS 服务发现",
		},
		{
			name:      "compress rejected",
			mutate:    func(i *ruleFeatureInput) { i.EnableCompress = true },
			wantError: "响应压缩",
		},
		{
			name:      "proxy timeout rejected",
			mutate:    func(i *ruleFeatureInput) { i.ProxyDialTimeout = 5 },
			wantError: "HTTP 代理超时配置",
		},
		{
			name:      "negative tcp health check port rejected",
			mutate:    func(i *ruleFeatureInput) { i.TCPHealthCheckPort = -1 },
			wantError: "健康检查端口不能为负数",
		},
	}
	for _, testCase := range tests {
		t.Run(testCase.name, func(t *testing.T) {
			input := passthroughFeatureInput()
			testCase.mutate(&input)
			err := validateRuleFeatures(input)
			if err == nil || !strings.Contains(err.Error(), testCase.wantError) {
				t.Fatalf("validateRuleFeatures() error = %v, want containing %q", err, testCase.wantError)
			}
		})
	}
}

func TestPassthrough_sni_domain_shapes(t *testing.T) {
	rejected := []struct {
		name      string
		domain    string
		wantError string
	}{
		{name: "space", domain: "a b.example.com", wantError: "空白字符"},
		{name: "port suffix", domain: "app.example.com:8443", wantError: "端口尾缀"},
		{name: "ip literal", domain: "10.0.0.1", wantError: "IP 字面量"},
		{name: "multi domain list", domain: "a.example.com,b.example.com", wantError: "单个域名"},
		{name: "wildcard not leftmost", domain: "app.*.example.com", wantError: "最左标签"},
		{name: "wildcard partial label", domain: "q*.example.com", wantError: "最左标签"},
		{name: "wildcard single level", domain: "*.com", wantError: "至少须保留两级"},
		{name: "trailing dot", domain: "app.example.com.", wantError: "以点结尾"},
		{name: "empty label", domain: "app..example.com", wantError: "空标签"},
		{name: "underscore", domain: "app_ui.example.com", wantError: "非法字符"},
	}
	for _, testCase := range rejected {
		t.Run("reject "+testCase.name, func(t *testing.T) {
			input := passthroughFeatureInput()
			input.Domain = testCase.domain
			err := validateRuleFeatures(input)
			if err == nil || !strings.Contains(err.Error(), testCase.wantError) {
				t.Fatalf("validateRuleFeatures() error = %v, want containing %q", err, testCase.wantError)
			}
		})
	}
	t.Run("wildcard and mixed case accepted (normalized)", func(t *testing.T) {
		input := passthroughFeatureInput()
		input.Domain = "APP.Example.COM"
		if err := validateRuleFeatures(input); err != nil {
			t.Fatalf("validateRuleFeatures() error = %v, want nil (大小写归一后合法)", err)
		}
	})
}

func TestPassthrough_upstream_column_dirty_data_gate(t *testing.T) {
	t.Run("http rule carrying passthrough_upstream rejected", func(t *testing.T) {
		input := ruleFeatureInput{Protocol: "http", Domain: "app.example.com", ListenPort: 8080,
			PassthroughUpstream: "10.0.0.5:10443"}
		err := validateRuleFeatures(input)
		if err == nil || !strings.Contains(err.Error(), "仅透传（passthrough）规则支持") {
			t.Fatalf("validateRuleFeatures() error = %v, want 防脏门", err)
		}
	})
	t.Run("tcp rule carrying passthrough_upstream rejected", func(t *testing.T) {
		input := ruleFeatureInput{Protocol: "tcp", ListenPort: 9000,
			PassthroughUpstream: "10.0.0.5:10443"}
		err := validateRuleFeatures(input)
		if err == nil || !strings.Contains(err.Error(), "仅透传（passthrough）规则支持") {
			t.Fatalf("validateRuleFeatures() error = %v, want 防脏门", err)
		}
	})
}

// seedPassthroughRule 直插启用中的透传行（冲突门占用方）——启用态透传行只能
// 经 DB 直插构造（S1-a 保存门恒禁用态落库）。
func seedPassthroughRule(t *testing.T, caddyID, domain, upstream string, listenPort, enabled int) {
	t.Helper()
	if _, err := db.DB.Exec(`INSERT INTO lb_rules (caddy_id,name,description,protocol,domain,listen_port,strategy,enabled,enable_compress,passthrough_upstream)
		VALUES (?,?,?,'passthrough',?,?,'weighted_round_robin',?,1,?)`,
		caddyID, caddyID, "", domain, listenPort, enabled, upstream); err != nil {
		t.Fatalf("seed passthrough rule %s: %v", caddyID, err)
	}
}

func newPassthroughRouter(t *testing.T) (*Handlers, *gin.Engine, func(string) *httptest.ResponseRecorder) {
	t.Helper()
	handler := newRuleFeatureTestHandlers(t)
	t.Cleanup(services.SetCertDirForTest(t.TempDir()))
	gin.SetMode(gin.TestMode)
	router := gin.New()
	router.POST("/rules", handler.CreateRule)
	router.PUT("/rules/:caddy_id", handler.UpdateRule)
	create := func(body string) *httptest.ResponseRecorder {
		t.Helper()
		request := httptest.NewRequest(http.MethodPost, "/rules", strings.NewReader(body))
		request.Header.Set("Content-Type", "application/json")
		response := httptest.NewRecorder()
		router.ServeHTTP(response, request)
		return response
	}
	return handler, router, create
}

func passthroughCreateBody(name, domain string, enabled bool) string {
	return fmt.Sprintf(`{"name":%q,"protocol":"passthrough","domain":%q,"listen_port":%d,"passthrough_upstream":"10.0.0.5:10443","health_check_interval":10,"health_check_timeout":2,"health_check_unhealthy_threshold":3,"health_check_healthy_threshold":2,"enabled":%v}`,
		name, domain, services.DefaultHTTPSPort(), enabled)
}

func TestPassthroughCreateRule_disabled_save_passes(t *testing.T) {
	_, _, create := newPassthroughRouter(t)
	response := create(passthroughCreateBody("passthrough-ok", "app.example.com", false))
	if response.Code != http.StatusCreated {
		t.Fatalf("status=%d body=%s, want 201", response.Code, response.Body.String())
	}
	var payload struct {
		Data struct {
			CaddyID string `json:"caddy_id"`
		} `json:"data"`
	}
	if err := json.Unmarshal(response.Body.Bytes(), &payload); err != nil || payload.Data.CaddyID == "" {
		t.Fatalf("parse create response %q: %v", response.Body.String(), err)
	}
	caddyID := payload.Data.CaddyID
	// 列落库验证：passthrough_upstream 经唯一事实源 INSERT 携带。
	var storedUpstream, storedDomain string
	if err := db.DB.QueryRow(`SELECT COALESCE(passthrough_upstream,''), COALESCE(domain,'') FROM lb_rules WHERE caddy_id = ?`,
		caddyID).Scan(&storedUpstream, &storedDomain); err != nil {
		t.Fatalf("read stored rule: %v", err)
	}
	if storedUpstream != "10.0.0.5:10443" || storedDomain != "app.example.com" {
		t.Fatalf("stored passthrough_upstream=%q domain=%q, want 10.0.0.5:10443/app.example.com", storedUpstream, storedDomain)
	}
}

func TestPassthroughCreateRule_enabled_rejected_in_s1a(t *testing.T) {
	_, _, create := newPassthroughRouter(t)
	response := create(passthroughCreateBody("passthrough-enabled", "app.example.com", true))
	if response.Code != http.StatusBadRequest || !strings.Contains(response.Body.String(), "暂不支持启用") {
		t.Fatalf("status=%d body=%s, want 400 暂不支持启用", response.Code, response.Body.String())
	}
}

func TestPassthroughCreateRule_tls_fields_rejected(t *testing.T) {
	_, _, create := newPassthroughRouter(t)
	body := fmt.Sprintf(`{"name":"passthrough-tls","protocol":"passthrough","domain":"app.example.com","listen_port":%d,"passthrough_upstream":"10.0.0.5:10443","enable_tls":true,"enabled":false}`,
		services.DefaultHTTPSPort())
	response := create(body)
	if response.Code != http.StatusBadRequest || !strings.Contains(response.Body.String(), "透传域名证书由上游管理") {
		t.Fatalf("status=%d body=%s, want 400 证书由上游管理", response.Code, response.Body.String())
	}
}

func TestPassthroughCreateRule_explicit_upstreams_rejected(t *testing.T) {
	_, _, create := newPassthroughRouter(t)
	body := fmt.Sprintf(`{"name":"passthrough-ups","protocol":"passthrough","domain":"app.example.com","listen_port":%d,"passthrough_upstream":"10.0.0.5:10443","enabled":false,"upstreams":[{"host":"127.0.0.1","port":9000,"enabled":true}]}`,
		services.DefaultHTTPSPort())
	response := create(body)
	if response.Code != http.StatusBadRequest || !strings.Contains(response.Body.String(), "不支持 upstreams") {
		t.Fatalf("status=%d body=%s, want 400 不支持 upstreams", response.Code, response.Body.String())
	}
}

func TestPassthroughCreateRule_port_must_be_https_default(t *testing.T) {
	_, _, create := newPassthroughRouter(t)
	body := fmt.Sprintf(`{"name":"passthrough-port","protocol":"passthrough","domain":"app.example.com","listen_port":%d,"passthrough_upstream":"10.0.0.5:10443","enabled":false}`,
		services.DefaultHTTPSPort()+1)
	response := create(body)
	if response.Code != http.StatusBadRequest || !strings.Contains(response.Body.String(), "HTTPS 默认口") {
		t.Fatalf("status=%d body=%s, want 400 HTTPS 默认口", response.Code, response.Body.String())
	}
}

func TestPassthroughCreateRule_sni_conflicts(t *testing.T) {
	// 每个子测试独立 fixture：冲突占用方（启用态透传行）只能经 DB 直插构造，
	// 而 S1-a 阶段启用中的透传行会使全量渲染失败——独立 DB 保证互不污染。
	t.Run("same port same SNI rejected", func(t *testing.T) {
		_, _, create := newPassthroughRouter(t)
		seedPassthroughRule(t, "lb_pt_sni1", "app.example.com", "10.0.0.9:10443", services.DefaultHTTPSPort(), 1)
		response := create(passthroughCreateBody("passthrough-dup", "app.example.com", false))
		if response.Code != http.StatusBadRequest || !strings.Contains(response.Body.String(), "已被透传规则") {
			t.Fatalf("status=%d body=%s, want 400 同 SNI 冲突", response.Code, response.Body.String())
		}
	})
	t.Run("wildcard vs exact overlap rejected", func(t *testing.T) {
		_, _, create := newPassthroughRouter(t)
		seedPassthroughRule(t, "lb_pt_sni2", "*.a.example", "10.0.0.9:10443", services.DefaultHTTPSPort(), 1)
		response := create(passthroughCreateBody("passthrough-wild", "b.a.example", false))
		if response.Code != http.StatusBadRequest || !strings.Contains(response.Body.String(), "已被透传规则") {
			t.Fatalf("status=%d body=%s, want 400 通配重叠", response.Code, response.Body.String())
		}
	})
	t.Run("different SNI coexists", func(t *testing.T) {
		_, _, create := newPassthroughRouter(t)
		// 占用方为禁用态（S1-a 阶段启用中的透传行会使全量渲染失败——这正是
		// 恒禁用态门的理由；冲突门语义：仅启用中的透传规则占用 SNI）。
		seedPassthroughRule(t, "lb_pt_sni3", "kept.example", "10.0.0.9:10443", services.DefaultHTTPSPort(), 0)
		response := create(passthroughCreateBody("passthrough-co", "other.example", false))
		if response.Code != http.StatusCreated {
			t.Fatalf("status=%d body=%s, want 201（不同 SNI 不冲突，禁用占用方不阻塞）", response.Code, response.Body.String())
		}
	})
	t.Run("same domain as enabled http rule rejected", func(t *testing.T) {
		_, _, create := newPassthroughRouter(t)
		seedShadowHTTPRule(t, "lb_pt_http1", "term.example", services.DefaultHTTPSPort(), 1)
		response := create(passthroughCreateBody("passthrough-term", "term.example", false))
		if response.Code != http.StatusBadRequest || !strings.Contains(response.Body.String(), "本地终结") {
			t.Fatalf("status=%d body=%s, want 400 透传 vs 本地终结", response.Code, response.Body.String())
		}
	})
}

// seedShadowHTTPRule 直插启用中 HTTP 规则（含启用上游——冲突门口径：零启用上游
// 不占用域名，与 enabledRuleDomainConflict 同源）。
func seedShadowHTTPRule(t *testing.T, caddyID, domain string, listenPort, enabled int) {
	t.Helper()
	if _, err := db.DB.Exec(`INSERT INTO lb_rules (caddy_id,name,description,protocol,domain,listen_port,strategy,enabled,enable_compress)
		VALUES (?,?,?,'http',?,?,'weighted_round_robin',?,1)`,
		caddyID, caddyID, "", domain, listenPort, enabled); err != nil {
		t.Fatalf("seed http rule %s: %v", caddyID, err)
	}
	if _, err := db.DB.Exec(`INSERT INTO upstreams (rule_id,host,port,weight,enabled,protocol) VALUES (?,'127.0.0.1',9000,1,1,'http')`, caddyID); err != nil {
		t.Fatalf("seed upstream %s: %v", caddyID, err)
	}
}

func TestPassthroughCreateRule_http_reverse_gate(t *testing.T) {
	_, _, create := newPassthroughRouter(t)
	seedPassthroughRule(t, "lb_pt_rev1", "reverse.example", "10.0.0.9:10443", services.DefaultHTTPSPort(), 1)
	body := fmt.Sprintf(`{"name":"http-over-passthrough","protocol":"http","domain":"reverse.example","listen_port":%d,"health_check_interval":10,"health_check_timeout":2,"health_check_unhealthy_threshold":3,"health_check_healthy_threshold":2,"upstreams":[{"host":"127.0.0.1","port":9000,"enabled":true}]}`,
		services.DefaultHTTPSPort())
	response := create(body)
	if response.Code != http.StatusBadRequest || !strings.Contains(response.Body.String(), "已被透传规则") {
		t.Fatalf("status=%d body=%s, want 400 HTTP 反门", response.Code, response.Body.String())
	}
}

func TestPassthroughUpdateRule_keep_disabled_and_edit_upstream(t *testing.T) {
	handler, router, create := newPassthroughRouter(t)
	_ = handler
	response := create(passthroughCreateBody("passthrough-edit", "edit.example", false))
	if response.Code != http.StatusCreated {
		t.Fatalf("create status=%d body=%s, want 201", response.Code, response.Body.String())
	}
	var payload struct {
		Code int `json:"code"`
		Data struct {
			CaddyID string `json:"caddy_id"`
		} `json:"data"`
	}
	if err := json.Unmarshal(response.Body.Bytes(), &payload); err != nil || payload.Data.CaddyID == "" {
		t.Fatalf("parse create response %q: %v", response.Body.String(), err)
	}
	caddyID := payload.Data.CaddyID

	// 部分更新：仅改透传上游（nil 字段沿用存量、禁用态保持）→ 200 且列更新。
	request := httptest.NewRequest(http.MethodPut, "/rules/"+caddyID, strings.NewReader(`{"passthrough_upstream":"10.0.0.6:20443"}`))
	request.Header.Set("Content-Type", "application/json")
	recorder := httptest.NewRecorder()
	router.ServeHTTP(recorder, request)
	if recorder.Code != http.StatusOK {
		t.Fatalf("update status=%d body=%s, want 200", recorder.Code, recorder.Body.String())
	}
	var storedUpstream string
	if err := db.DB.QueryRow(`SELECT COALESCE(passthrough_upstream,'') FROM lb_rules WHERE caddy_id = ?`, caddyID).Scan(&storedUpstream); err != nil {
		t.Fatalf("read updated rule: %v", err)
	}
	if storedUpstream != "10.0.0.6:20443" {
		t.Fatalf("updated passthrough_upstream=%q, want 10.0.0.6:20443", storedUpstream)
	}

	// 启用尝试 → 400（S1-a 禁用态门）。
	enableRequest := httptest.NewRequest(http.MethodPut, "/rules/"+caddyID, strings.NewReader(`{"enabled":true}`))
	enableRequest.Header.Set("Content-Type", "application/json")
	enableRecorder := httptest.NewRecorder()
	router.ServeHTTP(enableRecorder, enableRequest)
	if enableRecorder.Code != http.StatusBadRequest || !strings.Contains(enableRecorder.Body.String(), "暂不支持启用") {
		t.Fatalf("enable status=%d body=%s, want 400 暂不支持启用", enableRecorder.Code, enableRecorder.Body.String())
	}

	// 非透传协议显式携带 passthrough_upstream → 400（防脏门）。
	// 以既有 HTTP 规则验证 UpdateRule 方向。
	httpResponse := create(`{"name":"legacy-http-edit","protocol":"http","domain":"legacy-edit.example","listen_port":8080,"health_check_interval":10,"health_check_timeout":2,"health_check_unhealthy_threshold":3,"health_check_healthy_threshold":2,"upstreams":[{"host":"127.0.0.1","port":9000,"enabled":true}]}`)
	if httpResponse.Code != http.StatusCreated {
		t.Fatalf("http create status=%d body=%s, want 201", httpResponse.Code, httpResponse.Body.String())
	}
	var httpPayload struct {
		Data struct {
			CaddyID string `json:"caddy_id"`
		} `json:"data"`
	}
	if err := json.Unmarshal(httpResponse.Body.Bytes(), &httpPayload); err != nil || httpPayload.Data.CaddyID == "" {
		t.Fatalf("parse http create response: %v", err)
	}
	dirtyRequest := httptest.NewRequest(http.MethodPut, "/rules/"+httpPayload.Data.CaddyID, strings.NewReader(`{"passthrough_upstream":"10.0.0.5:10443"}`))
	dirtyRequest.Header.Set("Content-Type", "application/json")
	dirtyRecorder := httptest.NewRecorder()
	router.ServeHTTP(dirtyRecorder, dirtyRequest)
	if dirtyRecorder.Code != http.StatusBadRequest || !strings.Contains(dirtyRecorder.Body.String(), "仅透传（passthrough）规则支持") {
		t.Fatalf("dirty update status=%d body=%s, want 400 防脏门", dirtyRecorder.Code, dirtyRecorder.Body.String())
	}
}

func TestPassthrough_legacy_zero_impact(t *testing.T) {
	_, _, create := newPassthroughRouter(t)
	// 存量零影响直证：无 passthrough 规则的库上，HTTP/TCP 规则保存行为不变。
	httpBody := `{"name":"legacy-http","protocol":"http","domain":"legacy.example","listen_port":8080,"health_check_interval":10,"health_check_timeout":2,"health_check_unhealthy_threshold":3,"health_check_healthy_threshold":2,"upstreams":[{"host":"127.0.0.1","port":9000,"enabled":true}]}`
	if response := create(httpBody); response.Code != http.StatusCreated {
		t.Fatalf("http create status=%d body=%s, want 201", response.Code, response.Body.String())
	}
	tcpBody := `{"name":"legacy-tcp","protocol":"tcp","listen_port":19000,"health_check_interval":10,"health_check_timeout":2,"health_check_unhealthy_threshold":3,"health_check_healthy_threshold":2,"upstreams":[{"host":"127.0.0.1","port":19001,"enabled":true}]}`
	if response := create(tcpBody); response.Code != http.StatusCreated {
		t.Fatalf("tcp create status=%d body=%s, want 201", response.Code, response.Body.String())
	}
}
