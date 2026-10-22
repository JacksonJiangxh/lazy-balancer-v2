package handlers

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"github.com/gin-gonic/gin"
	"gopkg.in/yaml.v3"

	"lazy-balancer-v2/internal/apipath"
	"lazy-balancer-v2/internal/config"
	"lazy-balancer-v2/internal/db"
	"lazy-balancer-v2/internal/mcpserver"
	"lazy-balancer-v2/internal/models"
	"lazy-balancer-v2/internal/services"
)

func TestBuildOpenAPIYAML_contains_cluster_contract_and_valid_yaml(t *testing.T) {
	openAPI := buildOpenAPIYAML()
	var document map[string]any
	if err := yaml.Unmarshal([]byte(openAPI), &document); err != nil {
		t.Fatalf("parse generated OpenAPI YAML: %v", err)
	}
	for _, path := range []string{"/cluster/status", "/cluster/register", "/cluster/sync/snapshot", "/cluster/nodes/report", "/cluster/promote"} {
		if !strings.Contains(openAPI, "  "+path+":") {
			t.Errorf("OpenAPI missing path %s", path)
		}
	}
	for _, legacyPath := range []string{"  /nodes/register:", "  /sync/status:", "  /sync/pull:"} {
		if strings.Contains(openAPI, legacyPath) {
			t.Errorf("OpenAPI retains legacy path %s", legacyPath)
		}
	}
	for _, scheme := range []string{"clusterToken:", "registrationSecret:"} {
		if !strings.Contains(openAPI, scheme) {
			t.Errorf("OpenAPI missing security scheme %s", scheme)
		}
	}
	for _, field := range []string{
		"custom_routes_enabled",
		"path_rules",
		"proxy_dial_timeout",
		"proxy_response_header_timeout",
		"proxy_read_timeout",
		"proxy_write_timeout",
		"proxy_stream_timeout",
		"proxy_flush_interval",
		"proxy_stream_close_delay",
		`"upstreams":null`,
	} {
		if !strings.Contains(openAPI, field) {
			t.Errorf("OpenAPI missing rule routing field %s", field)
		}
	}
}

func TestBuildOpenAPIYAML_contains_active_configuration_and_certificate_paths(t *testing.T) {
	openAPI := buildOpenAPIYAML()
	var document struct {
		Paths map[string]any `yaml:"paths"`
	}
	if err := yaml.Unmarshal([]byte(openAPI), &document); err != nil {
		t.Fatalf("parse generated OpenAPI YAML: %v", err)
	}
	for _, path := range []string{"/config/import/validate", "/certificate-configs", "/certificates", "/rules/{caddy_id}/cert-info"} {
		if _, exists := document.Paths[path]; !exists {
			t.Errorf("OpenAPI missing active path %s", path)
		}
	}
}

func TestAPIDocRoutes_match_snapshot_authorization_and_request_contracts(t *testing.T) {
	routes := make(map[string]apiDocRoute, len(apiDocRoutes))
	for _, route := range apiDocRoutes {
		routes[route.Method+" "+route.Path] = route
	}

	var snapshotExample struct {
		Data struct {
			SchemaVersion int `json:"schema_version"`
		} `json:"data"`
	}
	if err := json.Unmarshal([]byte(routes["GET /cluster/sync/snapshot"].Response), &snapshotExample); err != nil {
		t.Fatalf("parse snapshot response example: %v", err)
	}
	if snapshotExample.Data.SchemaVersion != services.CurrentSnapshotSchema {
		t.Errorf("snapshot schema_version=%d, want %d", snapshotExample.Data.SchemaVersion, services.CurrentSnapshotSchema)
	}

	for _, key := range []string{"GET /api-keys", "GET /config/health"} {
		route := routes[key]
		if !strings.Contains(route.Description, "所有已登录用户可读") {
			t.Errorf("%s does not document authenticated read access", key)
		}
		for _, routeError := range route.Errors {
			if strings.HasPrefix(routeError, "403 ") {
				t.Errorf("%s incorrectly documents 403: %s", key, routeError)
			}
		}
	}
	for _, key := range []string{
		"GET /cluster/status",
		"GET /cluster/nodes",
		"POST /cluster/register-tokens",
		"POST /cluster/nodes/:id/approve",
		"POST /cluster/nodes/:id/reject",
		"POST /cluster/nodes/:id/login-ticket",
		"PUT /cluster/nodes/:id/access-url",
		"DELETE /cluster/nodes/:id",
		"POST /cluster/mode",
		"POST /cluster/promote",
		"POST /cluster/sync/pull",
		"PUT /cluster/settings",
	} {
		description := routes[key].Description
		if !strings.Contains(description, "JWT") || !strings.Contains(description, "API Key") {
			t.Errorf("%s does not document JWT and API Key authentication: %q", key, description)
		}
		if strings.Contains(description, "仅接受 JWT") {
			t.Errorf("%s retains JWT-only authentication description: %q", key, description)
		}
	}
	if description := routes["GET /cluster/nodes"].Description; !strings.Contains(description, "仅主节点") {
		t.Errorf("GET /cluster/nodes lost master-node semantics: %q", description)
	}
	if request := routes["POST /rules/:caddy_id/duplicate"].Request; request != "" {
		t.Errorf("duplicate rule documents unused request body: %s", request)
	}
}

func TestBuildOpenAPIYAML_documents_operation_specific_contracts(t *testing.T) {
	// Given
	var document struct {
		Paths map[string]map[string]struct {
			Security   []map[string][]string `yaml:"security"`
			Parameters []struct {
				Name string `yaml:"name"`
				In   string `yaml:"in"`
			} `yaml:"parameters"`
			RequestBody struct {
				Required bool                      `yaml:"required"`
				Content  map[string]map[string]any `yaml:"content"`
			} `yaml:"requestBody"`
			Responses map[string]struct {
				Content map[string]map[string]any `yaml:"content"`
			} `yaml:"responses"`
		} `yaml:"paths"`
	}

	// When
	err := yaml.Unmarshal([]byte(buildOpenAPIYAML()), &document)

	// Then
	if err != nil {
		t.Fatalf("parse generated OpenAPI YAML: %v", err)
	}
	if _, exists := document.Paths["/users/{id}"]; !exists {
		t.Fatal("OpenAPI does not convert Gin path parameters")
	}
	if _, exists := document.Paths["/users/:id"]; exists {
		t.Fatal("OpenAPI retains Gin path syntax")
	}
	updateUser := document.Paths["/users/{id}"]["put"]
	if len(updateUser.Parameters) != 1 || updateUser.Parameters[0].Name != "id" || updateUser.Parameters[0].In != "path" {
		t.Fatalf("update user parameters=%+v", updateUser.Parameters)
	}
	metricsHistory := document.Paths["/metrics/history"]["get"]
	if len(metricsHistory.Parameters) != 2 {
		t.Fatalf("metrics history query parameters=%+v", metricsHistory.Parameters)
	}
	if _, exists := document.Paths["/users"]["post"].Responses["201"]; !exists {
		t.Fatal("create user success response is not 201")
	}
	snapshot := document.Paths["/cluster/sync/snapshot"]["get"]
	if response, exists := snapshot.Responses["304"]; !exists || len(response.Content) != 0 {
		t.Fatalf("snapshot 304 response=%+v exists=%v", response, exists)
	}
	adminTLS := document.Paths["/admin-tls"]["put"]
	if _, exists := adminTLS.RequestBody.Content["multipart/form-data"]; !exists {
		t.Fatal("admin TLS update request is not multipart/form-data")
	}
	// （2026-09-06 裁定）：批量全量重签须显式 {"all":true} 确认，请求体不再可省略
	issue := document.Paths["/certificates/issue"]["post"]
	if !issue.RequestBody.Required {
		t.Fatal("certificate issue request body must be required")
	}
}

func TestBuildOpenAPIYAML_documents_per_operation_security(t *testing.T) {
	// Given
	var document struct {
		Paths map[string]map[string]struct {
			Security []map[string][]string `yaml:"security"`
		} `yaml:"paths"`
		Components struct {
			SecuritySchemes map[string]any `yaml:"securitySchemes"`
		} `yaml:"components"`
	}

	// When
	err := yaml.Unmarshal([]byte(buildOpenAPIYAML()), &document)

	// Then
	if err != nil {
		t.Fatalf("parse generated OpenAPI YAML: %v", err)
	}
	for _, operation := range []struct {
		path   string
		method string
	}{{"/auth/login", "post"}, {"/auth/ticket-login", "post"}, {"/auth/setup", "get"}, {"/auth/setup", "post"}, {"/branding", "get"}} {
		security := document.Paths[operation.path][operation.method].Security
		if security == nil || len(security) != 0 {
			t.Errorf("%s %s security=%v, want explicit empty security", operation.method, operation.path, security)
		}
	}
	if _, exists := document.Components.SecuritySchemes["mcpApiKey"]; !exists {
		t.Fatal("OpenAPI missing independent MCP API key scheme")
	}
	mcpSecurity := document.Paths["/mcp"]["post"].Security
	if len(mcpSecurity) != 1 {
		t.Fatalf("MCP security=%v", mcpSecurity)
	}
	if _, exists := mcpSecurity[0]["mcpApiKey"]; !exists {
		t.Fatalf("MCP security=%v, want mcpApiKey", mcpSecurity)
	}
	confirmSecurity := document.Paths["/cluster/registration/confirm"]["post"].Security
	if len(confirmSecurity) != 1 {
		t.Fatalf("registration confirmation security=%v", confirmSecurity)
	}
	if _, exists := confirmSecurity[0]["clusterToken"]; !exists {
		t.Fatalf("registration confirmation security=%v, want clusterToken", confirmSecurity)
	}
	dashboardSecurity := document.Paths["/metrics/dashboard"]["get"].Security
	if len(dashboardSecurity) != 1 {
		t.Fatalf("metrics dashboard security=%v", dashboardSecurity)
	}
	if _, exists := dashboardSecurity[0]["bearerAuth"]; !exists {
		t.Fatalf("metrics dashboard security=%v, want bearerAuth", dashboardSecurity)
	}
}

func TestAPIDocRoutes_documents_registration_confirmation_lifecycle(t *testing.T) {
	// Given
	routes := make(map[string]apiDocRoute, len(apiDocRoutes))
	for _, route := range apiDocRoutes {
		routes[route.Method+" "+route.Path] = route
	}

	// When
	statusDescription := routes["GET /cluster/register/:id/status"].Description

	// Then
	if !strings.Contains(statusDescription, "确认") {
		t.Fatalf("registration status description does not direct clients to confirmation: %q", statusDescription)
	}
	if strings.Contains(statusDescription, "首次成功快照同步后失效") {
		t.Fatalf("registration status description retains snapshot-based invalidation: %q", statusDescription)
	}
}

func TestBuildOpenAPIYAML_wraps_business_examples_and_documents_exceptions(t *testing.T) {
	// Given
	openAPI := buildOpenAPIYAML()
	var document struct {
		Info struct {
			Description string `yaml:"description"`
		} `yaml:"info"`
		Paths map[string]map[string]struct {
			Description string `yaml:"description"`
			Responses   map[string]struct {
				Content map[string]struct {
					// /auth/oidc/login|callback 等跳转端点经
					// rawResponse 暴露裸字符串示例(302 形态),示例不再恒为
					// 对象——本测试只对 /config 的对象形状断言。
					Example any `yaml:"example"`
				} `yaml:"content"`
			} `yaml:"responses"`
		} `yaml:"paths"`
	}

	// When
	err := yaml.Unmarshal([]byte(openAPI), &document)

	// Then
	if err != nil {
		t.Fatalf("parse generated OpenAPI YAML: %v", err)
	}
	configExample, isObject := document.Paths["/config"]["get"].Responses["200"].Content["application/json"].Example.(map[string]any)
	if !isObject || configExample["code"] != 0 || configExample["data"] == nil {
		t.Fatalf("business response example=%v, want wrapped {code,message,data} object", configExample)
	}

	for _, exception := range []string{"登录", "下载", "MCP", "304", "HTML", "YAML"} {
		if !strings.Contains(document.Info.Description, exception) {
			t.Errorf("general description missing response exception %q", exception)
		}
	}
	for path, methods := range document.Paths {
		for method, operation := range methods {
			if method == "post" || method == "put" || method == "delete" {
				if !strings.Contains(operation.Description, "安全重试") {
					t.Errorf("%s %s lacks retry contract: %q", method, path, operation.Description)
				}
			}
		}
	}
	fragmentContract := document.Paths["/cluster/nodes/{id}/login-ticket"]["post"].Description
	for _, fragment := range []string{"#login_ticket=", "percent-encoded", "清除 fragment"} {
		if !strings.Contains(fragmentContract, fragment) {
			t.Errorf("login ticket description missing %q: %q", fragment, fragmentContract)
		}
	}
}

func TestAPIDocRoutes_document_validation_and_error_statuses(t *testing.T) {
	// Given
	routes := make(map[string]apiDocRoute, len(apiDocRoutes))
	for _, route := range apiDocRoutes {
		routes[route.Method+" "+route.Path] = route
	}

	// When
	validate := routes["POST /config/import/validate"]

	// Then
	for _, text := range []string{"200", "valid=false", "400", "413", "128MB"} {
		if !strings.Contains(validate.Description, text) && !containsRouteError(validate.Errors, text) {
			t.Errorf("validation contract missing %q: description=%q errors=%v", text, validate.Description, validate.Errors)
		}
	}
	for key, statuses := range map[string][]string{
		"POST /users":                       {"409"},
		"PUT /users/:id":                    {"404", "409"},
		"PUT /users/:id/status":             {"404", "409"},
		"DELETE /users/:id":                 {"404", "409"},
		"POST /users/:id/reset-password":    {"404"},
		"POST /certificates/jobs/:id/retry": {"409"},
		"POST /certificates/issue":          {"400", "404", "429", "500"},
	} {
		for _, status := range statuses {
			if !containsRouteError(routes[key].Errors, status) {
				t.Errorf("%s missing documented status %s: %v", key, status, routes[key].Errors)
			}
		}
	}
}

// 绊线
// export 去不可达 413(GET 无请求体);download 补 428(mfaStepUpGuard GET 特例,
// middleware.go:886-887);import 响应登记 data.summary/disabled_conflicts/warnings
// (warnings 为软跳过/会话吊销/ACME 悬挂等警告的唯一机器可读出口);promote 描述
// 对齐实现(不调 BumpClusterVersion,启动自动备份调度器);/mcp/tools 登记
// read_only 字段语义(HTTP 语义只读,不代表只读 Key 可见性)。
func TestAPIDocRoutes_importQueuePartialContract(t *testing.T) {
	routes := make(map[string]apiDocRoute, len(apiDocRoutes))
	for _, route := range apiDocRoutes {
		routes[route.Method+" "+route.Path] = route
	}
	route := routes["POST /config/import/v1"]
	if !containsRouteError(route.Errors, "409") {
		t.Fatalf("V1 import errors=%v, want certificate queue drain 409", route.Errors)
	}
	for _, field := range []string{"partial", "warnings", "disabled_conflicts"} {
		if !strings.Contains(route.Response, field) {
			t.Fatalf("V1 import response missing %s: %s", field, route.Response)
		}
	}
	if !strings.Contains(route.Description, "200") || !strings.Contains(route.Description, "partial=true") {
		t.Fatalf("V1 import description lacks committed/partial contract: %s", route.Description)
	}
}

func TestAPIDocRoutes_documentationContracts(t *testing.T) {
	routes := make(map[string]apiDocRoute, len(apiDocRoutes))
	for _, route := range apiDocRoutes {
		routes[route.Method+" "+route.Path] = route
	}

	for _, routeError := range routes["GET /config/export"].Errors {
		if strings.HasPrefix(routeError, "413") {
			t.Errorf("GET /config/export documents unreachable 413 (GET has no request body): %q", routeError)
		}
	}
	if !containsRouteError(routes["GET /auto-backup/:id/download"].Errors, "428") {
		t.Errorf("GET /auto-backup/:id/download errors=%v, want 428 mfa_step_up_required", routes["GET /auto-backup/:id/download"].Errors)
	}
	importRoute := routes["POST /config/import"]
	for _, field := range []string{"summary", "disabled_conflicts", "warnings"} {
		if !strings.Contains(importRoute.Response, field) {
			t.Errorf("POST /config/import response example missing data.%s: %s", field, importRoute.Response)
		}
	}
	promote := routes["POST /cluster/promote"].Description
	if strings.Contains(promote, "递增版本") {
		t.Errorf("POST /cluster/promote description retains 递增版本 (Promote does not bump cluster version): %q", promote)
	}
	if !strings.Contains(promote, "自动备份调度器") {
		t.Errorf("POST /cluster/promote description lacks auto-backup scheduler startup: %q", promote)
	}
	tools := routes["GET /mcp/tools"].Description
	// read_only 是「对只读 Key 可用」的能力语义，与
	// method==GET 不等价——描述必须点名 export_config 例外与读探测 POST，
	// 并逐工具钉死分类（弱子串断言曾把相反语义钉住）。
	for _, fragment := range []string{"read_only", "只读 API Key", "export_config"} {
		if !strings.Contains(tools, fragment) {
			t.Errorf("GET /mcp/tools description lacks %q: %q", fragment, tools)
		}
	}
	if strings.Contains(tools, "HTTP 语义只读") || strings.Contains(tools, "method==GET") {
		t.Errorf("GET /mcp/tools description retains stale HTTP-semantics read_only: %q", tools)
	}
	readOnlyProbes := map[string]bool{
		"parse_certificate": true, "validate_import": true, "preview_config": true,
	}
	// test_certificate_config 会写 DNS TXT 验证记录，
	// 已移出只读探测集——对只读 Key 不可见（工具保留给管理员）。
	// test_ca_provider 同理移出（ZeroSSL 缺 EAB 时
	// 会真实写 ca_providers.credentials）。
	specs := mcpserver.ListToolSpecs()
	if len(specs) == 0 {
		t.Fatal("ListToolSpecs returned no tools")
	}
	for _, spec := range specs {
		wantReadOnly := spec.Method == http.MethodGet && spec.Name != "export_config"
		if readOnlyProbes[spec.Name] {
			wantReadOnly = true
		}
		if spec.ReadOnly != wantReadOnly {
			t.Errorf("tool %s (%s) read_only=%v, want %v（只读 Key 可用性语义）", spec.Name, spec.Method, spec.ReadOnly, wantReadOnly)
		}
	}
	if config := specsReadOnly(specs, "export_config"); config != false {
		t.Errorf("export_config read_only=%v, want false（只读 Key 不可见）", config)
	}
	for name := range readOnlyProbes {
		if !specsReadOnly(specs, name) {
			t.Errorf("%s read_only=false, want true（读探测 POST 对只读 Key 可用）", name)
		}
	}
}

func specsReadOnly(specs []mcpserver.ToolSpec, name string) bool {
	for _, spec := range specs {
		if spec.Name == name {
			return spec.ReadOnly
		}
	}
	return false
}

// 非 JSON 响应示例（二进制/TXT）必须登记 rawResponse 与
// 显式媒体类型——此前两个下载端点默认 application/json 且被 documentedResponse
// 包成 {"code":0,...,"data":非 JSON}，OpenAPI 消费方按 JSON 解析必失败。
func TestAPIDocs_nonJSONResponsesDeclareExplicitMediaType(t *testing.T) {
	// Given 全部路由及其生成规格
	var document struct {
		Paths map[string]map[string]struct {
			Responses map[string]struct {
				Content map[string]struct {
					Example any `yaml:"example"`
				} `yaml:"content"`
			} `yaml:"responses"`
		} `yaml:"paths"`
	}
	if err := yaml.Unmarshal([]byte(buildOpenAPIYAML()), &document); err != nil {
		t.Fatalf("parse generated OpenAPI YAML: %v", err)
	}
	expected := map[string]string{
		"GET /auto-backup/:id/download":     "application/octet-stream",
		"GET /security/ip-lists/:id/export": "text/plain; charset=utf-8",
	}

	// When 逐路由检查非 JSON 响应示例（合法 JSON 数组/对象由生成器包成
	// {code,message,data} 信封；{...} 形态为文档占位符，同样按 JSON 处理；
	// 只有纯文本/二进制形态才必须显式登记）
	for _, route := range apiDocRoutes {
		response := strings.TrimSpace(route.Response)
		if response == "" || strings.HasPrefix(response, "{") || strings.HasPrefix(response, "[") || json.Valid([]byte(response)) {
			continue
		}
		key := route.Method + " " + route.Path
		contract := apiDocContracts[key]
		if !contract.rawResponse {
			t.Errorf("%s response example %q lacks rawResponse registration（会被包成 JSON 信封）", key, response)
		}
		if contract.responseContentType == "" {
			t.Errorf("%s response example %q lacks explicit responseContentType", key, response)
		}
	}

	// Then 两个已知下载端点：契约与生成的 YAML 媒体类型一致、示例为纯文本
	for key, contentType := range expected {
		contract := apiDocContracts[key]
		if !contract.rawResponse || contract.responseContentType != contentType {
			t.Errorf("%s contract=%+v, want rawResponse with %s", key, contract, contentType)
		}
		method, path := splitRouteKey(t, key)
		operation := document.Paths[apipath.ToOpenAPI(path)][strings.ToLower(method)]
		media := operation.Responses["200"].Content
		if _, ok := media[contentType]; !ok {
			t.Errorf("%s 200 content=%v, want %s", key, mediaTypeKeys(media), contentType)
		}
		if _, isJSON := media["application/json"]; isJSON {
			t.Errorf("%s still documents application/json response", key)
		}
		for _, entry := range media {
			if _, isMap := entry.Example.(map[string]any); isMap {
				t.Errorf("%s example=%v, want plain-text example (not JSON object)", key, entry.Example)
			}
		}
	}
}

func splitRouteKey(t *testing.T, key string) (string, string) {
	t.Helper()
	method, path, found := strings.Cut(key, " ")
	if !found {
		t.Fatalf("malformed route key %q", key)
	}
	return method, path
}

func mediaTypeKeys(media map[string]struct {
	Example any `yaml:"example"`
}) []string {
	keys := make([]string, 0, len(media))
	for key := range media {
		keys = append(keys, key)
	}
	return keys
}

// 媒体类型与示例形态须自洽——ops-playbook 声明
// text/markdown 却给 JSON 示例；/admin-tls 与 /admin-tls/inspect 只登记
// multipart，遗漏 MCP 通道唯一的 application/json 变体。
func TestBuildOpenAPIYAML_documentsMarkdownAndAdminTLSContentVariants(t *testing.T) {
	// Given
	var document struct {
		Paths map[string]map[string]struct {
			RequestBody struct {
				Content map[string]struct {
					Example any `yaml:"example"`
				} `yaml:"content"`
			} `yaml:"requestBody"`
			Responses map[string]struct {
				Content map[string]struct {
					Example any `yaml:"example"`
				} `yaml:"content"`
			} `yaml:"responses"`
		} `yaml:"paths"`
	}
	if err := yaml.Unmarshal([]byte(buildOpenAPIYAML()), &document); err != nil {
		t.Fatalf("parse generated OpenAPI YAML: %v", err)
	}

	// Then ops-playbook 示例是 markdown 正文而非 JSON 对象
	playbook := document.Paths["/mcp/ops-playbook"]["get"].Responses["200"].Content
	markdown, ok := playbook["text/markdown"]
	if !ok {
		t.Fatalf("/mcp/ops-playbook 200 content=%v, want text/markdown", mediaTypeKeys(playbook))
	}
	text, isString := markdown.Example.(string)
	if !isString || !strings.HasPrefix(text, "#") || !strings.Contains(text, "手册") {
		t.Errorf("/mcp/ops-playbook example=%v, want markdown text starting with #", markdown.Example)
	}

	// Then 两个 admin-tls 端点同时声明 multipart 与 application/json
	for _, operation := range []struct {
		path   string
		method string
	}{{"/admin-tls", "put"}, {"/admin-tls/inspect", "post"}} {
		content := document.Paths[operation.path][operation.method].RequestBody.Content
		if _, ok := content["multipart/form-data"]; !ok {
			t.Errorf("%s %s request content=%v, want multipart/form-data", operation.method, operation.path, mediaTypeKeys(content))
		}
		jsonEntry, ok := content["application/json"]
		if !ok {
			t.Errorf("%s %s request content=%v, want application/json variant (MCP 通道)", operation.method, operation.path, mediaTypeKeys(content))
			continue
		}
		if _, isMap := jsonEntry.Example.(map[string]any); !isMap {
			t.Errorf("%s %s JSON example=%v, want object", operation.method, operation.path, jsonEntry.Example)
		}
	}
}

func TestCreateUser_returnsConflict_whenUsernameAlreadyExists(t *testing.T) {
	// Given
	h := newBackupTestHandlers(t)
	seedUserAuditTest(t, 1, "duplicate", "admin", true)

	// When
	response := serveUserMutation(h, http.MethodPost, "/users", `{"username":"duplicate","password":"Secret1!","role":"user"}`, 1, h.CreateUser)

	// Then
	if response.Code != http.StatusConflict || !strings.Contains(response.Body.String(), "用户名已存在") {
		t.Fatalf("status=%d body=%q", response.Code, response.Body.String())
	}
}

func TestCreateUserError_usesChineseMessage(t *testing.T) {
	// Given
	h := &Handlers{}

	// When
	response := serveUserMutation(h, http.MethodPost, "/users", `{`, 1, h.CreateUser)

	// Then
	if !strings.Contains(response.Body.String(), "请求格式错误") {
		t.Fatalf("user error=%q", response.Body.String())
	}
}

func TestDeleteAPIKeyError_usesChineseMessage(t *testing.T) {
	// Given
	h := &Handlers{}
	response := httptest.NewRecorder()
	context, _ := gin.CreateTestContext(response)
	context.Request = httptest.NewRequest(http.MethodDelete, "/api-keys/invalid", nil)
	context.Params = gin.Params{{Key: "id", Value: "invalid"}}

	// When
	h.DeleteAPIKey(context)

	// Then
	if !strings.Contains(response.Body.String(), "ID 参数无效") {
		t.Fatalf("API key error=%q", response.Body.String())
	}
}

func TestGetBranding_returnsDefaults_withoutWritingMissingFile(t *testing.T) {
	// Given
	dataDir := t.TempDir()
	h := NewHandlers(Dependencies{Config: &config.Config{DataDir: dataDir, Version: "test"}})
	response := httptest.NewRecorder()
	context, _ := gin.CreateTestContext(response)
	context.Request = httptest.NewRequest(http.MethodGet, "/branding", nil)

	// When
	h.GetBranding(context)

	// Then
	if response.Code != http.StatusOK || !strings.Contains(response.Body.String(), `"version":"test"`) {
		t.Fatalf("status=%d body=%q", response.Code, response.Body.String())
	}
	if _, err := os.Stat(filepath.Join(dataDir, "branding.json")); !os.IsNotExist(err) {
		t.Fatalf("GET branding wrote file: %v", err)
	}
}

func TestGetBranding_fileVersion_overridesBuildVersion(t *testing.T) {
	// Given
	dataDir := t.TempDir()
	custom := `{"app_name":"Lazy Balancer","footer_text":"x","version":"9.9.9-custom"}`
	if err := os.WriteFile(filepath.Join(dataDir, "branding.json"), []byte(custom), 0o644); err != nil {
		t.Fatalf("write branding: %v", err)
	}
	h := NewHandlers(Dependencies{Config: &config.Config{DataDir: dataDir, Version: "2.0.7"}})
	response := httptest.NewRecorder()
	context, _ := gin.CreateTestContext(response)
	context.Request = httptest.NewRequest(http.MethodGet, "/branding", nil)

	// When
	h.GetBranding(context)

	// Then
	if response.Code != http.StatusOK || !strings.Contains(response.Body.String(), `"version":"9.9.9-custom"`) {
		t.Fatalf("file version must win over build version: status=%d body=%q", response.Code, response.Body.String())
	}
}

func containsRouteError(errors []string, status string) bool {
	for _, routeError := range errors {
		if strings.HasPrefix(routeError, status+" ") {
			return true
		}
	}
	return false
}

// ++:OIDC 公开契约登记、lbbak 导出形态、
// validate 128MB 上限与 settings/oidc 重试契约的文档漂移绊线。
func TestBuildOpenAPIYAML_documents_oidc_public_lbbak_and_retry_contracts(t *testing.T) {
	// Given
	var document struct {
		Paths map[string]map[string]struct {
			Security   []map[string][]string `yaml:"security"`
			Parameters []struct {
				Name string `yaml:"name"`
				In   string `yaml:"in"`
			} `yaml:"parameters"`
			RequestBody struct {
				Content map[string]map[string]any `yaml:"content"`
			} `yaml:"requestBody"`
			Responses map[string]struct {
				Content map[string]map[string]any `yaml:"content"`
			} `yaml:"responses"`
			Description string `yaml:"description"`
		} `yaml:"paths"`
	}
	err := yaml.Unmarshal([]byte(buildOpenAPIYAML()), &document)
	if err != nil {
		t.Fatalf("parse generated OpenAPI YAML: %v", err)
	}

	// 三条公开 OIDC 路由(登录页探测/授权跳转/回调)不得误标 bearerAuth。
	for _, operation := range []struct {
		path   string
		method string
	}{{"/auth/oidc/status", "get"}, {"/auth/oidc/login", "get"}, {"/auth/oidc/callback", "get"}} {
		security := document.Paths[operation.path][operation.method].Security
		if security == nil || len(security) != 0 {
			t.Errorf("C1: %s %s security=%v, want explicit empty security (public)", operation.method, operation.path, security)
		}
	}

	// ③:导出恒为 lbbak tar.gz(application/gzip),sections query 可选分类;
	// 描述不得再宣称「下载 JSON 备份文件」。
	export := document.Paths["/config/export"]["get"]
	if _, exists := export.Responses["200"].Content["application/gzip"]; !exists {
		t.Errorf("C2: /config/export 200 content=%v, want application/gzip (lbbak tar.gz)", export.Responses["200"].Content)
	}
	foundSections := false
	for _, parameter := range export.Parameters {
		if parameter.In == "query" && parameter.Name == "sections" {
			foundSections = true
		}
	}
	if !foundSections {
		t.Errorf("C2: /config/export parameters=%+v, want sections query parameter", export.Parameters)
	}
	if strings.Contains(export.Description, "JSON 备份文件") || !strings.Contains(export.Description, "lbbak") {
		t.Errorf("C2: /config/export description=%q, want lbbak tar.gz form", export.Description)
	}

	// validate 上限与错误码按 128MB 实现口径(maxConfigImportBytes=128<<20)。
	validate := routesEntry(t, "POST /config/import/validate")
	if !strings.Contains(validate.Description, "128MB") || !containsRouteError(validate.Errors, "413") {
		t.Errorf("C2: validate description=%q errors=%v, want 128MB limit text and 413 error", validate.Description, validate.Errors)
	}
	for _, routeError := range validate.Errors {
		if strings.Contains(routeError, "16") {
			t.Errorf("C2: validate error %q retains stale 16 MiB limit", routeError)
		}
	}
	// import 端点描述须覆盖二进制 lbbak 形态(tar.gz 而非仅 JSON)。
	imp := routesEntry(t, "POST /config/import")
	if !strings.Contains(imp.Description, "lbbak") {
		t.Errorf("C2: /config/import description=%q, want binary lbbak form documented", imp.Description)
	}

	// settings/oidc 三键重试契约(PUT/DELETE 幂等可重试,POST test 读探测可重试)。
	for _, operation := range []struct {
		path   string
		method string
	}{
		{"/settings/oidc", "put"},
		{"/settings/oidc", "delete"},
		{"/settings/oidc/test", "post"},
	} {
		description := document.Paths[operation.path][operation.method].Description
		// 幂等 PUT/DELETE 与读探测 POST 不得落入「不可安全重试」族
		//(通用兜底文案「不可安全重试：重复调用可能创建新资源…」含子串
		//「安全重试」,故以排除不可重试族为契约)。
		if strings.Contains(description, "不可安全重试") || strings.Contains(description, "不可盲目安全重试") {
			t.Errorf("C7: %s %s description=%q, want retryable contract", operation.method, operation.path, description)
		}
		if !strings.Contains(description, "重试") {
			t.Errorf("C7: %s %s description=%q lacks retry contract", operation.method, operation.path, description)
		}
	}
	// 回调错误表补 404 oidc_disabled/502 discovery;PUT 示例补 display_name。
	callback := routesEntry(t, "GET /auth/oidc/callback")
	if !containsRouteError(callback.Errors, "404") || !containsRouteError(callback.Errors, "502") {
		t.Errorf("C7: callback errors=%v, want 404 oidc_disabled and 502 discovery", callback.Errors)
	}
	oidcUpdate := routesEntry(t, "PUT /settings/oidc")
	if !strings.Contains(oidcUpdate.Request, "display_name") {
		t.Errorf("C7: PUT /settings/oidc request=%q, want display_name example field", oidcUpdate.Request)
	}
}

func routesEntry(t *testing.T, key string) apiDocRoute {
	t.Helper()
	for _, route := range apiDocRoutes {
		if route.Method+" "+route.Path == key {
			return route
		}
	}
	t.Fatalf("route %s missing from apiDocRoutes", key)
	return apiDocRoute{}
}

// 任务 ID 是 "threat"/"cert-job:5" 等字符串——OpenAPI
// 对 /system/tasks/{id} 族六个端点的路径参数必须保留 type: string（与其余
// 数字 :id 路由的 integer 判定分流）；MCP 侧同参数一直正确标 string，两侧
// 此前自相矛盾。
func TestBuildOpenAPIYAML_tasksPathParametersStayString(t *testing.T) {
	// Given
	var document struct {
		Paths map[string]map[string]struct {
			Parameters []struct {
				Name   string `yaml:"name"`
				In     string `yaml:"in"`
				Schema struct {
					Type string `yaml:"type"`
				} `yaml:"schema"`
			} `yaml:"parameters"`
		} `yaml:"paths"`
	}

	// When
	err := yaml.Unmarshal([]byte(buildOpenAPIYAML()), &document)

	// Then
	if err != nil {
		t.Fatalf("parse generated OpenAPI YAML: %v", err)
	}
	for _, operation := range []struct{ path, method string }{
		{"/system/tasks/{id}/logs", "get"},
		{"/system/tasks/{id}/history", "get"},
		{"/system/tasks/{id}/trigger", "post"},
		{"/system/tasks/{id}/toggle", "post"},
		{"/system/tasks/{id}/control", "post"},
		{"/system/tasks/{id}/cancel", "post"},
	} {
		parameters := document.Paths[operation.path][operation.method].Parameters
		if len(parameters) != 1 || parameters[0].Name != "id" || parameters[0].In != "path" {
			t.Fatalf("%s %s parameters=%+v", operation.method, operation.path, parameters)
		}
		if parameters[0].Schema.Type != "string" {
			t.Errorf("%s %s id schema type=%q, want string (task IDs such as \"threat\" or \"cert-job:5\" are strings)", operation.method, operation.path, parameters[0].Schema.Type)
		}
	}
	// 回归形状：数字 :id 路由不受 tasks 分流影响，保持 integer。
	if parameters := document.Paths["/users/{id}"]["put"].Parameters; len(parameters) != 1 || parameters[0].Schema.Type != "integer" {
		t.Fatalf("PUT /users/{id} parameters=%+v, want id integer", parameters)
	}
}

// 威胁大屏文档响应示例键集必须与实现一致——
// rollup 改造（top_rules/attack_type_share/recent_rate/rollup_* 披露）后文档滞后。
// 钉测直接调用真实 handler 取响应键集，与 apiDocRoutes 示例双向比对。
func TestAPIDocs_threatScreenExampleKeysMatchImplementation(t *testing.T) {
	setupSecurityPolicyTestDB(t)
	router := newThreatScreenRouter(t, newThreatMetricsServer(t).URL)
	recorder := getRequest(t, router, "/security/overview/threat-screen")
	if recorder.Code != http.StatusOK {
		t.Fatalf("status=%d body=%s", recorder.Code, recorder.Body.String())
	}
	var impl struct {
		Data map[string]any `json:"data"`
	}
	if err := json.Unmarshal(recorder.Body.Bytes(), &impl); err != nil {
		t.Fatalf("parse implementation response: %v", err)
	}

	var docExample map[string]any
	for _, route := range apiDocRoutes {
		if route.Method == http.MethodGet && route.Path == "/security/overview/threat-screen" {
			if err := json.Unmarshal([]byte(route.Response), &docExample); err != nil {
				t.Fatalf("parse doc example: %v", err)
			}
		}
	}
	if docExample == nil {
		t.Fatal("apiDocRoutes missing GET /security/overview/threat-screen entry")
	}

	for key := range impl.Data {
		if _, ok := docExample[key]; !ok {
			t.Errorf("实现响应键 %q 未在文档示例中", key)
		}
	}
	for key := range docExample {
		if _, ok := impl.Data[key]; !ok {
			t.Errorf("文档示例键 %q 实现未返回", key)
		}
	}
}

// OpenAPI 总述的敏感材料可见性必须与实现同口径——
// TLS 私钥（rules.go）与 DNS 凭证（certificates.go）对非管理员
// 与只读 API Key 一律掩码，总述不得再声称「对所有已登录用户可读」。
func TestBuildOpenAPIYAML_descriptionMatchesCredentialMasking(t *testing.T) {
	openAPI := buildOpenAPIYAML()
	var document struct {
		Info struct {
			Description string `yaml:"description"`
		} `yaml:"info"`
	}
	if err := yaml.Unmarshal([]byte(openAPI), &document); err != nil {
		t.Fatalf("parse generated OpenAPI YAML: %v", err)
	}
	description := document.Info.Description
	if strings.Contains(description, "TLS 私钥、DNS 凭证及其他配置数据对所有已登录用户可读") {
		t.Fatalf("general description retains stale readable-by-all claim: %q", description)
	}
	for _, fragment := range []string{"TLS 私钥与 DNS 凭证仅对管理员", "掩码", "TLSKeySet"} {
		if !strings.Contains(description, fragment) {
			t.Errorf("general description missing masking contract %q: %q", fragment, description)
		}
	}
}

// GET /certificates/jobs 的文档示例曾写成裸数组，
// documentedResponse 会把它包成 data:[...]，与实现的 data.list/total/page/
// page_size/status_counts 对象分叉——按文档生成 SDK/脚本的消费方解析必失败。
// 钉测直接调用真实 handler 取 data 顶层键集，与 apiDocRoutes 示例双向比对。
func TestAPIDocs_certJobListExampleKeysMatchImplementation(t *testing.T) {
	h := newBackupTestHandlers(t)
	router := gin.New()
	router.GET("/certificates/jobs", h.ListCertJobs)
	recorder := httptest.NewRecorder()
	router.ServeHTTP(recorder, httptest.NewRequest(http.MethodGet, "/certificates/jobs", nil))
	if recorder.Code != http.StatusOK {
		t.Fatalf("status=%d body=%s", recorder.Code, recorder.Body.String())
	}
	var impl struct {
		Data map[string]any `json:"data"`
	}
	if err := json.Unmarshal(recorder.Body.Bytes(), &impl); err != nil {
		t.Fatalf("parse implementation response: %v", err)
	}

	var docExample map[string]any
	for _, route := range apiDocRoutes {
		if route.Method == http.MethodGet && route.Path == "/certificates/jobs" {
			if err := json.Unmarshal([]byte(route.Response), &docExample); err != nil {
				t.Fatalf("文档示例必须是 data 对象的 JSON（裸数组会与实现 data.list 分叉）: %v", err)
			}
		}
	}
	if docExample == nil {
		t.Fatal("apiDocRoutes missing GET /certificates/jobs entry")
	}
	for key := range impl.Data {
		if _, ok := docExample[key]; !ok {
			t.Errorf("实现响应键 %q 未在文档示例中", key)
		}
	}
	for key := range docExample {
		if _, ok := impl.Data[key]; !ok {
			t.Errorf("文档示例键 %q 实现未返回", key)
		}
	}
}

// 写操作 428 生成门：mfaStepUpGuard 覆盖的全部 JWT 写路由（writeMethods +
// 敏感导出 GET，豁免机制本体 verify-step/logout、非 JWT 认证面、只读语义写
// 路由——判定与 middleware/services 同一事实源）必须在错误表登记 428。
// 此前 428 靠手工登记，系统性漏网（规则写族/安全写族等均未登记）。
func TestAPIDocRoutes_writeEndpointsDocumentMFAStepUp(t *testing.T) {
	writeMethods := map[string]bool{http.MethodPost: true, http.MethodPut: true, http.MethodPatch: true, http.MethodDelete: true}
	// 与写操作同敏感级的导出 GET（middleware sensitiveExportGetRoutes 同名单，
	// apiKeyReadOnlyGuard 与 mfaStepUpGuard 共用）。
	sensitiveExportGets := map[string]bool{"GET /config/export": true, "GET /auto-backup/:id/download": true}
	// step-up 机制本体与登出豁免（DecideMFAStepUp 短路，428 不可达）。
	stepUpExempt := map[string]bool{"POST /auth/logout": true, "POST /auth/mfa/verify-step": true}
	checked := 0
	for _, route := range apiDocRoutes {
		key := route.Method + " " + route.Path
		if !writeMethods[route.Method] && !sensitiveExportGets[key] {
			continue
		}
		// 非 JWT 认证面（公开/集群机器/MCP 专用头）无 step-up 语义。
		if apiDocContractFor(route).security != "" {
			continue
		}
		if stepUpExempt[key] {
			continue
		}
		// 只读语义写路由（批量查询/测试/预览/采集租约）与只读 Key 同一事实源豁免。
		if services.IsReadOnlyWriteRoute(route.Method, "/api/v1"+route.Path) {
			continue
		}
		checked++
		if !containsRouteError(route.Errors, "428") {
			t.Errorf("%s errors=%v, want 428 mfa_step_up_required（mfaStepUpGuard 覆盖的 JWT 写操作）", key, route.Errors)
		}
	}
	if checked == 0 {
		t.Fatal("no write routes checked——428 生成门比对形态失效")
	}
}

// MFA 写端点的两个跨切错误：配置导入窗口 409（users 表在全量替换清单内，
// 窗口内写入会被静默覆盖）与 OIDC 用户 403（OIDC 身份由 IdP 承担，不支持
// 本地 MFA 操作）——五个端点同门（mfa.go rejectWriteDuringImport /
// rejectOIDCUserMFAOperation）。
func TestAPIDocRoutes_mfaWriteEndpointsDocumentImportWindowAndOIDC(t *testing.T) {
	for _, key := range []string{
		"POST /auth/mfa/setup",
		"POST /auth/mfa/activate",
		"POST /auth/mfa/disable",
		"POST /auth/mfa/recovery-codes",
		"POST /users/:id/mfa/reset",
	} {
		route := routesEntry(t, key)
		if !containsRouteError(route.Errors, "409") {
			t.Errorf("%s errors=%v, want 409（配置导入窗口拒绝 MFA 写）", key, route.Errors)
		}
	}
	for _, key := range []string{
		"POST /auth/mfa/setup",
		"POST /auth/mfa/activate",
		"POST /auth/mfa/disable",
		"POST /auth/mfa/recovery-codes",
	} {
		route := routesEntry(t, key)
		if !containsRouteError(route.Errors, "403") {
			t.Errorf("%s errors=%v, want 403（OIDC 用户不支持本地 MFA）", key, route.Errors)
		}
	}
	// 管理端重置已有 403 admin_required（同码去重）；OIDC 目标拒绝须进描述。
	if !strings.Contains(routesEntry(t, "POST /users/:id/mfa/reset").Description, "OIDC") {
		t.Errorf("POST /users/:id/mfa/reset description lacks OIDC 目标拒绝说明")
	}
}

// 分页/时间参数校验 400：安全事件与证书任务列表对非法 page/page_size 与
// 无效/倒置时间区间返回 400（非静默忽略），错误表必须登记。
func TestAPIDocRoutes_paginatedReadsDocumentValidation400(t *testing.T) {
	for _, key := range []string{"GET /security/events", "GET /certificates/jobs"} {
		route := routesEntry(t, key)
		if !containsRouteError(route.Errors, "400") {
			t.Errorf("%s errors=%v, want 400（非法分页/时间参数显式拒绝）", key, route.Errors)
		}
	}
}

// 契约表绊线①：apiDocContracts 每个键必须命中 apiDocRoutes——字符串键松
// 耦合下错拼/删除残留会静默回落默认契约（bearerAuth/200/JSON），已实证
// 漂移到机器接口误标。
func TestAPIDocContracts_keysExistInRoutes(t *testing.T) {
	routeKeys := make(map[string]bool, len(apiDocRoutes))
	for _, route := range apiDocRoutes {
		routeKeys[route.Method+" "+route.Path] = true
	}
	for key := range apiDocContracts {
		if !routeKeys[key] {
			t.Errorf("apiDocContracts 键 %q 不在 apiDocRoutes——错拼或路由删除残留", key)
		}
	}
}

// GET 不得产出 requestBody：查询参数一律经契约表 queryParameters 登记为
// parameters(in: query)。此前三条大屏 GET 把查询串放进 Request 字段，
// 被生成器输出成带 JSON 示例的 requestBody——SDK 按 body 构参恒不生效。
func TestAPIDocRoutes_getRequestsDeclareQueryNotBody(t *testing.T) {
	for _, route := range apiDocRoutes {
		if route.Method == http.MethodGet && route.Request != "" {
			t.Errorf("GET %s 的 Request 字段非空（%q）——GET 查询参数必须走 queryParameters，Request 仅用于 body 方法", route.Path, route.Request)
		}
	}
	var document struct {
		Paths map[string]map[string]struct {
			RequestBody map[string]any `yaml:"requestBody"`
			Parameters  []struct {
				Name string `yaml:"name"`
				In   string `yaml:"in"`
			} `yaml:"parameters"`
		} `yaml:"paths"`
	}
	if err := yaml.Unmarshal([]byte(buildOpenAPIYAML()), &document); err != nil {
		t.Fatalf("parse generated OpenAPI YAML: %v", err)
	}
	for path, operations := range document.Paths {
		if get, ok := operations["get"]; ok && get.RequestBody != nil {
			t.Errorf("GET %s 生成了 requestBody——GET 不得有请求体", path)
		}
	}
	// 游标/窗口参数逐个登记为 query 参数。
	wantQuery := map[string][]string{
		"/security/overview/threat-screen":             {"hours"},
		"/security/events/feed":                        {"since_id", "limit"},
		"/security/events/toast-summary":               {"since_id", "limit", "baseline"},
		"/security/overview/threat-screen/attack-flow": {"since", "limit"},
		"/security/overview/threat-screen/events":      {"since", "limit"},
		"/security/events/count":                       {"ip", "days"},
	}
	for path, names := range wantQuery {
		get, ok := document.Paths[path]["get"]
		if !ok {
			t.Errorf("OpenAPI missing GET %s", path)
			continue
		}
		got := make(map[string]bool, len(get.Parameters))
		for _, parameter := range get.Parameters {
			if parameter.In == "query" {
				got[parameter.Name] = true
			}
		}
		for _, name := range names {
			if !got[name] {
				t.Errorf("GET %s 缺 query 参数 %q（现有 %v）", path, name, got)
			}
		}
	}
}

// 成功状态码契约：异步受理 202 与浏览器跳转 302 不得输出成默认 200
// （生成客户端把 202/302 当非成功处理，备份触发/OIDC 登录集成断裂）。
func TestBuildOpenAPIYAML_documentsNon200SuccessStatuses(t *testing.T) {
	var document struct {
		Paths map[string]map[string]struct {
			Responses map[string]any `yaml:"responses"`
		} `yaml:"paths"`
	}
	if err := yaml.Unmarshal([]byte(buildOpenAPIYAML()), &document); err != nil {
		t.Fatalf("parse generated OpenAPI YAML: %v", err)
	}
	want := map[string]string{
		"/auto-backup/run post":   "202",
		"/auth/oidc/login get":    "302",
		"/auth/oidc/callback get": "302",
	}
	for operation, status := range want {
		path, method, _ := strings.Cut(operation, " ")
		responses := document.Paths[path][method].Responses
		if _, ok := responses[status]; !ok {
			t.Errorf("%s %s responses=%v, want 成功状态码 %s", method, path, responseKeys(responses), status)
		}
	}
}

func responseKeys(responses map[string]any) []string {
	keys := make([]string, 0, len(responses))
	for key := range responses {
		keys = append(keys, key)
	}
	return keys
}

// MFA 首次绑定无需请求体（未启用 MFA 时空 body 合法）——requestBody 必须
// 标 required:false，否则 codegen 客户端会发无意义 {} 或拒绝调用。
func TestBuildOpenAPIYAML_mfaSetupBodyOptional(t *testing.T) {
	var document struct {
		Paths map[string]map[string]struct {
			RequestBody struct {
				Required bool `yaml:"required"`
			} `yaml:"requestBody"`
		} `yaml:"paths"`
	}
	if err := yaml.Unmarshal([]byte(buildOpenAPIYAML()), &document); err != nil {
		t.Fatalf("parse generated OpenAPI YAML: %v", err)
	}
	setup, ok := document.Paths["/auth/mfa/setup"]["post"]
	if !ok {
		t.Fatal("OpenAPI missing POST /auth/mfa/setup")
	}
	if setup.RequestBody.Required {
		t.Error("POST /auth/mfa/setup requestBody.required=true, want false（首次绑定无需请求体）")
	}
}

// policy_type=mixed 是存量兼容形态：显式提交与跨阶段内容推断均被 400 拒绝，
// 创建/更新描述不得宣称可显式提交 mixed。
func TestAPIDocRoutes_policyTypeMixedDocumentationMatchesRejection(t *testing.T) {
	for _, key := range []string{"POST /security/policies", "PUT /security/policies/:id"} {
		description := routesEntry(t, key).Description
		if strings.Contains(description, "显式 mixed 须") {
			t.Errorf("%s description 仍宣称显式 mixed 可提交: %q", key, description)
		}
		if !strings.Contains(description, "mixed") || !strings.Contains(description, "拒绝") {
			t.Errorf("%s description 须说明 mixed 显式提交/跨阶段推断被拒绝: %q", key, description)
		}
	}
}

// system=true 内置名单分两类：威胁情报名单只读（写路径 400）、自动封禁预置
// 名单可增删处置（含解封语义）——两处描述必须同时表达两类语义，不得互斥表述。
func TestAPIDocRoutes_systemIPListSemanticsConsistent(t *testing.T) {
	for _, key := range []string{"GET /security/ip-lists", "GET /security/ip-lists/:id"} {
		description := routesEntry(t, key).Description
		if !strings.Contains(description, "威胁") || !strings.Contains(description, "自动封禁") {
			t.Errorf("%s description 须同时说明两类 system=1 名单语义: %q", key, description)
		}
		if strings.Contains(description, "内置只读名单") || strings.Contains(description, "内置名单只读（写路径一律 400）") {
			t.Errorf("%s description 仍把所有 system=1 名单表述为只读: %q", key, description)
		}
	}
}

// —— 响应示例键对账（扩面：原仅威胁大屏与证书任务两个端点）——

// jsonTagKeySet 反射收集结构体的 JSON 键集（跳过 "-"，递归匿名内嵌）。
// 返回 (全部键, 非 omitempty 键)——omitempty 键允许文档示例有而实时响应无。
func jsonTagKeySet(t *testing.T, sample any) (all, required map[string]bool) {
	t.Helper()
	all, required = make(map[string]bool), make(map[string]bool)
	valueType := reflect.TypeOf(sample)
	for valueType.Kind() == reflect.Pointer {
		valueType = valueType.Elem()
	}
	if valueType.Kind() != reflect.Struct {
		t.Fatalf("sample %T is not a struct", sample)
	}
	for i := range valueType.NumField() {
		field := valueType.Field(i)
		if field.Anonymous {
			subAll, subRequired := jsonTagKeySet(t, reflect.New(field.Type).Elem().Interface())
			for key := range subAll {
				all[key] = true
			}
			for key := range subRequired {
				required[key] = true
			}
			continue
		}
		name, opts, _ := strings.Cut(field.Tag.Get("json"), ",")
		if name == "" || name == "-" {
			continue
		}
		all[name] = true
		if !strings.Contains(opts, "omitempty") {
			required[name] = true
		}
	}
	return all, required
}

func docResponseExample(t *testing.T, key string) map[string]any {
	t.Helper()
	route := routesEntry(t, key)
	var example map[string]any
	if err := json.Unmarshal([]byte(route.Response), &example); err != nil {
		t.Fatalf("%s 文档示例必须是 data 对象的 JSON: %v", key, err)
	}
	// 示例为完整信封（{"code":...,"data":{...}}）形态时解包到 data 载荷。
	if data, ok := example["data"].(map[string]any); ok {
		if _, hasCode := example["code"]; hasCode {
			return data
		}
	}
	return example
}

func assertKeySetsEqual(t *testing.T, context string, docKeys, implKeys map[string]bool) {
	t.Helper()
	for key := range implKeys {
		if !docKeys[key] {
			t.Errorf("%s：实现响应键 %q 未在文档示例中", context, key)
		}
	}
	for key := range docKeys {
		if !implKeys[key] {
			t.Errorf("%s：文档示例键 %q 实现未返回", context, key)
		}
	}
}

// assertStructKeysDocumented 校验文档示例键集落在 struct 全部键内、且覆盖
// 全部非 omitempty 键（omitempty 键空值不下发，示例可含可不含）。
func assertStructKeysDocumented(t *testing.T, context string, docKeys map[string]bool, sample any) {
	t.Helper()
	all, required := jsonTagKeySet(t, sample)
	for key := range required {
		if !docKeys[key] {
			t.Errorf("%s：实现响应键 %q 未在文档示例中", context, key)
		}
	}
	for key := range docKeys {
		if !all[key] {
			t.Errorf("%s：文档示例键 %q 实现结构无此字段", context, key)
		}
	}
}

func mapKeysOf(m map[string]any) map[string]bool {
	keys := make(map[string]bool, len(m))
	for key := range m {
		keys[key] = true
	}
	return keys
}

// 安全总览：包装结构 securityOverviewResponse（内嵌 models.SecurityOverview +
// raw_coverage_from/backfill_incomplete/includes_reserved/ingestion）——示例缺
// crs_available/update_status/attack_types_stage 等键会让消费者丢失覆盖可信度
// 与采集健康位。
func TestAPIDocs_securityOverviewExampleKeysMatchImplementation(t *testing.T) {
	example := docResponseExample(t, "GET /security/overview")
	assertStructKeysDocumented(t, "GET /security/overview", mapKeysOf(example), securityOverviewResponse{})

	nested := func(arrayKey string, sample any) {
		t.Helper()
		items, ok := example[arrayKey].([]any)
		if !ok || len(items) == 0 {
			t.Errorf("GET /security/overview 示例缺 %s 数组元素", arrayKey)
			return
		}
		item, ok := items[0].(map[string]any)
		if !ok {
			t.Errorf("GET /security/overview 示例 %s[0] 不是对象", arrayKey)
			return
		}
		assertStructKeysDocumented(t, "GET /security/overview "+arrayKey+"[]", mapKeysOf(item), sample)
	}
	nested("top_ips", models.SecurityTopIP{})
	nested("trend", models.SecurityTrendPoint{})
	nested("attack_types", models.SecurityAttackType{})
	nested("attack_types_stage", models.SecurityAttackType{})
	ingestion, ok := example["ingestion"].(map[string]any)
	if !ok {
		t.Fatalf("GET /security/overview 示例缺 ingestion 对象")
	}
	assertStructKeysDocumented(t, "GET /security/overview ingestion", mapKeysOf(ingestion), services.SecurityEventsIngestionHealthSnapshot())
}

// 安全事件列表：data 恒含 includes_reserved（口径披露）与 ingestion（采集
// 健康位，与总览同源）——示例缺键会丢关键字段。MetricsDB 未装配分支与成功
// 路径同键形状，直接取降级分支对账。
func TestAPIDocs_securityEventsExampleKeysMatchImplementation(t *testing.T) {
	h := newBackupTestHandlers(t)
	oldMetricsDB := db.MetricsDB
	db.MetricsDB = nil
	t.Cleanup(func() { db.MetricsDB = oldMetricsDB })

	router := gin.New()
	router.GET("/security/events", h.ListSecurityEvents)
	recorder := httptest.NewRecorder()
	router.ServeHTTP(recorder, httptest.NewRequest(http.MethodGet, "/security/events", nil))
	if recorder.Code != http.StatusOK {
		t.Fatalf("status=%d body=%s", recorder.Code, recorder.Body.String())
	}
	var impl struct {
		Data map[string]any `json:"data"`
	}
	if err := json.Unmarshal(recorder.Body.Bytes(), &impl); err != nil {
		t.Fatalf("parse implementation response: %v", err)
	}
	assertKeySetsEqual(t, "GET /security/events", mapKeysOf(docResponseExample(t, "GET /security/events")), mapKeysOf(impl.Data))
}

// Caddy 状态：statusData 七键（含 pid 与 background_apply_error）——示例缺
// pid/后台重载失败面会让巡检脚本误判进程态与配置收敛态。
func TestAPIDocs_caddyStatusExampleKeysMatchImplementation(t *testing.T) {
	h := newBackupTestHandlers(t)
	router := gin.New()
	router.GET("/caddy/status", h.GetCaddyStatus)
	recorder := httptest.NewRecorder()
	router.ServeHTTP(recorder, httptest.NewRequest(http.MethodGet, "/caddy/status", nil))
	if recorder.Code != http.StatusOK {
		t.Fatalf("status=%d body=%s", recorder.Code, recorder.Body.String())
	}
	var impl struct {
		Data map[string]any `json:"data"`
	}
	if err := json.Unmarshal(recorder.Body.Bytes(), &impl); err != nil {
		t.Fatalf("parse implementation response: %v", err)
	}
	assertKeySetsEqual(t, "GET /caddy/status", mapKeysOf(docResponseExample(t, "GET /caddy/status")), mapKeysOf(impl.Data))
}

// 集群状态：ClusterStatus 含 sync_users/sync_rules/sync_security 三开关与
// transport_insecure 明文链路标志——示例缺键会让外部监控漏掉同步范围与
// 明文传输常驻提示。
func TestAPIDocs_clusterStatusExampleKeysMatchImplementation(t *testing.T) {
	h := newBackupTestHandlers(t)
	if _, err := db.DB.Exec("INSERT OR IGNORE INTO global_config (id) VALUES (1)"); err != nil {
		t.Fatalf("seed global_config: %v", err)
	}
	router := gin.New()
	router.GET("/cluster/status", h.GetClusterStatus)
	recorder := httptest.NewRecorder()
	router.ServeHTTP(recorder, httptest.NewRequest(http.MethodGet, "/cluster/status", nil))
	if recorder.Code != http.StatusOK {
		t.Fatalf("status=%d body=%s", recorder.Code, recorder.Body.String())
	}
	var impl struct {
		Data map[string]any `json:"data"`
	}
	if err := json.Unmarshal(recorder.Body.Bytes(), &impl); err != nil {
		t.Fatalf("parse implementation response: %v", err)
	}
	assertKeySetsEqual(t, "GET /cluster/status", mapKeysOf(docResponseExample(t, "GET /cluster/status")), mapKeysOf(impl.Data))
}

// 任务监控聚合：顶层含 tasks 与 cert_jobs_truncated；任务项键集以
// services.TaskInfo/TaskRunInfo 为准（omitempty 键允许示例有而实时响应
// 无——反射键集是全集上界）。
func TestAPIDocs_systemTasksExampleKeysMatchImplementation(t *testing.T) {
	example := docResponseExample(t, "GET /system/tasks")
	for _, key := range []string{"tasks", "cert_jobs_truncated"} {
		if _, ok := example[key]; !ok {
			t.Errorf("GET /system/tasks 示例缺顶层键 %q", key)
		}
	}
	items, ok := example["tasks"].([]any)
	if !ok || len(items) == 0 {
		t.Fatalf("GET /system/tasks 示例缺 tasks 数组元素")
	}
	item, ok := items[0].(map[string]any)
	if !ok {
		t.Fatalf("GET /system/tasks 示例 tasks[0] 不是对象")
	}
	taskAll, _ := jsonTagKeySet(t, services.TaskInfo{})
	for key := range mapKeysOf(item) {
		if !taskAll[key] {
			t.Errorf("GET /system/tasks 示例 tasks[] 键 %q 不在 TaskInfo", key)
		}
	}
	// 任务说明/运行节奏必须在示例中；started_at 仍属 TaskInfo 全集但仅
	// 常驻族有值（Scheduled 示例不得携带）。
	for _, key := range []string{"description", "cadence"} {
		if !taskAll[key] {
			t.Fatalf("TaskInfo 已无 %q 字段——本钉测需同步", key)
		}
		if _, ok := item[key]; !ok {
			t.Errorf("GET /system/tasks 示例 tasks[] 缺 %q", key)
		}
	}
	if !taskAll["started_at"] {
		t.Fatal("TaskInfo 已无 started_at 字段——本钉测需同步")
	}
	// 示例值必须与实现口径一致（键集测试拦不住值漂移）：
	// Scheduled 的 cadence 恒「定时排程」；threat 可取消（Cancelable=true）；
	// started_at 仅常驻族非空（Scheduled 示例不得携带）。
	if got, _ := item["cadence"].(string); got != "定时排程" {
		t.Errorf("GET /system/tasks 示例 cadence=%q, want 定时排程（Scheduled 实现口径）", got)
	}
	if got, ok := item["cancellable"].(bool); !ok || !got {
		t.Errorf("GET /system/tasks 示例 cancellable=%v, want true（threat 注册 Cancelable=true）", item["cancellable"])
	}
	if _, exists := item["started_at"]; exists {
		t.Error("GET /system/tasks 示例不得为 Scheduled 任务携带 started_at（仅常驻族非空）")
	}
	lastRun, ok := item["last_run"].(map[string]any)
	if !ok {
		t.Fatalf("GET /system/tasks 示例缺 last_run 对象")
	}
	runAll, _ := jsonTagKeySet(t, services.TaskRunInfo{})
	for key := range mapKeysOf(lastRun) {
		if !runAll[key] {
			t.Errorf("GET /system/tasks 示例 last_run 键 %q 不在 TaskRunInfo", key)
		}
	}
}

// 废弃字段响应面收敛：upstreams.dynamic_dns（写侧恒 0 的废弃列）与全局
// dns_provider/dns_credentials（签发链不消费的遗留字段，凭证恒空）不再随
// API 响应下发——消费者不得据恒假值做判定。DB 列与导入/快照兼容不受影响
// （缺省即零值）。
func TestDeprecatedFields_omittedFromAPIResponses(t *testing.T) {
	upstreamJSON, err := json.Marshal(models.Upstream{Host: "127.0.0.1", Port: 9000})
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(upstreamJSON), "dynamic_dns") {
		t.Errorf("Upstream 零值仍下发废弃 dynamic_dns 键: %s", upstreamJSON)
	}
	configJSON, err := json.Marshal(models.GlobalConfig{})
	if err != nil {
		t.Fatal(err)
	}
	for _, key := range []string{"dns_provider", "dns_credentials"} {
		if strings.Contains(string(configJSON), `"`+key+`"`) {
			t.Errorf("GlobalConfig 零值仍下发遗留键 %s: %s", key, configJSON)
		}
	}
}
