package services

import (
	"strings"
	"testing"
)

// staticResponsePathRule 构造静态响应路径规则（默认不携带上游）。
func staticResponsePathRule(code int, redirectURL, body, contentType string) PathRuleConfig {
	return PathRuleConfig{
		SortOrder:    1,
		MatchType:    "prefix",
		Path:         "/static",
		Action:       "respond",
		StatusCode:   code,
		RedirectURL:  redirectURL,
		ResponseBody: body,
		ContentType:  contentType,
	}
}

// lastHandlerOf 返回路由链尾 handler（断言终结形态）。
func lastHandlerOf(t *testing.T, route map[string]interface{}) map[string]interface{} {
	t.Helper()
	handlers, ok := route["handle"].([]interface{})
	if !ok || len(handlers) == 0 {
		t.Fatalf("route handle has type %T / empty", route["handle"])
	}
	last, ok := handlers[len(handlers)-1].(map[string]interface{})
	if !ok {
		t.Fatalf("last handler has type %T", handlers[len(handlers)-1])
	}
	return last
}

// responseHeadersOf 取 static_response 的 headers（缺失返回空表）。
func responseHeadersOf(t *testing.T, handler map[string]interface{}) map[string]interface{} {
	t.Helper()
	if handler["handler"] != "static_response" {
		t.Fatalf("handler=%v, want static_response: %#v", handler["handler"], handler)
	}
	headers, ok := handler["headers"].(map[string]interface{})
	if !ok {
		return map[string]interface{}{}
	}
	return headers
}

// headerValuesOf 取响应头值切片（缺失返回 nil）。
func headerValuesOf(headers map[string]interface{}, name string) []string {
	values, ok := headers[name].([]string)
	if !ok {
		return nil
	}
	return values
}

// Given: 路径规则配置为静态响应（200 + 响应体）
// When: 生成 HTTP 路由对象
// Then: 该路径路由链尾为本程序 static_response（不含 reverse_proxy），
// 且默认补 Content-Type 并原样携带响应体
func TestStaticResponsePathRule_rendersStaticResponseNotProxy(t *testing.T) {
	rule := baseHTTPRule()
	rule.CustomRoutesEnabled = true
	rule.PathRules = []PathRuleConfig{staticResponsePathRule(200, "", "<h1>maintenance</h1>", "")}

	routes, _, err := generateHTTPRouteObjects(rule)
	if err != nil {
		t.Fatalf("generate HTTP route objects: %v", err)
	}
	pathRoute := upstreamPathRouteByID(t, routes, "rule-http_path_0")
	chain := marshalChain(t, pathRoute)
	handler := lastHandlerOf(t, pathRoute)
	if handler["handler"] != "static_response" {
		t.Fatalf("chain tail handler=%v, want static_response: %s", handler["handler"], chain)
	}
	if got := handler["status_code"]; got != 200 {
		t.Fatalf("status_code=%v, want 200", got)
	}
	if got := handler["body"]; got != "<h1>maintenance</h1>" {
		t.Fatalf("body=%v, want raw HTML", got)
	}
	headers := responseHeadersOf(t, handler)
	if got := headerValuesOf(headers, "Content-Type"); len(got) != 1 || got[0] != defaultRespondContentType {
		t.Fatalf("Content-Type=%v, want [%s]", got, defaultRespondContentType)
	}
	// 静态响应形态与上游无关——链内不得出现 reverse_proxy
	if strings.Contains(chain, "reverse_proxy") {
		t.Fatalf("static response chain must not contain reverse_proxy: %s", chain)
	}
}

// Given: 重定向响应码（301）与目标 URL
// When: 生成静态响应 handler
// Then: 必备 Location 头就位，且不携带响应体与 Content-Type
func TestStaticResponseHandler_redirectPresetsLocation(t *testing.T) {
	handler := staticResponseHandler(staticResponsePathRule(301, "https://example.com/new", "ignored", "text/plain"))
	if got := handler["status_code"]; got != 301 {
		t.Fatalf("status_code=%v, want 301", got)
	}
	headers := responseHeadersOf(t, handler)
	if got := headerValuesOf(headers, "Location"); len(got) != 1 || got[0] != "https://example.com/new" {
		t.Fatalf("Location=%v, want [https://example.com/new]", got)
	}
	if headerValuesOf(headers, "Content-Type") != nil {
		t.Fatalf("redirect must not set Content-Type: %v", headers)
	}
	if _, hasBody := handler["body"]; hasBody {
		t.Fatalf("redirect must not carry body: %#v", handler)
	}
}

// Given: 204 No Content
// When: 生成静态响应 handler
// Then: 无响应体、无 Content-Type（按标准不允许带体）
func TestStaticResponseHandler_noContentOmitsBody(t *testing.T) {
	handler := staticResponseHandler(staticResponsePathRule(204, "", "should-be-dropped", "text/html"))
	if _, hasBody := handler["body"]; hasBody {
		t.Fatalf("204 must not carry body: %#v", handler)
	}
	headers := responseHeadersOf(t, handler)
	if headerValuesOf(headers, "Content-Type") != nil {
		t.Fatalf("204 must not set Content-Type: %v", headers)
	}
}

// Given: 401 / 405 状态码
// When: 生成静态响应 handler
// Then: 按 RFC 9110 预设必备响应头（WWW-Authenticate / Allow）
func TestStaticResponseHandler_standardPresetHeaders(t *testing.T) {
	unauthorized := responseHeadersOf(t, staticResponseHandler(staticResponsePathRule(401, "", "", "")))
	if got := headerValuesOf(unauthorized, "WWW-Authenticate"); len(got) != 1 || !strings.HasPrefix(got[0], "Basic ") {
		t.Fatalf("401 WWW-Authenticate=%v, want Basic realm preset", got)
	}
	methodNotAllowed := responseHeadersOf(t, staticResponseHandler(staticResponsePathRule(405, "", "", "")))
	if got := headerValuesOf(methodNotAllowed, "Allow"); len(got) != 1 || !strings.Contains(got[0], "GET") {
		t.Fatalf("405 Allow=%v, want method list preset", got)
	}
}

// Given: 自定义内容类型
// When: 生成静态响应 handler
// Then: 用户值覆盖默认 Content-Type
func TestStaticResponseHandler_customContentTypeWins(t *testing.T) {
	handler := staticResponseHandler(staticResponsePathRule(200, "", `{"ok":true}`, "application/json"))
	headers := responseHeadersOf(t, handler)
	if got := headerValuesOf(headers, "Content-Type"); len(got) != 1 || got[0] != "application/json" {
		t.Fatalf("Content-Type=%v, want [application/json]", got)
	}
}

// Given: 响应体含花括号（JSON/模板）
// When: 生成静态响应 handler
// Then: 开括号被转义为 \{ ——Caddy replacer 据此按字面输出（闭合括号无需转义），
// 用户内容不会被当作占位符吞掉
func TestStaticResponseHandler_escapesPlaceholdersInBody(t *testing.T) {
	handler := staticResponseHandler(staticResponsePathRule(200, "", `{"uri":"{http.request.uri}"}`, "application/json"))
	body, _ := handler["body"].(string)
	if !strings.Contains(body, `\{http.request.uri}`) {
		t.Fatalf("body=%q, want escaped opening brace", body)
	}
	// 每个 { 都必须带转义前缀（数量相等即无遗漏）
	if strings.Count(body, "{") != strings.Count(body, `\{`) {
		t.Fatalf("body=%q, want every opening brace escaped", body)
	}
}

// Given: 同一规则内既有静态响应路径、又有反向代理路径
// When: 生成 HTTP 路由对象
// Then: 两种形态各自成链、互不影响（代理路径仍以 reverse_proxy 收尾）
func TestStaticResponseAndProxyPathRulesCoexist(t *testing.T) {
	rule := baseHTTPRule()
	rule.CustomRoutesEnabled = true
	rule.PathRules = []PathRuleConfig{
		{
			SortOrder: 1, MatchType: "exact", Path: "/healthz", Action: "respond",
			StatusCode: 200, ResponseBody: "ok", ContentType: "text/plain",
		},
		{
			SortOrder: 2, MatchType: "prefix", Path: "/api",
			Upstreams: []UpstreamConfig{{Host: "10.0.1.20", Port: 9090, Weight: 1, Enabled: true}},
		},
	}

	routes, _, err := generateHTTPRouteObjects(rule)
	if err != nil {
		t.Fatalf("generate HTTP route objects: %v", err)
	}
	staticRoute := upstreamPathRouteByID(t, routes, "rule-http_path_0")
	if got := lastHandlerOf(t, staticRoute)["handler"]; got != "static_response" {
		t.Fatalf("static path tail=%v, want static_response", got)
	}
	proxyRoute := upstreamPathRouteByID(t, routes, "rule-http_path_1")
	proxyIndex, _ := handlerPositions(t, proxyRoute)
	if proxyIndex < 0 {
		t.Fatalf("proxy path must keep reverse_proxy: %s", marshalChain(t, proxyRoute))
	}
}

// Given: 预置状态码集合与辅助判定
// When: 调用白名单/重定向/带体判定
// Then: 口径与前端 respondStatusGroups 一致
func TestRespondStatusPresetContract(t *testing.T) {
	for _, code := range []int{200, 204, 301, 302, 303, 307, 308, 400, 401, 403, 404, 405, 410, 429, 500, 502, 503, 504} {
		if !IsSupportedRespondStatus(code) {
			t.Fatalf("status %d must be supported", code)
		}
	}
	for _, code := range []int{0, 100, 205, 418, 501, 505, 999} {
		if IsSupportedRespondStatus(code) {
			t.Fatalf("status %d must NOT be supported", code)
		}
	}
	for _, code := range []int{301, 302, 303, 307, 308} {
		if !IsRedirectRespondStatus(code) {
			t.Fatalf("status %d must be a redirect", code)
		}
	}
	if IsRedirectRespondStatus(200) || IsRedirectRespondStatus(404) {
		t.Fatal("non-3xx must not be treated as redirect")
	}
	if respondBodyAllowed(204) || respondBodyAllowed(301) {
		t.Fatal("204/3xx must not allow body")
	}
	if !respondBodyAllowed(200) || !respondBodyAllowed(404) {
		t.Fatal("200/404 must allow body")
	}
}
