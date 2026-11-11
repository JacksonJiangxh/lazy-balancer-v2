package caddygeoip

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/caddyserver/caddy/v2"
	"github.com/caddyserver/caddy/v2/modules/caddyhttp"
)

// stubNext 记录 next 是否被调用——本处理器必须原样透传下游。
type stubNext struct{ called bool }

func (s *stubNext) ServeHTTP(_ http.ResponseWriter, _ *http.Request) error {
	s.called = true
	return nil
}

// newUpstreamHostTestRequest 构造携带请求级 replacer 的测试请求（模拟 Caddy
// 请求链上下文；上游占位符由 reverse_proxy 在选中上游后写入）。
func newUpstreamHostTestRequest() (*http.Request, *caddy.Replacer, *stubNext) {
	repl := caddy.NewReplacer()
	ctx := context.WithValue(context.Background(), caddy.ReplacerCtxKey, repl)
	req := httptest.NewRequest(http.MethodGet, "http://example.test/", nil).WithContext(ctx)
	return req, repl, &stubNext{}
}

// Given: 选中上游命中映射
// When: 求值 {lb.upstream_host} / {lb.upstream_sni}
// Then: 返回该上游配置的回源 Host（SNI 同值，域名无端口）
func TestUpstreamHostOverride_mapsSelectedUpstream(t *testing.T) {
	req, repl, next := newUpstreamHostTestRequest()
	repl.Set("http.reverse_proxy.upstream.hostport", "10.0.0.1:8080")
	repl.Set("http.reverse_proxy.upstream.host", "10.0.0.1")
	h := &UpstreamHostOverride{Hosts: map[string]string{"10.0.0.1:8080": "origin.example.com"}}

	if err := h.ServeHTTP(httptest.NewRecorder(), req, next); err != nil {
		t.Fatalf("ServeHTTP: %v", err)
	}
	if !next.called {
		t.Fatal("next must be called (pure passthrough)")
	}
	if got, _ := repl.GetString(upstreamHostPlaceholder); got != "origin.example.com" {
		t.Fatalf("lb.upstream_host=%q; want origin.example.com", got)
	}
	if got, _ := repl.GetString(upstreamSNIPlaceholder); got != "origin.example.com" {
		t.Fatalf("lb.upstream_sni=%q; want origin.example.com", got)
	}
}

// Given: 映射未收录该上游（回退语义第三级）
// When: 求值两个占位符
// Then: Host 回退 hostport、SNI 回退纯主机名（绝不产出空值、绝不透传客户端 Host）
func TestUpstreamHostOverride_fallsBackToUpstreamItself(t *testing.T) {
	req, repl, next := newUpstreamHostTestRequest()
	repl.Set("http.reverse_proxy.upstream.hostport", "10.0.0.9:8080")
	repl.Set("http.reverse_proxy.upstream.host", "10.0.0.9")
	h := &UpstreamHostOverride{Hosts: map[string]string{"10.0.0.1:8080": "origin.example.com"}}

	if err := h.ServeHTTP(httptest.NewRecorder(), req, next); err != nil {
		t.Fatalf("ServeHTTP: %v", err)
	}
	if got, _ := repl.GetString(upstreamHostPlaceholder); got != "10.0.0.9:8080" {
		t.Fatalf("lb.upstream_host=%q; want 10.0.0.9:8080", got)
	}
	if got, _ := repl.GetString(upstreamSNIPlaceholder); got != "10.0.0.9" {
		t.Fatalf("lb.upstream_sni=%q; want 10.0.0.9", got)
	}
}

// Given: 客户端请求带自己的 Host（用户域名）+ 映射未命中该上游
// When: 求值 {lb.upstream_host}
// Then: 恒返回上游自身 hostport——**绝不透传客户端 Host**（H2/H4 钉测）
func TestUpstreamHostOverride_neverLeaksClientHost(t *testing.T) {
	repl := caddy.NewReplacer()
	ctx := context.WithValue(context.Background(), caddy.ReplacerCtxKey, repl)
	req := httptest.NewRequest(http.MethodGet, "http://user-facing.example.com/", nil).WithContext(ctx)
	repl.Set("http.request.host", "user-facing.example.com")
	repl.Set("http.request.hostport", "user-facing.example.com:443")
	repl.Set("http.reverse_proxy.upstream.hostport", "10.0.0.9:8080")
	repl.Set("http.reverse_proxy.upstream.host", "10.0.0.9")
	next := &stubNext{}
	h := &UpstreamHostOverride{Hosts: map[string]string{"10.0.0.1:8080": "origin.example.com"}}

	if err := h.ServeHTTP(httptest.NewRecorder(), req, next); err != nil {
		t.Fatalf("ServeHTTP: %v", err)
	}
	if got, _ := repl.GetString(upstreamHostPlaceholder); got != "10.0.0.9:8080" {
		t.Fatalf("lb.upstream_host=%q; want 10.0.0.9:8080（不得为客户端 Host）", got)
	}
	if got, _ := repl.GetString(upstreamSNIPlaceholder); got != "10.0.0.9" {
		t.Fatalf("lb.upstream_sni=%q; want 10.0.0.9（不得为客户端 Host）", got)
	}
}

// Given: 配置的回源 Host 带端口
// When: 求值 SNI 占位符
// Then: SNI 剥离端口（SNI 不得含端口），Host 头保留端口原样
func TestUpstreamHostOverride_sniStripsPort(t *testing.T) {
	req, repl, next := newUpstreamHostTestRequest()
	repl.Set("http.reverse_proxy.upstream.hostport", "10.0.0.1:8080")
	repl.Set("http.reverse_proxy.upstream.host", "10.0.0.1")
	h := &UpstreamHostOverride{Hosts: map[string]string{"10.0.0.1:8080": "origin.example.com:8443"}}

	if err := h.ServeHTTP(httptest.NewRecorder(), req, next); err != nil {
		t.Fatalf("ServeHTTP: %v", err)
	}
	if got, _ := repl.GetString(upstreamHostPlaceholder); got != "origin.example.com:8443" {
		t.Fatalf("lb.upstream_host=%q; want origin.example.com:8443", got)
	}
	if got, _ := repl.GetString(upstreamSNIPlaceholder); got != "origin.example.com" {
		t.Fatalf("lb.upstream_sni=%q; want origin.example.com (port stripped)", got)
	}
}

// Given: 空映射（理论上生成侧不会发射该处理器）
// When: ServeHTTP
// Then: 不注册占位符（查询 not found）且纯透传
func TestUpstreamHostOverride_emptyHostsRegistersNothing(t *testing.T) {
	req, repl, next := newUpstreamHostTestRequest()
	h := &UpstreamHostOverride{}

	if err := h.ServeHTTP(httptest.NewRecorder(), req, next); err != nil {
		t.Fatalf("ServeHTTP: %v", err)
	}
	if !next.called {
		t.Fatal("next must be called")
	}
	if _, found := repl.Get(upstreamHostPlaceholder); found {
		t.Fatal("placeholder must stay unregistered when hosts is empty")
	}
}

// Given: 请求上下文缺失 replacer（异常装配）
// When: ServeHTTP
// Then: 不 panic、纯透传（防御性稳定设计）
func TestUpstreamHostOverride_missingReplacerPassthrough(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet, "http://example.test/", nil)
	next := &stubNext{}
	h := &UpstreamHostOverride{Hosts: map[string]string{"10.0.0.1:8080": "origin.example.com"}}

	if err := h.ServeHTTP(httptest.NewRecorder(), req, next); err != nil {
		t.Fatalf("ServeHTTP: %v", err)
	}
	if !next.called {
		t.Fatal("next must be called without replacer context")
	}
}

// Given: 处理器注册后查询无关 key
// When: repl.Get 其它占位符
// Then: 本提供者不拦截（返回 not found，交后续提供者处理）
func TestUpstreamHostOverride_ignoresOtherKeys(t *testing.T) {
	req, repl, next := newUpstreamHostTestRequest()
	h := &UpstreamHostOverride{Hosts: map[string]string{"10.0.0.1:8080": "origin.example.com"}}

	if err := h.ServeHTTP(httptest.NewRecorder(), req, next); err != nil {
		t.Fatalf("ServeHTTP: %v", err)
	}
	if _, found := repl.Get("lb.unrelated"); found {
		t.Fatal("provider must ignore unrelated keys")
	}
}

// Given: 模块已注册
// When: 查询模块清单
// Then: http.handlers.lb_upstream_host 存在且可实例化（xcaddy --with 编入后
// 生成侧发射的 handler 才能被 Caddy 解析——V5 模块自洽的编译期锚点）
func TestUpstreamHostOverride_moduleRegistered(t *testing.T) {
	info, err := caddy.GetModule("http.handlers.lb_upstream_host")
	if err != nil {
		t.Fatalf("module http.handlers.lb_upstream_host must be registered: %v", err)
	}
	if _, ok := info.New().(*UpstreamHostOverride); !ok {
		t.Fatalf("module instance type=%T; want *UpstreamHostOverride", info.New())
	}
}

// ── 生产就绪硬证据：生成产物能被真实 Caddy 解码链加载 ──────────────────────

// Given: 生成侧发射的配置片段（取自真实生成产物的 lb_upstream_host 段，混合态）
// When: 走 **Caddy 真实的 route 加载链**——`Route` 反序列化 HandlersRaw →
// `route.Provision(caddy.Context, *caddyhttp.Metrics)` → `ctx.LoadModule` 按
// `"handler"` 键在模块表里分派
// Then: 解析成本模块实例且 Hosts 与生成侧逐字一致。这条链就是 caddy load /
// validate 走的路，因此本用例失败 == 线上配置必然加载失败（比 `caddy validate`
// 更贴近根因，且不依赖外部二进制）。
func TestUpstreamHostOverride_routeDecodesGeneratedJSON(t *testing.T) {
	routeJSON := `{"handle":[{"handler":"lb_upstream_host","hosts":{"10.0.0.1:8080":"a.internal","10.0.0.2:8080":"rule.example.com"}}]}`
	var route caddyhttp.Route
	if err := json.Unmarshal([]byte(routeJSON), &route); err != nil {
		t.Fatalf("Route 解码失败: %v", err)
	}
	if len(route.HandlersRaw) != 1 {
		t.Fatalf("HandlersRaw len=%d, want 1", len(route.HandlersRaw))
	}

	ctx, cancel := caddy.NewContext(caddy.Context{Context: t.Context()})
	defer cancel()
	if err := route.Provision(ctx, new(caddyhttp.Metrics)); err != nil {
		t.Fatalf("Provision 失败（caddy load 会同样失败）: %v", err)
	}
	if len(route.Handlers) != 1 {
		t.Fatalf("Handlers len=%d, want 1", len(route.Handlers))
	}
	got, ok := route.Handlers[0].(*UpstreamHostOverride)
	if !ok {
		t.Fatalf("handler 类型=%T, want *UpstreamHostOverride", route.Handlers[0])
	}
	if len(got.Hosts) != 2 || got.Hosts["10.0.0.1:8080"] != "a.internal" || got.Hosts["10.0.0.2:8080"] != "rule.example.com" {
		t.Fatalf("Hosts=%v，与生成侧不符", got.Hosts)
	}
}
