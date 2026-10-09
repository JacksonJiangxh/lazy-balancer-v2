package caddygeoip

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/caddyserver/caddy/v2"
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
// Then: Host 回退 hostport、SNI 回退纯主机名（绝不产出空值）
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
