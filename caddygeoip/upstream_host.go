package caddygeoip

import (
	"net"
	"net/http"

	"github.com/caddyserver/caddy/v2"
	"github.com/caddyserver/caddy/v2/modules/caddyhttp"
)

func init() {
	caddy.RegisterModule(UpstreamHostOverride{})
}

// 占位符键（请求期由本处理器惰性注册；生成侧 internal/services/caddy.go
// 同步引用，改名须双侧同步）。
const (
	// upstreamHostPlaceholder 回源 Host：命中映射返回配置值，未命中回退上游
	// 自身 dial 地址（host:port）——用于 reverse_proxy headers 的 Host 头。
	upstreamHostPlaceholder = "lb.upstream_host"
	// upstreamSNIPlaceholder 回源 SNI：命中映射返回配置值（剥离端口），未命中
	// 回退上游纯主机名——用于 TLS transport 的 server_name（SNI 不得含端口）。
	upstreamSNIPlaceholder = "lb.upstream_sni"
)

// UpstreamHostOverride 逐上游回源 Host 覆盖处理器（http.handlers.lb_upstream_host）。
//
// 背景：Caddy 单个 reverse_proxy 的请求头操作是 handler 级配置——同一负载池的
// 所有上游共享一个 Host 值（静态串或 {http.reverse_proxy.upstream.hostport}
// 占位符），无法表达「同一规则内不同上游使用不同静态回源 Host」。本处理器在
// 请求期向 replacer 注册惰性占位符，求值时机恰为 reverse_proxy 选中上游之后
// （reverseproxy.go v2.11.6：先 repl.Set("http.reverse_proxy.upstream.hostport")
// 再应用 headers/transport 占位符），此时按选中的 hostport 查表下发对应回源
// Host——使「上游自定义 > 规则级 > 上游自身」三级回退在单一负载池内成立，
// 负载均衡/健康检查/重试语义不变。
//
// 稳定设计：零 Provision/零失败模式；未配置映射或 replacer 上下文缺失时纯
// 透传；未命中映射回退上游自身地址（绝不产出空 Host）；next 原样透传。
type UpstreamHostOverride struct {
	// Hosts 上游 dial（host:port，与 {http.reverse_proxy.upstream.hostport}
	// 输出同格式）→ 回源 Host 的映射；仅收录「有效回源 Host 非上游自身」的
	// 条目，未收录的上游由未命中兜底走自身地址（回退语义第三级）。
	Hosts map[string]string `json:"hosts,omitempty"`
}

// CaddyModule returns the caddy module information.
func (UpstreamHostOverride) CaddyModule() caddy.ModuleInfo {
	return caddy.ModuleInfo{
		ID:  "http.handlers.lb_upstream_host",
		New: func() caddy.Module { return new(UpstreamHostOverride) },
	}
}

// ServeHTTP 注册惰性占位符提供者后原样透传下游（reverse_proxy 之前执行）。
func (h *UpstreamHostOverride) ServeHTTP(w http.ResponseWriter, r *http.Request, next caddyhttp.Handler) error {
	if len(h.Hosts) == 0 {
		return next.ServeHTTP(w, r)
	}
	repl, ok := r.Context().Value(caddy.ReplacerCtxKey).(*caddy.Replacer)
	if !ok || repl == nil {
		return next.ServeHTTP(w, r)
	}
	hosts := h.Hosts
	repl.Map(caddy.ReplacerFunc(func(key string) (any, bool) {
		switch key {
		case upstreamHostPlaceholder, upstreamSNIPlaceholder:
		default:
			return nil, false
		}
		// 求值时机=上游选中之后（header/transport 占位符展开），此刻 hostport
		// 已由 reverse_proxy 写入 replacer；重试循环会刷新该值，逐次读取即最新。
		hostport, _ := repl.GetString("http.reverse_proxy.upstream.hostport")
		if host, hit := hosts[hostport]; hit && host != "" {
			if key == upstreamSNIPlaceholder {
				// SNI 不得含端口：配置值带端口时剥离（Host 头侧原样保留）。
				if hostOnly, _, err := net.SplitHostPort(host); err == nil {
					host = hostOnly
				}
			}
			return host, true
		}
		// 未命中（理论不可达：生成侧恒按启用上游全量收敛）：回退自身地址。
		if key == upstreamSNIPlaceholder {
			hostOnly, _ := repl.GetString("http.reverse_proxy.upstream.host")
			return hostOnly, true
		}
		return hostport, true
	}))
	return next.ServeHTTP(w, r)
}

// Interface guards(编译期契约,零运行时成本)。
var (
	_ caddyhttp.MiddlewareHandler = (*UpstreamHostOverride)(nil)
)
