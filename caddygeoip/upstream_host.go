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

// UpstreamHostOverride 逐上游回源 Host 覆盖处理器（lb_upstream_host）。
// 要点：请求期惰性占位符，在 reverse_proxy 选中上游后按 hostport 查表下发；禁切回内建 map 方案。
// 详见 docs/fork-notes/caddygeoip-handler.md §2
type UpstreamHostOverride struct {
	// Hosts 上游 dial(host:port) → 回源 Host 映射；仅收录「有效回源 Host 非上游自身」的条目。
	// 详见 docs/fork-notes/caddygeoip-handler.md §3
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
		// 绝不回退客户端 Host——上游未配置回源 Host 时应以回源目标身份访问。
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
