// Package caddychain provides a Caddy HTTP handler module implementing
// 「链式回退 + 竞速」(chain fallback with hedged racing) proxying.
//
// 上游按优先级（生成侧已按权重降序排好）组成回退链：
//   - 请求 0 发出后等待 race_interval_ms 仍无有效响应（响应头），
//     则向下一优先级上游并行发出请求 1，两路竞速；依次类推；
//   - 某路返回网络错误或 status>=400 时，不等竞速间隔，立即发出下一路；
//   - 最先返回有效响应（status<400）的一路胜出，响应流式直达客户端，
//     其余在途请求被取消截断；
//   - 单一路径超过 request_timeout_ms 未收到响应头即取消该路径（兜底截断）；
//     响应头到达后 body 流不再受此超时约束（护住大文件/SSE/长连接）。
//
// 收尾：全部车道落定为 bad → 透传最先到达的 bad 响应；全部车道错误 →
// 502（全部为超时则 504）。
//
// 配置由面板 internal/services/caddy.go 在 rule.Strategy == "chain_fallback"
// 时生成（JSON 键 "handler": "chain_proxy"），与 reverse_proxy 互斥发射。
package caddychain

import (
	"crypto/tls"
	"fmt"
	"net"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/caddyserver/caddy/v2"
	"github.com/caddyserver/caddy/v2/modules/caddyhttp"
	"go.uber.org/zap"
)

func init() {
	caddy.RegisterModule(ChainProxy{})
}

// ChainUpstream 描述回退链上的一个上游。Dial 为 host:port（host 部分可含
// IPv6 字面量，net.Dialer 直收）；Host 为该上游的最终回源 Host（生成侧已按
// 「上游 host_header > 规则级 host_header > 空=用 dial 地址」三级回退解析）；
// Scheme 为回源协议（http/https，空=http）。
type ChainUpstream struct {
	Dial   string `json:"dial,omitempty"`
	Scheme string `json:"scheme,omitempty"`
	Host   string `json:"host,omitempty"`
}

// Default* 与面板写侧默认值同口径（rules.go CreateRule / caddy.go 渲染兜底）。
// 预算公式（全挂兜底最坏情形）：总耗时 ≈ (N−1)×RaceInterval + RequestTimeout，
// 按 N=6 封顶 + 浏览器 60s 等待约束设计：5×3000+30000=45s < 60s（15s 余量），
// N<6 自动收敛（2 路最坏 33s）。RaceInterval=3s 兼顾竞速收益与非幂等请求
//（POST）重复执行窗口；RequestTimeout=30s 为单路无响应头的判死阈值。
const (
	DefaultRaceIntervalMS   = 3000
	DefaultRequestTimeoutMS = 30000
	DefaultDialTimeoutMS    = 5000
	// DefaultBodyReplayLimitBytes 与参考项目 maxRetryBodyBytes（5MB）对齐：
	// 竞速要求请求体可重放，超限退化为仅车道 0 直通（不竞速不重放）。
	DefaultBodyReplayLimitBytes = 5 * 1024 * 1024
)

// ChainProxy is the Caddy module. JSON key: "chain_proxy".
type ChainProxy struct {
	// Upstreams 按优先级降序排列（生成侧已按权重排序，模块不重复处理）。
	Upstreams []ChainUpstream `json:"upstreams,omitempty"`

	// RaceIntervalMS 竞速间隔：距上一次发车道已过该时长仍无胜者则发出
	// 下一车道。<=0 时按 Default 兜底（Provision）。
	RaceIntervalMS int `json:"race_interval_ms,omitempty"`

	// RequestTimeoutMS 单车道兜底截断：超过该时长未收到响应头即取消该车道。
	// 仅约束响应头等待；body 流不受约束。<=0 时按 Default 兜底（Provision）。
	RequestTimeoutMS int `json:"request_timeout_ms,omitempty"`

	// DialTimeoutMS 建连超时（含隧道路径）。<=0 时按 Default 兜底。
	DialTimeoutMS int `json:"dial_timeout_ms,omitempty"`

	// BodyReplayLimitBytes 请求体重放上限；超限退化为仅车道 0 直通。
	// <=0 时按 Default 兜底（Provision）。
	BodyReplayLimitBytes int `json:"body_replay_limit_bytes,omitempty"`

	// StripRequestHeaders 入口无条件剥离的请求头清单（面板注入的 X-LB-*
	// 进程内控制头，与 reverse_proxy 的 headers.request.delete 同源）。
	StripRequestHeaders []string `json:"strip_request_headers,omitempty"`

	baseTransport *http.Transport
	// tlsCache 按 SNI 派生 transport 的缓存（指针承载，避免模块值拷贝带锁——
	// CaddyModule 值接收者约定）。惰性初始化，测试可绕过 Provision。
	tlsCache *tlsTransportCache
	logger   *zap.Logger
}

// tlsTransportCache HTTPS 上游回源 Host 与 dial 主机不一致时，按 SNI 缓存
// 派生 transport（ServerName 定制），连接池按 SNI 隔离。
type tlsTransportCache struct {
	mu         sync.Mutex
	transports map[string]*http.Transport
}

// CaddyModule returns the Caddy module information.
func (ChainProxy) CaddyModule() caddy.ModuleInfo {
	return caddy.ModuleInfo{
		ID:  "http.handlers.chain_proxy",
		New: func() caddy.Module { return new(ChainProxy) },
	}
}

// Provision builds the shared transports and applies defaults.
func (h *ChainProxy) Provision(ctx caddy.Context) error {
	if h.RaceIntervalMS <= 0 {
		h.RaceIntervalMS = DefaultRaceIntervalMS
	}
	if h.RequestTimeoutMS <= 0 {
		h.RequestTimeoutMS = DefaultRequestTimeoutMS
	}
	if h.DialTimeoutMS <= 0 {
		h.DialTimeoutMS = DefaultDialTimeoutMS
	}
	if h.BodyReplayLimitBytes <= 0 {
		h.BodyReplayLimitBytes = DefaultBodyReplayLimitBytes
	}
	dialTimeout := time.Duration(h.DialTimeoutMS) * time.Millisecond
	// insecure_skip_verify 与面板 reverse_proxy transport 生成口径一致
	//（caddy.go：上游 HTTPS 恒 insecure_skip_verify=true，回源证书校验由
	// 面板定位（内网/自签）豁免）。
	h.baseTransport = &http.Transport{
		DialContext:           (&net.Dialer{Timeout: dialTimeout, KeepAlive: 30 * time.Second}).DialContext,
		MaxIdleConns:          100,
		MaxIdleConnsPerHost:   10,
		IdleConnTimeout:       90 * time.Second,
		TLSHandshakeTimeout:   10 * time.Second,
		ExpectContinueTimeout: time.Second,
		TLSClientConfig:       &tls.Config{InsecureSkipVerify: true}, //nolint:gosec
		ForceAttemptHTTP2:     false,
	}
	h.tlsCache = &tlsTransportCache{transports: make(map[string]*http.Transport)}
	h.logger = ctx.Logger()
	return nil
}

// Validate ensures the configuration is usable.
func (h *ChainProxy) Validate() error {
	if len(h.Upstreams) == 0 {
		return fmt.Errorf("chain_proxy: 至少需要一个上游")
	}
	for i, up := range h.Upstreams {
		if up.Dial == "" {
			return fmt.Errorf("chain_proxy: 上游 %d 缺少 dial 地址", i)
		}
		if up.Scheme != "" && up.Scheme != "http" && up.Scheme != "https" {
			return fmt.Errorf("chain_proxy: 上游 %d 的 scheme 仅支持 http/https", i)
		}
	}
	return nil
}

// Cleanup closes idle connections held by the transports of the outgoing
// config（重载窗口内新配置的 handler 持有自己的 transport 实例，互不影响）。
func (h *ChainProxy) Cleanup() error {
	if h.baseTransport != nil {
		h.baseTransport.CloseIdleConnections()
	}
	if h.tlsCache != nil {
		h.tlsCache.mu.Lock()
		for _, t := range h.tlsCache.transports {
			t.CloseIdleConnections()
		}
		h.tlsCache.mu.Unlock()
	}
	return nil
}

// log returns a non-nil logger (tests construct handlers without Provision).
func (h *ChainProxy) log() *zap.Logger {
	if h.logger == nil {
		return zap.NewNop()
	}
	return h.logger
}

// transportFor returns the transport for the upstream. HTTPS 上游且回源 Host
// 与 dial 主机不一致时，按 SNI 缓存派生 transport（ServerName 定制），连接池
// 按 SNI 隔离；其余一律共享 base transport。
func (h *ChainProxy) transportFor(up ChainUpstream) *http.Transport {
	if up.Scheme != "https" {
		return h.baseTransport
	}
	sni := sniOf(up)
	if sni == "" || strings.EqualFold(sni, hostnameOf(up.Dial)) {
		return h.baseTransport
	}
	if h.tlsCache == nil {
		h.tlsCache = &tlsTransportCache{transports: make(map[string]*http.Transport)}
	}
	h.tlsCache.mu.Lock()
	defer h.tlsCache.mu.Unlock()
	if t, ok := h.tlsCache.transports[sni]; ok {
		return t
	}
	t := h.baseTransport.Clone()
	cfg := t.TLSClientConfig.Clone()
	cfg.ServerName = sni
	t.TLSClientConfig = cfg
	h.tlsCache.transports[sni] = t
	return t
}

// sniOf resolves the TLS server name from the upstream's effective Host（剥
// 端口；SNI 不得含端口），与面板 stripPortForSNI 同口径。Host 为空时返回空串
// （交给 transport 以 dial 主机兜底）。
func sniOf(up ChainUpstream) string {
	return hostOnly(up.Host)
}

// hostOnly strips the port from a host[:port] value; bare IPv6 / no-port
// forms pass through unchanged.
func hostOnly(hostPort string) string {
	if hostPort == "" {
		return ""
	}
	if h, _, err := net.SplitHostPort(hostPort); err == nil {
		return h
	}
	return hostPort
}

// hostnameOf strips the port from a dial address (host:port / [v6]:port).
func hostnameOf(dial string) string {
	return hostOnly(dial)
}

// isUpgradeRequest reports whether the request carries a protocol upgrade
// (websocket 等)——竞速路径会剥离 Upgrade/Connection 头，升级请求走隧道。
func isUpgradeRequest(r *http.Request) bool {
	if r.Header.Get("Upgrade") == "" {
		return false
	}
	for _, v := range r.Header.Values("Connection") {
		if strings.Contains(strings.ToLower(v), "upgrade") {
			return true
		}
	}
	return false
}

// ServeHTTP implements caddyhttp.MiddlewareHandler. 终端处理器：本 handler
// 要么成功写出上游响应，要么自行写出错误响应，恒返回 nil（不进错误路由）。
func (h *ChainProxy) ServeHTTP(w http.ResponseWriter, r *http.Request, _ caddyhttp.Handler) error {
	if len(h.Upstreams) == 0 {
		chainWriteError(w, http.StatusBadGateway, "chain_proxy: no upstreams configured")
		return nil
	}
	// X-LB-* 进程内控制头剥离（与 reverse_proxy headers.request.delete 同源；
	// 先剥后用，防客户端伪造同名头直达后端）。
	for _, name := range h.StripRequestHeaders {
		r.Header.Del(name)
	}
	if isUpgradeRequest(r) {
		// 升级请求（websocket）不竞速：按链序建连隧道，dial 失败换下一上游。
		return h.serveTunnel(w, r)
	}
	body, overflow, err := bufferBody(r, h.BodyReplayLimitBytes)
	if err != nil {
		h.log().Warn("chain_proxy: 读取请求体失败", zap.Error(err))
		chainWriteError(w, http.StatusBadRequest, "chain_proxy: failed to read request body")
		return nil
	}
	if overflow || len(h.Upstreams) == 1 {
		// 请求体超重放上限（仅车道 0 直通，前缀续流）或链上仅一个上游
		//（退化直通）。
		return h.serveSingleLane(w, r, body, overflow)
	}
	return h.serveRace(w, r, body)
}
