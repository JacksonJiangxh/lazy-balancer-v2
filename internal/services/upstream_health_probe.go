package services

// 逐上游健康检查路径（JJC-20261121-001）渲染辅助与面板侧聚合探针注册表。
//
// 背景（Caddy v2.11.7 官方能力实证，raw 源码逐字核实）：
//   - reverse_proxy 单 handler 的主动探测 uri 是 handler 级（healthchecks.go
//     doActiveHealthCheck：u.Path 恒取 HealthChecks.Active.uri.Path），Upstream
//     结构体无逐上游路径字段，占位符不可作用于 path（headers/body 才经 replacer）。
//   - 存在官方 health_upstream 中间服务模式（ActiveHealthChecks.Upstream）：非空时
//     probe URL Host 恒取该地址（dialInfoUpstream 整体替换），探测结果仍按原
//     upstream 记账（per-proxy-handler 状态机/摘除恢复不变）；headers 经
//     replacer 展开，{http.reverse_proxy.active.target_upstream} 在探测路径
//     Set 为逐上游 dial 地址（networkAddr）。
//   - transport 带 TLS 时探测 scheme 经 OverrideHealthCheckScheme 强制升 https，
//     命中 tls.except_ports 的探测端口豁免——本引擎面板口据此豁免。
//
// 因此路径分歧形态的渲染为：health_upstream → 127.0.0.1:<面板口>，uri 携带
// 规则 ID，X-LB-Probe-Target 头携带逐上游 dial 地址；面板聚合端点按规则 ID + 目标
// 头定位该上游的有效探测路径，真实探测并回 2xx/5xx——探测状态机全部保留 Caddy
// 原生实现，数据面零改动。路径全同规则维持原生渲染逐字节不变。
//
// 注册表生命周期：渲染前快照+清空收集器 → 渲染中经 registerPerUpstreamProbeRule
// 累积 → 成功出口 commitPerUpstreamProbeRegistry 原子替换；渲染失败出口不动
// 注册表（运行配置未变，端点寻址面必须与运行配置一致）。

import (
	"context"
	"crypto/tls"
	"net"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"
)

// PanelProbePathPrefix 面板聚合探针端点路径前缀（免认证回环面，仅 Caddy 探测消费）。
const PanelProbePathPrefix = "/lb-hc-probe/"

// PanelProbeGinPath gin 路由树形态（middleware 挂载用）：通配段承接规则 ID。
const PanelProbeGinPath = "/lb-hc-probe/:rule_id"

// perUpstreamProbeURI 渲染产物中 health_checks.active.uri 的值：
// 面板聚合探针端点 + 规则 ID（Caddy 探测 URL = health_upstream + uri）。
func perUpstreamProbeURI(ruleID string) string {
	return PanelProbePathPrefix + ruleID
}

// effectiveUpstreamHealthPaths 计算启用上游的逐上游有效探测路径
// （逐上游 > 规则级 > "/"；TrimSpace 归一——与 origin_domain 三级回退同风格）。
func effectiveUpstreamHealthPaths(rule SingleRuleConfig, enabledUpstreams []UpstreamConfig) []string {
	fallback := strings.TrimSpace(rule.HealthCheckPath)
	if fallback == "" {
		fallback = "/"
	}
	paths := make([]string, len(enabledUpstreams))
	for i, u := range enabledUpstreams {
		p := strings.TrimSpace(u.HealthCheckPath)
		if p == "" {
			p = fallback
		}
		paths[i] = p
	}
	return paths
}

// healthProbePathsDiverge 判定启用上游的有效探测路径是否分歧（与规则级基准任一
// 不同即分歧）。全同（含全部留空=跟随规则级）返回 false——原生渲染逐字节不变。
func healthProbePathsDiverge(basePath string, probePaths []string) bool {
	for _, p := range probePaths {
		if p != basePath {
			return true
		}
	}
	return false
}

// probeRuleDef 一条分歧规则的逐上游探测面（渲染期登记、端点消费）。
type probeRuleDef struct {
	ruleID    string
	interval  int               // 秒（healthCheckCore 语义）
	timeout   int               // 秒
	probeHost string            // 健康检查域名优先于规则级后端域名（与原生 probe Host 同源）
	targets   map[string]string // dial 地址 → 有效探测路径
	schemes   map[string]bool   // dial 地址 → 上游是否 https（探测 scheme 判定）
}

// probeEngine 聚合探针注册表：活跃面（endpoint 寻址）+ 渲染期收集器。
type probeEngine struct {
	mu        sync.RWMutex
	rules     map[string]*probeRuleDef // 活跃注册表（与运行配置一致的寻址面）
	collected []*probeRuleDef          // 渲染期收集器（本渲染累积）
}

var probeEngineSingleton = &probeEngine{
	rules: make(map[string]*probeRuleDef),
}

// perUpstreamProbeRegistrySnapshot 渲染前快照活跃注册表（失败出口还原用）。
func perUpstreamProbeRegistrySnapshot() []*probeRuleDef {
	engine := probeEngineSingleton
	engine.mu.RLock()
	defer engine.mu.RUnlock()
	out := make([]*probeRuleDef, 0, len(engine.rules))
	for _, def := range engine.rules {
		out = append(out, def)
	}
	return out
}

// resetPerUpstreamProbeCollector 清空渲染期收集器。
func resetPerUpstreamProbeCollector() {
	engine := probeEngineSingleton
	engine.mu.Lock()
	defer engine.mu.Unlock()
	engine.collected = nil
}

// commitPerUpstreamProbeRegistry 渲染成功出口：收集器原子替换活跃注册表。
func commitPerUpstreamProbeRegistry() {
	engine := probeEngineSingleton
	engine.mu.Lock()
	defer engine.mu.Unlock()
	rebuilt := make(map[string]*probeRuleDef, len(engine.collected))
	for _, def := range engine.collected {
		rebuilt[def.ruleID] = def
	}
	engine.rules = rebuilt
	engine.collected = nil
}

// restorePerUpstreamProbeRegistry 渲染失败出口还原活跃注册表（generationFailure
// 不调用——运行配置未变时端点寻址面保持一致；测试/显式回滚入口使用）。
func restorePerUpstreamProbeRegistry(snapshot []*probeRuleDef) {
	engine := probeEngineSingleton
	engine.mu.Lock()
	defer engine.mu.Unlock()
	rebuilt := make(map[string]*probeRuleDef, len(snapshot))
	for _, def := range snapshot {
		rebuilt[def.ruleID] = def
	}
	engine.rules = rebuilt
	engine.collected = nil
}

// registerPerUpstreamProbeRule 渲染期登记单条分歧规则（buildHTTPHandleChain 内
// probeDivergent 分支调用；幂等——同轮渲染同规则单次装配）。
func registerPerUpstreamProbeRule(def *probeRuleDef) {
	engine := probeEngineSingleton
	engine.mu.Lock()
	defer engine.mu.Unlock()
	engine.collected = append(engine.collected, def)
}

// perUpstreamProbeDef 按规则 ID 查活跃注册表（端点消费）。
func perUpstreamProbeDef(ruleID string) (*probeRuleDef, bool) {
	engine := probeEngineSingleton
	engine.mu.RLock()
	defer engine.mu.RUnlock()
	def, ok := engine.rules[ruleID]
	return def, ok
}

// buildProbeRuleDef 渲染期装配单条分歧规则定义（纯函数，登记与测试共用）。
func buildProbeRuleDef(rule SingleRuleConfig, enabledUpstreams []UpstreamConfig, probePaths []string, hc healthCheckValues) *probeRuleDef {
	probeHost := strings.TrimSpace(rule.HealthCheckHost)
	if probeHost == "" {
		probeHost = strings.TrimSpace(rule.HostHeader)
	}
	def := &probeRuleDef{
		ruleID:    rule.CaddyID,
		interval:  hc.interval,
		timeout:   hc.timeout,
		probeHost: probeHost,
		targets:   make(map[string]string, len(enabledUpstreams)),
		schemes:   make(map[string]bool, len(enabledUpstreams)),
	}
	for i, u := range enabledUpstreams {
		dial := joinUpstreamAddress(u.Host, u.Port)
		def.targets[dial] = probePaths[i]
		def.schemes[dial] = u.Protocol == "https"
	}
	return def
}

// HandlePanelProbe 聚合探针端点：GET/HEAD /lb-hc-probe/<ruleID>。
// X-LB-Probe-Target（Caddy 展开的逐上游 dial 地址）→ 该上游有效路径真实探测
// → 200（2xx 健康）/ 502（失败）。仅回环来源放行（Caddy 与面板同容器，探测源
// 恒 127.0.0.1——外部面不可用此端点扰动探测状态）。
func HandlePanelProbe(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet && r.Method != http.MethodHead {
		w.WriteHeader(http.StatusMethodNotAllowed)
		return
	}
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		host = r.RemoteAddr
	}
	if host != "127.0.0.1" && host != "::1" {
		http.Error(w, "forbidden", http.StatusForbidden)
		return
	}
	ruleID := strings.TrimPrefix(r.URL.Path, PanelProbePathPrefix)
	if ruleID == "" || strings.Contains(ruleID, "/") {
		http.NotFound(w, r)
		return
	}
	target := strings.TrimSpace(r.Header.Get("X-LB-Probe-Target"))
	if target == "" {
		http.Error(w, "missing probe target", http.StatusBadRequest)
		return
	}
	def, ok := perUpstreamProbeDef(ruleID)
	if !ok {
		http.NotFound(w, r)
		return
	}
	path, ok := def.targets[target]
	if !ok {
		// 目标不在本规则登记面（渲染漂移/伪造头）：失败语义（Caddy 对该
		// upstream 记失败——渲染漂移会被下一次成功渲染纠偏；头值是地址而非
		// 路径面文本，限定字符集，注入面天然收口）。
		w.WriteHeader(http.StatusBadGateway)
		return
	}
	if probeUpstreamHealth(def, target, path, r.Context()) {
		w.WriteHeader(http.StatusOK)
		return
	}
	w.WriteHeader(http.StatusBadGateway)
}

// probeUpstreamHealth 单目标真实探测：scheme=上游协议（http/https）；Host=
// 健康检查域名三级回退（与原生 probe Host 同源）；2xx=健康。
// 探测 TLS 跳过证书校验（与数据面 insecure_skip_verify 渲染同语义——自签
// 证书后端是本面板常见形态，探测不得比数据面更严）。
func probeUpstreamHealth(def *probeRuleDef, target, path string, parent context.Context) bool {
	scheme := "http"
	if def.schemes[target] {
		scheme = "https"
	}
	u := &url.URL{Scheme: scheme, Host: target, Path: path}
	timeout := time.Duration(def.timeout) * time.Second
	if timeout <= 0 {
		timeout = 5 * time.Second
	}
	ctx, cancel := context.WithTimeout(parent, timeout)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u.String(), nil)
	if err != nil {
		return false
	}
	if def.probeHost != "" {
		req.Host = def.probeHost
	}
	req.Header.Set("User-Agent", "lazy-balancer-probe")
	resp, err := insecureProbeClient.Do(req)
	if err != nil {
		return false
	}
	defer resp.Body.Close()
	return resp.StatusCode >= 200 && resp.StatusCode < 300
}

// insecureProbeClient 探测共享 client：TLS 跳过校验、按规则 timeout 走请求级
// ctx、client 级兜底超时防悬挂；探测连接池与数据面隔离。
var insecureProbeClient = &http.Client{
	Timeout: 30 * time.Second,
	Transport: &http.Transport{
		TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
		MaxIdleConns:    8,
		IdleConnTimeout: 30 * time.Second,
	},
}
