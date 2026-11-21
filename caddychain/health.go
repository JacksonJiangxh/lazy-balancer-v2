package caddychain

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"time"

	"go.uber.org/zap"
)

// 主动健康检查（HC）缺省值：与 uniform 原生 HC 对齐表同值（方案 §三.2）。
const (
	DefaultHCIntervalMS   = 30000
	DefaultHCTimeoutMS    = 5000
	DefaultHCPath         = "/"
	DefaultHCHealthyLag   = 2
	DefaultHCUnhealthyLag = 3
	// hcProbeUA 探测请求 UA 标识（日志与上游侧可辨识）。
	hcProbeUA = "chain_proxy-health-check"
	// hcBodyProbeLimitBytes 期望响应体子串检查的最大读取量。
	hcBodyProbeLimitBytes = 8 * 1024
)

// ChainHealthCheck 主动健康检查配置（chain_proxy 的 health_check 键）。
// nil = 不探测 = 既有行为零变化。
type ChainHealthCheck struct {
	// IntervalMS 探测间隔。<=0 按默认 30s 兜底。
	IntervalMS int `json:"interval_ms,omitempty"`
	// TimeoutMS 单次探测超时。<=0 按默认 5s 兜底。
	TimeoutMS int `json:"timeout_ms,omitempty"`
	// ExpectStatus 期望状态：单值整数（如 "200"）或闭区间串（如 "200-299"）。
	// 缺省 "200-299" 即 2xx 区间；含 "-" 按闭区间解析，min>max 拒绝（Validate）。
	ExpectStatus string `json:"expect_status,omitempty"`
	// Path 探测路径，缺省 "/"。
	Path string `json:"path,omitempty"`
	// HealthyLag 连续成功该次数后重新入池。<=0 按默认 2 兜底。
	HealthyLag int `json:"healthy_lag,omitempty"`
	// UnhealthyLag 连续失败该次数后摘除。<=0 按默认 3 兜底。
	UnhealthyLag int `json:"unhealthy_lag,omitempty"`
	// Body 期望响应体子串；缺省不查。
	Body string `json:"body,omitempty"`
}

// parseExpectStatus 解析 expect_status：返回 [low, high] 闭区间。
// 单一语法：单值整数或闭区间串（min>max 拒绝）。
func parseExpectStatus(s string) (low, high int, err error) {
	s = strings.TrimSpace(s)
	if s == "" {
		return 200, 299, nil
	}
	if strings.Contains(s, "-") {
		parts := strings.SplitN(s, "-", 2)
		low, err = strconv.Atoi(strings.TrimSpace(parts[0]))
		if err != nil {
			return 0, 0, fmt.Errorf("health_check: expect_status 区间下界非法: %q", s)
		}
		high, err = strconv.Atoi(strings.TrimSpace(parts[1]))
		if err != nil {
			return 0, 0, fmt.Errorf("health_check: expect_status 区间上界非法: %q", s)
		}
		if low > high {
			return 0, 0, fmt.Errorf("health_check: expect_status 区间下界大于上界: %q", s)
		}
		return low, high, nil
	}
	low, err = strconv.Atoi(s)
	if err != nil {
		return 0, 0, fmt.Errorf("health_check: expect_status 仅支持单值整数或闭区间串: %q", s)
	}
	return low, low, nil
}

// laneHealthState 单车道健康状态：healthy/unhealthy 两态 + 连续成功/失败计数。
type laneHealthState struct {
	healthy  bool
	succRuns int
	failRuns int
}

// healthMonitor 主动健康检查子系统：调度 goroutine（单 tick）+ 逐车道探测器
// （复用 transportFor——SNI 派生/连接池与数据面同源）+ 逐车道状态机
// （互斥锁保护）。初始态全 healthy（先放行后探测收敛）。
type healthMonitor struct {
	h    *ChainProxy
	cfg  *ChainHealthCheck
	low  int // expect 闭区间下界
	high int // expect 闭区间上界
	// path 规则级探测路径（兜底源：车道未配置 health_check_path 时消费；
	// newHealthMonitor 归一含前导 / 补齐）。逐车道覆盖面见 paths。
	path   string
	paths  []string // 逐车道有效探测路径（JJC-20261121-001）：车道覆盖>规则级兜底；与 Upstreams 同序同长

	mu     sync.Mutex
	states []laneHealthState

	stop chan struct{}
	done chan struct{}
}

// newHealthMonitor 装配并启动监控（含缺省值归一与 expect 解析）。
func newHealthMonitor(h *ChainProxy) (*healthMonitor, error) {
	cfg := h.HealthCheck
	low, high, err := parseExpectStatus(cfg.ExpectStatus)
	if err != nil {
		return nil, err
	}
	m := &healthMonitor{
		h:    h,
		cfg:  cfg,
		low:  low,
		high: high,
		stop: make(chan struct{}),
		done: make(chan struct{}),
	}
	if cfg.IntervalMS <= 0 {
		cfg.IntervalMS = DefaultHCIntervalMS
	}
	if cfg.TimeoutMS <= 0 {
		cfg.TimeoutMS = DefaultHCTimeoutMS
	}
	m.path = cfg.Path
	if m.path == "" {
		m.path = DefaultHCPath
	}
	if !strings.HasPrefix(m.path, "/") {
		m.path = "/" + m.path
	}
	// 逐车道探测路径解析（JJC-20261121-001）：车道 HealthCheckPath 非空优先
	//（独立归一——前导 / 补齐），空则回退规则级归一结果（m.path）。
	m.paths = make([]string, len(h.Upstreams))
	for i, up := range h.Upstreams {
		p := strings.TrimSpace(up.HealthCheckPath)
		if p == "" {
			p = m.path
		}
		if !strings.HasPrefix(p, "/") {
			p = "/" + p
		}
		m.paths[i] = p
	}
	if cfg.HealthyLag <= 0 {
		cfg.HealthyLag = DefaultHCHealthyLag
	}
	if cfg.UnhealthyLag <= 0 {
		cfg.UnhealthyLag = DefaultHCUnhealthyLag
	}
	m.states = make([]laneHealthState, len(h.Upstreams))
	for i := range m.states {
		m.states[i].healthy = true // 初始态全 healthy（裁决 3）
	}
	return m, nil
}

// start 启动调度 goroutine。
func (m *healthMonitor) start() {
	go m.run()
}

// run 调度主循环：interval 逐车道对齐探测节奏；stop 后先等在飞探测落定
// （probeAll 内 wg.Wait）再关闭 done 放行 Cleanup。
func (m *healthMonitor) run() {
	defer close(m.done)
	ticker := time.NewTicker(time.Duration(m.cfg.IntervalMS) * time.Millisecond)
	defer ticker.Stop()
	for {
		select {
		case <-m.stop:
			return
		case <-ticker.C:
			m.probeAll()
		}
	}
}

// probeAll 逐车道并发探测并等待全部落定（Cleanup 先等后放的执行体）。
func (m *healthMonitor) probeAll() {
	var wg sync.WaitGroup
	for i := range m.h.Upstreams {
		wg.Add(1)
		go func(idx int) {
			defer wg.Done()
			m.record(idx, m.probe(idx))
		}(i)
	}
	wg.Wait()
}

// probe 单车道探测：scheme=车道 Scheme（空=http）；Host=回源 Host 单源
// （上游 host_header > 规则级 > dial 的三级回退结果，与数据面严格一致）；
// path=逐车道有效探测路径（车道 health_check_path > 规则级 Path 兜底，
// JJC-20261121-001）；复用 transportFor（SNI 派生与连接池与数据面同源）。
func (m *healthMonitor) probe(idx int) bool {
	up := m.h.Upstreams[idx]
	scheme := up.Scheme
	if scheme == "" {
		scheme = "http"
	}
	host := up.Host
	if host == "" {
		host = up.Dial
	}
	u := &url.URL{Scheme: scheme, Host: up.Dial, Path: m.paths[idx]}
	timeout := time.Duration(m.cfg.TimeoutMS) * time.Millisecond
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u.String(), nil)
	if err != nil {
		return false
	}
	req.Host = host
	req.Header.Set("User-Agent", hcProbeUA)
	resp, err := m.h.transportFor(up).RoundTrip(req)
	if err != nil {
		return false
	}
	defer resp.Body.Close()
	if resp.StatusCode < m.low || resp.StatusCode > m.high {
		return false
	}
	if m.cfg.Body != "" {
		b, _ := io.ReadAll(io.LimitReader(resp.Body, hcBodyProbeLimitBytes))
		if !strings.Contains(string(b), m.cfg.Body) {
			return false
		}
	}
	return true
}

// record 状态机转移：连续成功/失败计数达阈值翻转（lag 阈值语义）。
func (m *healthMonitor) record(idx int, ok bool) {
	m.mu.Lock()
	defer m.mu.Unlock()
	st := &m.states[idx]
	if ok {
		st.succRuns++
		st.failRuns = 0
		if !st.healthy && st.succRuns >= m.cfg.HealthyLag {
			st.healthy = true
			st.succRuns = 0
		}
		return
	}
	st.failRuns++
	st.succRuns = 0
	if st.healthy && st.failRuns >= m.cfg.UnhealthyLag {
		st.healthy = false
		st.failRuns = 0
	}
}

// healthy 单车道当前健康态；monitor 为 nil（未启用 HC）恒 true。
func (m *healthMonitor) healthy(idx int) bool {
	if m == nil {
		return true
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.states[idx].healthy
}

// eligibleLanes 选路联动单源（JJC-20261120-002）：可参与选路的上游下标序
// = HC∩passive 交集——两套注册表独立，任一判摘即摘（恢复条件各自独立：
// HC=连续 healthy_lag 次探测成功；passive=摘除期满 half-open 试探）。
// 交集为空返回全部（全灭不专判——防探测器/计数器误判时全站 502，真实
// 请求照常放行）；两子系统均未启用时为全序，既有行为零变化。
func (h *ChainProxy) eligibleLanes() []int {
	all := make([]int, len(h.Upstreams))
	for i := range all {
		all[i] = i
	}
	out := make([]int, 0, len(all))
	for _, i := range all {
		if h.hcState.healthy(i) && h.passiveHealthy(i) {
			out = append(out, i)
		}
	}
	if len(out) == 0 {
		return all
	}
	return out
}

// laneEligible 单车道是否参与本次选路——eligibleLanes 的单车道投影
// （全灭不专判时交集为空恒 true），保证两口径永远同源。
func (h *ChainProxy) laneEligible(idx int) bool {
	for _, i := range h.eligibleLanes() {
		if i == idx {
			return true
		}
	}
	return false
}

// startHealthMonitor 挂载并启动 HC 子系统（HealthCheck 为 nil 时零操作）。
func (h *ChainProxy) startHealthMonitor() {
	if h.HealthCheck == nil || len(h.Upstreams) == 0 || h.hcState != nil {
		return
	}
	m, err := newHealthMonitor(h)
	if err != nil {
		h.log().Warn("chain_proxy: 健康检查配置非法，HC 未启动",
			zap.String("upstreams", strconv.Itoa(len(h.Upstreams))), zap.Error(err))
		return
	}
	h.hcState = m
	m.start()
}

// stopHealthMonitor 停止 HC 子系统并等待探测协程退出（done 先等后放——
// 吸取卡-20261118-01 后台协程×清理竞态经验）。
func (h *ChainProxy) stopHealthMonitor() {
	if h.hcState == nil {
		return
	}
	m := h.hcState
	h.hcState = nil
	close(m.stop)
	<-m.done
}
