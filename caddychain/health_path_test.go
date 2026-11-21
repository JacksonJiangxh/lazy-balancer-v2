package caddychain

// S2 逐车道探测路径用例（JJC-20261121-001）：
//   ① 分歧判别力：车道独立路径被分别探测（逐路径命中断言），独立翻转并联动摘除；
//   ② 回退语义：车道未配置 → 规则级路径；规则级亦空 → 缺省 /；
//   ③ 归一：车道路径无前导 / 自动补齐、空白 TrimSpace。

import (
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"
)

// pathProbeServer 多探针路径上游替身：probePaths 内的路径为探测面（逐路径
// 计数与可切换状态码），其余路径视为业务面（业务命中计数）。
type pathProbeServer struct {
	ts      *httptest.Server
	hits    map[string]*atomic.Int64
	states  map[string]*atomic.Int64
	bizHits atomic.Int64
}

func newPathProbeServer(t *testing.T, probePaths ...string) *pathProbeServer {
	s := &pathProbeServer{hits: map[string]*atomic.Int64{}, states: map[string]*atomic.Int64{}}
	for _, p := range probePaths {
		s.hits[p] = &atomic.Int64{}
		st := &atomic.Int64{}
		st.Store(http.StatusOK)
		s.states[p] = st
	}
	s.ts = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if st, ok := s.states[r.URL.Path]; ok {
			s.hits[r.URL.Path].Add(1)
			w.WriteHeader(int(st.Load()))
			return
		}
		s.bizHits.Add(1)
		w.WriteHeader(http.StatusOK)
	}))
	t.Cleanup(s.ts.Close)
	return s
}

func (s *pathProbeServer) setState(path string, code int64)  { s.states[path].Store(code) }
func (s *pathProbeServer) probeHits(path string) int64 {
	if h, ok := s.hits[path]; ok {
		return h.Load()
	}
	return 0 // 未注册路径（本替身只登记探测面）视作零命中
}
func (s *pathProbeServer) waitForProbe(t *testing.T, path string) {
	t.Helper()
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		if s.probeHits(path) > 0 {
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatalf("path %q was never probed", path)
}

// TestHC_PerLanePath_DivergentLanesProbedIndependently 分歧判别力：车道 0 带
// 独立路径 /alpha（无前导 / 归一补齐），车道 1 空=回退规则级 /beta。/alpha 判败
// → 车道 0 独立摘除（判别力自证——若两车道被同一路径探测则不会分叉）。
func TestHC_PerLanePath_DivergentLanesProbedIndependently(t *testing.T) {
	alpha := newPathProbeServer(t, "/alpha")
	beta := newPathProbeServer(t, "/beta")
	alpha.setState("/alpha", http.StatusBadGateway)
	h := startHC(t, newWRRHandler([]ChainUpstream{
		{Dial: dialOf(alpha.ts), HealthCheckPath: "alpha"}, // 无前导 /：HC 子系统归一补齐
		{Dial: dialOf(beta.ts)},                            // 空=回退规则级
	}, 50, 9000, 0), &ChainHealthCheck{IntervalMS: 40, TimeoutMS: 500, Path: "/beta", UnhealthyLag: 1, HealthyLag: 1})

	waitLaneHealthy(t, h, 0, false)
	waitLaneHealthy(t, h, 1, true)

	// 逐路径命中断言：车道 0 按其独立路径探测、车道 1 按规则级路径探测。
	if alpha.probeHits("/alpha") == 0 {
		t.Fatal("lane 0 was never probed on its own path /alpha")
	}
	if alpha.probeHits("/beta") != 0 {
		t.Fatalf("lane 0 probed rule-level path instead of its own: /beta hits=%d", alpha.probeHits("/beta"))
	}
	if beta.probeHits("/beta") == 0 {
		t.Fatal("lane 1 was never probed on rule-level path /beta")
	}

	// 摘除联动：车道 0 判摘后业务流量全部落车道 1。
	for i := 0; i < 4; i++ {
		resp := do(t, h, http.MethodGet, "/", "")
		if resp.StatusCode != http.StatusOK {
			t.Fatalf("request %d: status = %d", i, resp.StatusCode)
		}
		readAll(t, resp)
	}
	if alpha.bizHits.Load() != 0 {
		t.Fatalf("per-lane-probed unhealthy lane received %d business hits, want 0", alpha.bizHits.Load())
	}
	if beta.bizHits.Load() < 4 {
		t.Fatalf("healthy lane biz hits = %d, want >= 4", beta.bizHits.Load())
	}
}

// TestHC_PerLanePath_FallbackChain 回退链尾段：规则级路径亦空时车道被按缺省 /
// 探测（车道空→规则级空→DefaultHCPath）。
func TestHC_PerLanePath_FallbackChain(t *testing.T) {
	s := newPathProbeServer(t, "/")
	startHC(t, newWRRHandler([]ChainUpstream{{Dial: dialOf(s.ts)}}, 50, 9000, 0),
		&ChainHealthCheck{IntervalMS: 40, TimeoutMS: 500}) // Path 空且车道无覆盖
	s.waitForProbe(t, "/")
}

// TestHC_PerLanePath_NormalizationTable 归一表：车道覆盖 TrimSpace + 前导 /
// 补齐；空回退规则级归一结果（含规则级自身的补齐）。
func TestHC_PerLanePath_NormalizationTable(t *testing.T) {
	h := &ChainProxy{
		Upstreams: []ChainUpstream{
			{HealthCheckPath: "alpha"},
			{HealthCheckPath: "  /beta  "},
			{},
		},
		HealthCheck: &ChainHealthCheck{Path: "gamma"},
	}
	m, err := newHealthMonitor(h)
	if err != nil {
		t.Fatalf("newHealthMonitor: %v", err)
	}
	want := []string{"/alpha", "/beta", "/gamma"}
	for i, w := range want {
		if m.paths[i] != w {
			t.Fatalf("paths[%d] = %q, want %q", i, m.paths[i], w)
		}
	}
}
