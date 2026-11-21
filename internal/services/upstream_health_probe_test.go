package services

// S3 聚合探针引擎用例（JJC-20261121-001，route D=官方 health_upstream 聚合探针模式）：
//   ① effectiveUpstreamHealthPaths 回退链（逐上游>规则级>/）；
//   ② healthProbePathsDiverge 分歧判定（全同 false / 任一不同 true）；
//   ③ 注册表生命周期（收集→commit 可见 / snapshot→restore 失败还原）；
//   ④ buildProbeRuleDef 装配（probeHost 三级回退/scheme 表）；
//   ⑤ HandlePanelProbe 守卫（回环 403 面/方法限定/规则 404/缺头 400/未知目标 502）
//      与真实探测（http/https/skip-verify/2xx 活·失联败）。

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// TestEffectiveUpstreamHealthPaths_FallbackChain 回退链：逐上游覆盖>规则级>缺省 /；
// TrimSpace 归一（与 origin_domain 三级回退同风格）。
func TestEffectiveUpstreamHealthPaths_FallbackChain(t *testing.T) {
	rule := SingleRuleConfig{HealthCheckPath: "/rule-level"}
	ups := []UpstreamConfig{
		{HealthCheckPath: "/own"},
		{HealthCheckPath: "  "}, // 空白=未配置
		{},
	}
	got := effectiveUpstreamHealthPaths(rule, ups)
	want := []string{"/own", "/rule-level", "/rule-level"}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("paths[%d] = %q, want %q", i, got[i], want[i])
		}
	}

	// 规则级亦空：无覆盖的上游回退 /；有覆盖的保持自己的路径（覆盖不受规则级清空影响）。
	rule.HealthCheckPath = ""
	got = effectiveUpstreamHealthPaths(rule, ups)
	if got[0] != "/own" {
		t.Fatalf("empty rule-level: paths[0] = %q, want /own（逐上游覆盖优先）", got[0])
	}
	for i := 1; i < len(got); i++ {
		if got[i] != "/" {
			t.Fatalf("empty rule-level: paths[%d] = %q, want /", i, got[i])
		}
	}
}

// TestHealthProbePathsDiverge 分歧判定：全同（含全空跟随规则级）false；
// 任一有效路径与基准不同 true。
func TestHealthProbePathsDiverge(t *testing.T) {
	if healthProbePathsDiverge("/hc", []string{"/hc", "/hc"}) {
		t.Fatal("identical paths must not diverge")
	}
	if !healthProbePathsDiverge("/hc", []string{"/hc", "/own"}) {
		t.Fatal("one divergent path must diverge")
	}
	if healthProbePathsDiverge("/", []string{"/"}) {
		t.Fatal("all-default paths must not diverge")
	}
	if healthProbePathsDiverge("/hc", nil) {
		t.Fatal("no upstreams must not diverge")
	}
}

// TestPerUpstreamProbeRegistryLifecycle 注册表生命周期：收集态不可见 → commit
// 后可寻址 → snapshot/restore 失败出口还原。
func TestPerUpstreamProbeRegistryLifecycle(t *testing.T) {
	resetPerUpstreamProbeCollector()
	t.Cleanup(func() {
		resetPerUpstreamProbeCollector()
		restorePerUpstreamProbeRegistry(nil)
	})

	def := &probeRuleDef{ruleID: "lb_probe_lifecycle", targets: map[string]string{"127.0.0.1:1": "/hc"}}
	registerPerUpstreamProbeRule(def)
	if _, ok := perUpstreamProbeDef("lb_probe_lifecycle"); ok {
		t.Fatal("collected def must not be addressable before commit")
	}
	commitPerUpstreamProbeRegistry()
	if _, ok := perUpstreamProbeDef("lb_probe_lifecycle"); !ok {
		t.Fatal("committed def must be addressable")
	}

	// 失败出口：快照→收集新登记（不得可见）→restore 回快照态。
	snapshot := perUpstreamProbeRegistrySnapshot()
	resetPerUpstreamProbeCollector()
	registerPerUpstreamProbeRule(&probeRuleDef{ruleID: "lb_probe_draft", targets: map[string]string{}})
	restorePerUpstreamProbeRegistry(snapshot)
	if _, ok := perUpstreamProbeDef("lb_probe_draft"); ok {
		t.Fatal("restored registry must drop uncommitted collection")
	}
	if _, ok := perUpstreamProbeDef("lb_probe_lifecycle"); !ok {
		t.Fatal("restored registry must keep snapshot defs")
	}
}

// TestBuildProbeRuleDef 装配：probeHost=健康检查域名>规则级后端域名；targets/
// schemes 按 dial 键面装配；interval/timeout 取 healthCheckValues。
func TestBuildProbeRuleDef(t *testing.T) {
	rule := SingleRuleConfig{CaddyID: "lb_probe_def", HealthCheckHost: "hc.example.com", HostHeader: "origin.example.com"}
	ups := []UpstreamConfig{
		{Host: "10.0.0.1", Port: 9001, Protocol: "https"},
		{Host: "10.0.0.2", Port: 9002, Protocol: "http"},
	}
	paths := []string{"/a", "/b"}
	hc := healthCheckValues{interval: 15, timeout: 3, failing: 3, passes: 2}
	def := buildProbeRuleDef(rule, ups, paths, hc)

	if def.ruleID != "lb_probe_def" || def.interval != 15 || def.timeout != 3 {
		t.Fatalf("def header = %+v", def)
	}
	if def.probeHost != "hc.example.com" {
		t.Fatalf("probeHost = %q, want hc.example.com (HealthCheckHost 优先)", def.probeHost)
	}
	if def.targets["10.0.0.1:9001"] != "/a" || def.targets["10.0.0.2:9002"] != "/b" {
		t.Fatalf("targets = %v", def.targets)
	}
	if !def.schemes["10.0.0.1:9001"] || def.schemes["10.0.0.2:9002"] {
		t.Fatalf("schemes = %v", def.schemes)
	}

	// probeHost 回退：健康检查域名空 → 规则级后端域名。
	rule.HealthCheckHost = ""
	def2 := buildProbeRuleDef(rule, ups, paths, hc)
	if def2.probeHost != "origin.example.com" {
		t.Fatalf("probeHost fallback = %q, want origin.example.com", def2.probeHost)
	}
}

// panelProbeRequest 组装回环来源的探针请求（可覆写来源与头）。
func panelProbeRequest(t *testing.T, method, path string, remote string, targetHeader string) *http.Request {
	t.Helper()
	req := httptest.NewRequest(method, path, nil)
	if remote != "" {
		req.RemoteAddr = remote
	}
	if targetHeader != "" {
		req.Header.Set("X-LB-Probe-Target", targetHeader)
	}
	return req
}

func runPanelProbe(t *testing.T, req *http.Request) *httptest.ResponseRecorder {
	t.Helper()
	rec := httptest.NewRecorder()
	HandlePanelProbe(rec, req)
	return rec
}

// TestHandlePanelProbe_Guards 守卫面：非回环 403；GET/HEAD 之外 405；未知规则
// 404；缺 X-LB-Probe-Target 400；路径含 "/" 404。
func TestHandlePanelProbe_Guards(t *testing.T) {
	if code := runPanelProbe(t, panelProbeRequest(t, http.MethodGet, PanelProbePathPrefix+"any", "10.0.0.9:5555", "127.0.0.1:1")).Code; code != http.StatusForbidden {
		t.Fatalf("non-loopback = %d, want 403", code)
	}
	if code := runPanelProbe(t, panelProbeRequest(t, http.MethodPost, PanelProbePathPrefix+"any", "127.0.0.1:5555", "127.0.0.1:1")).Code; code != http.StatusMethodNotAllowed {
		t.Fatalf("POST = %d, want 405", code)
	}
	if code := runPanelProbe(t, panelProbeRequest(t, http.MethodGet, PanelProbePathPrefix+"lb_unknown_rule", "127.0.0.1:5555", "127.0.0.1:1")).Code; code != http.StatusNotFound {
		t.Fatalf("unknown rule = %d, want 404", code)
	}
	if code := runPanelProbe(t, panelProbeRequest(t, http.MethodGet, PanelProbePathPrefix+"sub/path", "127.0.0.1:5555", "")).Code; code != http.StatusNotFound {
		t.Fatalf("path with slash = %d, want 404", code)
	}
}

// TestHandlePanelProbe_MissingTargetHeaderAndUnknownTarget 已登记规则下：缺
// X-LB-Probe-Target → 400；目标不在登记面 → 502（失败语义，伪造/漂移头不扰动探测状态）。
func TestHandlePanelProbe_MissingTargetHeaderAndUnknownTarget(t *testing.T) {
	resetPerUpstreamProbeCollector()
	t.Cleanup(func() {
		resetPerUpstreamProbeCollector()
		restorePerUpstreamProbeRegistry(nil)
	})
	registerPerUpstreamProbeRule(&probeRuleDef{ruleID: "lb_probe_guard", targets: map[string]string{"127.0.0.1:9001": "/hc"}})
	commitPerUpstreamProbeRegistry()

	if code := runPanelProbe(t, panelProbeRequest(t, http.MethodGet, PanelProbePathPrefix+"lb_probe_guard", "127.0.0.1:5555", "")).Code; code != http.StatusBadRequest {
		t.Fatalf("missing target header = %d, want 400", code)
	}
	if code := runPanelProbe(t, panelProbeRequest(t, http.MethodGet, PanelProbePathPrefix+"lb_probe_guard", "127.0.0.1:5555", "10.9.9.9:1")).Code; code != http.StatusBadGateway {
		t.Fatalf("unknown target = %d, want 502", code)
	}
}

// TestHandlePanelProbe_ProbesRealUpstream 真实探测：http 上游按登记路径探测——
// 2xx 路径→200（Caddy 记健康）、5xx 路径→502（记失败）；https 上游 skip-verify
// 探测成功；失联目标→502。
func TestHandlePanelProbe_ProbesRealUpstream(t *testing.T) {
	up := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/ok":
			w.WriteHeader(http.StatusOK)
		case "/bad":
			w.WriteHeader(http.StatusBadGateway)
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	t.Cleanup(up.Close)
	upTLS := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	t.Cleanup(upTLS.Close)
	dead := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))
	deadAddr := dead.Listener.Addr().String()
	dead.Close() // 关闭制造失联目标

	dial := up.Listener.Addr().String()
	dialTLS := upTLS.Listener.Addr().String()
	resetPerUpstreamProbeCollector()
	t.Cleanup(func() {
		resetPerUpstreamProbeCollector()
		restorePerUpstreamProbeRegistry(nil)
	})
	registerPerUpstreamProbeRule(&probeRuleDef{
		ruleID:  "lb_probe_real",
		timeout: 2,
		targets: map[string]string{dial: "/ok", dialTLS: "/"},
		schemes: map[string]bool{dial: false, dialTLS: true},
	})
	commitPerUpstreamProbeRegistry()

	if code := runPanelProbe(t, panelProbeRequest(t, http.MethodGet, PanelProbePathPrefix+"lb_probe_real", "127.0.0.1:5555", dial)).Code; code != http.StatusOK {
		t.Fatalf("healthy upstream = %d, want 200", code)
	}
	if code := runPanelProbe(t, panelProbeRequest(t, http.MethodGet, PanelProbePathPrefix+"lb_probe_real", "127.0.0.1:5555", dialTLS)).Code; code != http.StatusOK {
		t.Fatalf("https upstream (skip-verify) = %d, want 200", code)
	}
	if code := runPanelProbe(t, panelProbeRequest(t, http.MethodGet, PanelProbePathPrefix+"lb_probe_real", "127.0.0.1:5555", deadAddr)).Code; code != http.StatusBadGateway {
		t.Fatalf("dead upstream = %d, want 502", code)
	}

	// 5xx 路径：登记面切换到 /bad → 探测判败。
	resetPerUpstreamProbeCollector()
	registerPerUpstreamProbeRule(&probeRuleDef{
		ruleID:  "lb_probe_real",
		timeout: 2,
		targets: map[string]string{dial: "/bad"},
		schemes: map[string]bool{dial: false},
	})
	commitPerUpstreamProbeRegistry()
	if code := runPanelProbe(t, panelProbeRequest(t, http.MethodGet, PanelProbePathPrefix+"lb_probe_real", "127.0.0.1:5555", dial)).Code; code != http.StatusBadGateway {
		t.Fatalf("5xx path = %d, want 502", code)
	}
	if !strings.HasPrefix(PanelProbePathPrefix, "/") {
		t.Fatal("probe prefix must keep leading slash")
	}
}
