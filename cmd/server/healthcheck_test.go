package main

import (
	"net/http"
	"net/http/httptest"
	"os"
	"strconv"
	"testing"
	"time"
)

// withPANEL_PORT 设临时 PANEL_PORT 环境变量（测试结束还原）。
func withPANEL_PORT(t *testing.T, value string) {
	t.Helper()
	old, had := os.LookupEnv("PANEL_PORT")
	if value == "" {
		_ = os.Unsetenv("PANEL_PORT")
	} else {
		_ = os.Setenv("PANEL_PORT", value)
	}
	t.Cleanup(func() {
		if had {
			_ = os.Setenv("PANEL_PORT", old)
		} else {
			_ = os.Unsetenv("PANEL_PORT")
		}
	})
}

// PANEL_PORT 换口后探针必须跟随：这是本能力的存在意义——host 模式下 8000
// 被占用时用户换口，探针打旧口会让容器长期误显 unhealthy（面板功能正常）。
func TestHealthcheckPanelPort_followsPANEL_PORT(t *testing.T) {
	withPANEL_PORT(t, "9000")
	urls := healthcheckURLs()
	wantHTTPS := "https://127.0.0.1:9000/health"
	wantHTTP := "http://127.0.0.1:9000/health"
	if urls[0] != wantHTTPS || urls[1] != wantHTTP {
		t.Fatalf("urls=%v, want [%q %q]", urls, wantHTTPS, wantHTTP)
	}
}

// 未设 PANEL_PORT → 出厂默认 8000（与 internal/config 的面板默认端口同口径）。
func TestHealthcheckPanelPort_defaultsWhenUnset(t *testing.T) {
	withPANEL_PORT(t, "")
	urls := healthcheckURLs()
	if urls[0] != "https://127.0.0.1:8000/health" || urls[1] != "http://127.0.0.1:8000/health" {
		t.Fatalf("urls=%v, want default :8000 both schemes", urls)
	}
}

// 非法值（非数字/越界）必须回落默认而非静默探错端口——与 envPort 同口径。
func TestHealthcheckPanelPort_invalidFallsBack(t *testing.T) {
	for _, tc := range []struct {
		name  string
		value string
	}{
		{"not-a-number", "abc"},
		{"zero", "0"},
		{"negative", "-1"},
		{"above-range", "65536"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			withPANEL_PORT(t, tc.value)
			port := healthcheckPanelPort()
			if port != defaultHealthcheckPort {
				t.Fatalf("port=%d, want default %d", port, defaultHealthcheckPort)
			}
			urls := healthcheckURLs()
			wantHTTPS := "https://127.0.0.1:" + strconv.Itoa(defaultHealthcheckPort) + "/health"
			wantHTTP := "http://127.0.0.1:" + strconv.Itoa(defaultHealthcheckPort) + "/health"
			if urls[0] != wantHTTPS || urls[1] != wantHTTP {
				t.Fatalf("urls=%v, want [%q %q]", urls, wantHTTPS, wantHTTP)
			}
		})
	}
}

// 端到端：面板真听在 PANEL_PORT 指定的口上，探针一次打对（HTTPS 先行命中）。
func TestRunHealthcheck_probesPANEL_PORTPort(t *testing.T) {
	withPANEL_PORT(t, "9000")
	// 还原 healthcheckURLs 让它按 env 求值（withHealthcheckURLs 的替身不放行）。
	oldURLs := healthcheckURLs
	healthcheckURLs = oldURLs
	t.Cleanup(func() { healthcheckURLs = oldURLs })

	// httptest 监听随机口，无法钉 9000；改为注入「求值结果」层——真实链路
	// （env → 端口 → URL）已由上面三个单测覆盖，本测只证明 runHealthcheck
	// 消费 healthcheckURLs() 的返回值。
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()
	withHealthcheckURLs(t, srv.URL, "http://127.0.0.1:1")
	if code := runHealthcheck(); code != 0 {
		t.Fatalf("exit=%d, want 0", code)
	}
}

func withHealthcheckURLs(t *testing.T, httpsURL, httpURL string) {
	t.Helper()
	oldURLs, oldTimeout := healthcheckURLs, healthcheckTimeout
	urls := []string{httpsURL, httpURL}
	healthcheckURLs = func() []string { return urls }
	t.Cleanup(func() {
		healthcheckURLs, healthcheckTimeout = oldURLs, oldTimeout
	})
}

func TestRunHealthcheck_httpsOK(t *testing.T) {
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()
	withHealthcheckURLs(t, srv.URL, "http://127.0.0.1:1")

	if code := runHealthcheck(); code != 0 {
		t.Fatalf("exit=%d, want 0（自签 HTTPS 回环应视为健康）", code)
	}
}

func TestRunHealthcheck_fallsBackToPlainHTTP(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()
	// HTTPS 端点不可达（面板关闭管理 TLS 的形态）→ 明文回落成功。
	withHealthcheckURLs(t, "https://127.0.0.1:1", srv.URL)

	if code := runHealthcheck(); code != 0 {
		t.Fatalf("exit=%d, want 0（HTTPS 失败后必须回落明文）", code)
	}
}

func TestRunHealthcheck_non200IsUnhealthy(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusServiceUnavailable)
	}))
	defer srv.Close()
	withHealthcheckURLs(t, "https://127.0.0.1:1", srv.URL)

	if code := runHealthcheck(); code != 1 {
		t.Fatalf("exit=%d, want 1（非 200 不得判健康）", code)
	}
}

func TestRunHealthcheck_timeoutIsUnhealthy(t *testing.T) {
	release := make(chan struct{})
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		<-release
		w.WriteHeader(http.StatusOK)
	}))
	defer func() { close(release); srv.Close() }()
	withHealthcheckURLs(t, "https://127.0.0.1:1", srv.URL)
	healthcheckTimeout = 50 * time.Millisecond

	start := time.Now()
	if code := runHealthcheck(); code != 1 {
		t.Fatalf("exit=%d, want 1（超时必须判不健康）", code)
	}
	if elapsed := time.Since(start); elapsed > 2*time.Second {
		t.Fatalf("耗时 %v，探针未按超时收敛", elapsed)
	}
}

func TestHealthcheckRequested_onlyFirstArgument(t *testing.T) {
	cases := []struct {
		args []string
		want bool
	}{
		{[]string{"lazy-balancer"}, false},
		{[]string{"lazy-balancer", "--healthcheck"}, true},
		{[]string{"lazy-balancer", "-config", "/app/config.yaml"}, false},
		// 只有首个参数触发模式切换，避免误吞服务参数。
		{[]string{"lazy-balancer", "-config", "--healthcheck"}, false},
	}
	for _, tc := range cases {
		if got := healthcheckRequested(tc.args); got != tc.want {
			t.Fatalf("args=%v got=%v want=%v", tc.args, got, tc.want)
		}
	}
}

// 明文入口若 302 到登录页，跟随跳转会拿到登录页 200 —— 必须判不健康。
func TestRunHealthcheck_doesNotFollowRedirect(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/health", func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, "/login", http.StatusFound)
	})
	mux.HandleFunc("/login", func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	})
	srv := httptest.NewServer(mux)
	defer srv.Close()
	withHealthcheckURLs(t, "https://127.0.0.1:1", srv.URL+"/health")

	if code := runHealthcheck(); code != 1 {
		t.Fatalf("exit=%d, want 1（302 不得跟随成登录页 200）", code)
	}
}

func TestRunHealthcheck_twoFailedAttemptsStayWithinConfiguredBudget(t *testing.T) {
	release := make(chan struct{})
	newBlockingServer := func(tlsEnabled bool) *httptest.Server {
		handler := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			<-release
			w.WriteHeader(http.StatusOK)
		})
		if tlsEnabled {
			return httptest.NewTLSServer(handler)
		}
		return httptest.NewServer(handler)
	}
	httpsServer := newBlockingServer(true)
	httpServer := newBlockingServer(false)
	defer func() {
		close(release)
		httpsServer.Close()
		httpServer.Close()
	}()
	withHealthcheckURLs(t, httpsServer.URL, httpServer.URL)
	healthcheckTimeout = 40 * time.Millisecond

	start := time.Now()
	if code := runHealthcheck(); code != 1 {
		t.Fatalf("exit=%d, want 1", code)
	}
	if elapsed := time.Since(start); elapsed > time.Second {
		t.Fatalf("two attempts took %v, want two bounded waits", elapsed)
	}
}
