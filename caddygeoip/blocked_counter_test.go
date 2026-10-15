package caddygeoip

import (
	"errors"
	"net/http"
	"net/http/httptest"
	"strconv"
	"testing"

	"github.com/caddyserver/caddy/v2/modules/caddyhttp"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/testutil"
	dto "github.com/prometheus/client_model/go"
)

// 表驱动:仅 coraza 中断(ID 非空+4xx)计数,其余形态零误计。
func TestSecurityBlockedCounter_ServeHTTP(t *testing.T) {
	rule := "lb_test_rule"
	testCounter := newSecurityBlockedCounterVec(prometheus.NewRegistry())
	before := testutil.ToFloat64(testCounter.WithLabelValues(rule))

	cases := []struct {
		name      string
		nextErr   error
		wantCount float64
	}{
		{"nil error passes through", nil, 0},
		{"coraza 403 interruption counts", caddyhttp.HandlerError{StatusCode: 403, ID: "abcdefghijklmnop"}, 1},
		{"coraza 429 custom block counts", caddyhttp.HandlerError{StatusCode: 429, ID: "qrstuvwxyzabcdef"}, 1},
		{"rate limit 429 (caddyhttp.Error generated ID) counts", caddyhttp.HandlerError{StatusCode: 429, ID: "rA9kX2mPq"}, 1},
		{"WAF internal 500 (16-char ID, F1 regression guard) not counted", caddyhttp.HandlerError{StatusCode: 500, ID: "abcdefghijklmnop"}, 0},
		{"caddy 404 no ID not counted", caddyhttp.HandlerError{StatusCode: 404, ID: ""}, 0},
		{"proxy 499 client-cancel (9-char ID) not counted", caddyhttp.HandlerError{StatusCode: 499, ID: "rA9kX2mPq"}, 0},
		{"request_body 413 (9-char ID) not counted", caddyhttp.HandlerError{StatusCode: 413, ID: "xY8kL2mNp"}, 0},
		{"plain error not counted", errors.New("boom"), 0},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			h := &SecurityBlockedCounter{Rule: rule, metrics: testCounter}
			next := caddyhttp.HandlerFunc(func(http.ResponseWriter, *http.Request) error { return tc.nextErr })
			rec := httptest.NewRecorder()
			req := httptest.NewRequest(http.MethodGet, "/", nil)
			gotErr := h.ServeHTTP(rec, req, next)
			// 返回值必须原样透传(链语义零改动)
			if gotErr != tc.nextErr {
				t.Fatalf("ServeHTTP returned %v, want passthrough %v", gotErr, tc.nextErr)
			}
		})
	}
	after := testutil.ToFloat64(testCounter.WithLabelValues(rule))
	wantTotal := before + 3 // coraza 403 + coraza 429 + ratelimit 429 三笔
	if after != wantTotal {
		t.Fatalf("counter=%v, want %v (before=%v)", after, wantTotal, before)
	}
}

// 第 75 轮（预检拦耗时口径）：拦截耗时写点的分段选键——
// 形状①预检段拦：起始头仍=注入原值（链未抵达 timing_pre 收点）→ 写 pre
// （决策后、403 写出前的纯预检评估），不得写 end（防同 ID 双段）；
// 形状②WAF/限流段拦：起始头已被 timing_pre 重写为分段锚点 → 写 end
// （链首至此全链，读侧 end-pre 得 WAF 段），不得写 pre。
// 第 76 轮：断言目标从侧车文件行改为进程内注册表快照；post-next 终态标记
// （auditTimingClose）一并钉住——审计写插件 drain 依赖该标记停止等待。
func TestSecurityBlockedCounter_timingSegmentSelection(t *testing.T) {
	const id = "0123456789abcdef"
	cases := []struct {
		name          string
		nextErr       error
		rewriteInNext bool // next 模拟 timing_pre 已过（重写起始头为锚点）
		wantSegment   string
	}{
		{"precheck interruption writes pre", caddyhttp.HandlerError{StatusCode: 403, ID: id}, false, "pre"},
		{"precheck interruption stage page 481 writes pre", caddyhttp.HandlerError{StatusCode: 481, ID: id}, false, "pre"},
		{"waf interruption after pre writes end", caddyhttp.HandlerError{StatusCode: 403, ID: id}, true, "end"},
		{"ratelimit 429 after pre writes end", caddyhttp.HandlerError{StatusCode: http.StatusTooManyRequests, ID: "rA9kX2mPq"}, true, "end"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			useTestTimingRegistry(t)
			h := &SecurityBlockedCounter{Rule: "lb_seg_rule"}
			next := caddyhttp.HandlerFunc(func(_ http.ResponseWriter, r *http.Request) error {
				if tc.rewriteInNext {
					// 模拟 timing_pre 的锚点交接契约：重写值严格大于注入原值
					//（时钟分辨率下同值会被误判为预检段拦——见实现注释）。
					old, _ := strconv.ParseInt(r.Header.Get(securityTimingStartHeader), 10, 64)
					r.Header.Set(securityTimingStartHeader, strconv.FormatInt(old+1, 10))
				}
				return tc.nextErr
			})
			req := httptest.NewRequest(http.MethodGet, "/", nil)

			if err := h.ServeHTTP(httptest.NewRecorder(), req, next); err != tc.nextErr {
				t.Fatalf("ServeHTTP = %v; want passthrough %v", err, tc.nextErr)
			}
			// timing ID 由 ServeHTTP 注入（覆盖客户端伪造值）——运行时取真实关联键
			id := req.Header.Get(securityTimingHeader)
			if len(id) != 16 {
				t.Fatalf("timing id header = %q; want 16-char injected id", id)
			}

			snap := auditTimingLookupForTest(t, id)
			if !snap.closed {
				t.Fatal("blocked_counter post-next must close the timing entry (terminal marker)")
			}
			switch tc.wantSegment {
			case "pre":
				if !snap.preSet || snap.endSet {
					t.Fatalf("snapshot = %+v; want exactly pre segment", snap)
				}
				if snap.preUs < 0 {
					t.Fatalf("pre=%d; want non-negative µs", snap.preUs)
				}
			case "end":
				if !snap.endSet || snap.preSet {
					t.Fatalf("snapshot = %+v; want exactly end segment", snap)
				}
				if snap.endUs < 0 {
					t.Fatalf("end=%d; want non-negative µs", snap.endUs)
				}
			}
		})
	}

	// 非拦截形态（logged 放行）：无分段写点，但终态标记照常置位（drain 不等待）。
	t.Run("logged passthrough closes entry without segments", func(t *testing.T) {
		useTestTimingRegistry(t)
		h := &SecurityBlockedCounter{Rule: "lb_seg_rule"}
		next := caddyhttp.HandlerFunc(func(http.ResponseWriter, *http.Request) error { return nil })
		req := httptest.NewRequest(http.MethodGet, "/", nil)
		if err := h.ServeHTTP(httptest.NewRecorder(), req, next); err != nil {
			t.Fatalf("ServeHTTP: %v", err)
		}
		id := req.Header.Get(securityTimingHeader)
		snap := auditTimingLookupForTest(t, id)
		if !snap.closed || snap.preSet || snap.endSet {
			t.Fatalf("snapshot = %+v; want closed empty entry", snap)
		}
	})
}

// P4-1(第 28.5 轮审计):Provision/registerOrExisting 护栏——7723d76d registry
// 事故(指标恒 0)的回归测试。
func TestRegisterOrExisting(t *testing.T) {
	reg := prometheus.NewRegistry()

	// 形状①:首次注册成功,返回新实例
	first := newSecurityBlockedCounterVec(reg)
	first.WithLabelValues("rule_a").Inc()
	var mfs []*dto.MetricFamily
	var err error
	mfs, err = reg.Gather()
	if err != nil {
		t.Fatal(err)
	}
	found := false
	for _, mf := range mfs {
		if mf.GetName() == "lazybalancer_security_blocked_total" {
			found = true
		}
	}
	if !found {
		t.Fatal("first registration: metric not exposed")
	}

	// 形状②:同 registry 重复注册复用实例(不丢数据,不 panic)
	second := newSecurityBlockedCounterVec(reg)
	if first != second {
		t.Fatal("re-registration on same registry must reuse existing instance (data preserved)")
	}
	if got := testutil.ToFloat64(first.WithLabelValues("rule_a")); got != 1 {
		t.Fatalf("reused instance lost data: count=%v, want 1", got)
	}

	// 形状③:跨 reload 新 registry 全新注册(归零,与 caddy_http_* 同纪元)
	reg2 := prometheus.NewRegistry()
	third := newSecurityBlockedCounterVec(reg2)
	if third == first {
		t.Fatal("cross-reload new registry must get fresh instance (reset to zero)")
	}
	if got := testutil.ToFloat64(third.WithLabelValues("rule_a")); got != 0 {
		t.Fatalf("cross-reload instance not zeroed: count=%v, want 0", got)
	}
}
