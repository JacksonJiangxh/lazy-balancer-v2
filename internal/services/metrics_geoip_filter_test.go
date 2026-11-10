package services

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"lazy-balancer-v2/internal/db"
)

// 透传判据只对 Caddy 的 caddy_http_* 指标族生效：geoip 透传路由没有
// reverse_proxy，它注入的序列只在 Caddy 自有指标族里出现；本插件自注册的
// lazybalancer_* 规则族只有 rule/class/direction 标签，且透传路由不挂规则
// 计量处理器——规则族既不可能、也不需要被该判据剔除。
func TestIsGeoIPPassSeries_onlyMatchesCaddyHTTPFamily(t *testing.T) {
	cases := []struct {
		name string
		line string
		want bool
	}{
		{"requests_total from passthrough route", `caddy_http_requests_total{handler="http.handlers.geoip2region",host="example.com",server="http_443"} 20`, true},
		{"duration count from passthrough route", `caddy_http_request_duration_seconds_count{code="429",handler="http.handlers.geoip2region",host="example.com",server="http_443"} 7`, true},
		{"main route series", `caddy_http_requests_total{handler="headers",host="example.com",server="http_443"} 20`, false},
		{"real rule series carries no handler label", `lazybalancer_requests_total{rule="lb_geo"} 7`, false},
		{"rule bytes series", `lazybalancer_bytes_total{rule="lb_geo",direction="in"} 7`, false},
		{"hypothetical rule series with handler label stays out of the predicate", `lazybalancer_requests_total{handler="http.handlers.geoip2region",rule="lb_geo"} 7`, false},
		{"layer4 family", `caddy_layer4_proxy_connections_total{upstream="127.0.0.1:80"} 1`, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := IsGeoIPPassSeries(tc.line); got != tc.want {
				t.Fatalf("IsGeoIPPassSeries(%q)=%v, want %v", tc.line, got, tc.want)
			}
		})
	}
}

// geoip 透传序列在单趟聚合的行分派前整行跳过（Caddy 全局族），同一批文本里的
// 规则族序列照常计入。逐字节分隔符语义由「按 \n 切分后丢弃命中行」天然保持，
// 无需另行重组副本；本用例钉三形态：普通行 + 透传行混排、透传行位于末行
// （无尾随换行）、带尾随换行。
func TestAggregatePrometheusText_skipsGeoipPassSeries(t *testing.T) {
	keep := `caddy_http_requests_total{handler="headers",host="example.com",server="http_443"} 20`
	geo := `caddy_http_requests_total{handler="http.handlers.geoip2region",host="example.com",server="http_443"} 20`
	rule := `lazybalancer_requests_total{rule="lb_geo"} 7`

	cases := []struct {
		name  string
		input string
	}{
		{"mixed lines", keep + "\n" + geo + "\n" + rule},
		{"geoip last line no newline", keep + "\n" + rule + "\n" + geo},
		{"trailing newline", keep + "\n" + geo + "\n" + rule + "\n"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			res := aggregatePrometheusText(tc.input, prometheusScanGlobal|prometheusScanRules)
			if res.globalErr != nil {
				t.Fatalf("global parse error: %v", res.globalErr)
			}
			if res.rulesErr != nil {
				t.Fatalf("rules parse error: %v", res.rulesErr)
			}
			if res.global.requestsTotal != 20 {
				t.Fatalf("global requests=%d, want 20（geoip 透传序列必须跳过）", res.global.requestsTotal)
			}
			agg := res.rules["lb_geo"]
			if agg == nil || agg.requests != 7 {
				t.Fatalf("rule aggregate=%+v, want requests=7（规则族序列照常计入）", agg)
			}
		})
	}
}

// 联动：采集链把同一份过滤结果用于 per-rule 落库。真实重复形态只存在于
// caddy_http_* 族（透传路由与主路由各注一次），规则族序列本身没有孪生行——
// per-rule 计数不得被透传行连带影响，也不得因过滤而丢失。
func TestCollect_perRuleCountsIgnorePassthroughSeries(t *testing.T) {
	setupMetricsRetentionTest(t)
	isolateMetricsState(t)
	text := `caddy_http_requests_total{handler="headers",host="example.com",server="http_443"} 20
caddy_http_requests_total{handler="http.handlers.geoip2region",host="example.com",server="http_443"} 20
lazybalancer_requests_total{rule="lb_geo"} 20
`
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(text))
	}))
	t.Cleanup(server.Close)
	service := NewMetricsService(server.URL, 30)

	service.collect()

	var requests int64
	if err := db.MetricsDB.QueryRow("SELECT COALESCE(SUM(requests_total),0) FROM metrics_history WHERE rule_id='lb_geo'").Scan(&requests); err != nil {
		t.Fatalf("read per-rule metrics: %v", err)
	}
	if requests != 20 {
		t.Fatalf("per-rule requests=%d, want 20（规则族序列原值落库）", requests)
	}
}
