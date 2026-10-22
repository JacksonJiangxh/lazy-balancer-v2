package services

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"lazy-balancer-v2/internal/db"
)

// geoip 透传序列在单趟聚合的行分派前整行跳过（全局族与规则族同时生效）。
// 逐字节分隔符语义由「按 \n 切分后丢弃命中行」天然保持，无需另行重组副本；
// 本用例钉四形态：普通行 + 透传行混排、透传行位于末行（无尾随换行）、
// 全局族与规则族同句柄。
func TestAggregatePrometheusText_skipsGeoipPassSeries(t *testing.T) {
	keep := `caddy_http_requests_total{handler="reverse_proxy",host="example.com"} 20`
	geo := `caddy_http_requests_total{handler="http.handlers.geoip2region",host="example.com"} 20`
	ruleKeep := `lazybalancer_requests_total{handler="reverse_proxy",rule="lb_geo"} 7`
	ruleGeo := `lazybalancer_requests_total{handler="http.handlers.geoip2region",rule="lb_geo"} 7`

	cases := []struct {
		name  string
		input string
	}{
		{"mixed lines", keep + "\n" + geo + "\n" + ruleKeep + "\n" + ruleGeo},
		{"geoip last line no newline", keep + "\n" + ruleKeep + "\n" + geo},
		{"trailing newline", keep + "\n" + geo + "\n" + ruleKeep + "\n" + ruleGeo + "\n"},
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
				t.Fatalf("rule aggregate=%+v, want requests=7（geoip 透传序列必须跳过）", agg)
			}
		})
	}
}

// 联动：过滤后的文本必须同时用于 per-host 存储——此前只断言全局
// TotalRequests，per-host 仍按未过滤文本落库（双计）不会被发现。
func TestCollect_perHostUsesFilteredSeries(t *testing.T) {
	setupMetricsRetentionTest(t)
	isolateMetricsState(t)
	text := `lazybalancer_requests_total{handler="reverse_proxy",host="example.com",rule="lb_geo"} 20
lazybalancer_requests_total{handler="http.handlers.geoip2region",host="example.com",rule="lb_geo"} 20
`
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(text))
	}))
	t.Cleanup(server.Close)
	service := NewMetricsService(server.URL, 30)

	service.collect()

	var requests int64
	if err := db.MetricsDB.QueryRow("SELECT COALESCE(SUM(requests_total),0) FROM metrics_history WHERE rule_id='lb_geo'").Scan(&requests); err != nil {
		t.Fatalf("read per-host metrics: %v", err)
	}
	if requests != 20 {
		t.Fatalf("per-host requests=%d, want 20（geoip 透传序列必须在 per-host 前剔除）", requests)
	}
}
