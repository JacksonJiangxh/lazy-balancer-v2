package handlers

import (
	"strings"
	"testing"
)

// geoip 透传路由（无 reverse_proxy）与主/路径路由会为同一请求各记一条指标
// 序列。采集链按 services.IsGeoIPPassSeries 整行剔除；实时指标解析此前
// 未剔除，导致首页「总请求数/流量/状态码分布」在启用 GeoIP 的规则上翻倍，
// 并与同页采集链来源的速率卡矛盾。本用例钉住两条链同口径（共用同一判据）。
func TestParsePrometheusMetrics_skipsGeoIPPassSeries(t *testing.T) {
	body := strings.Join([]string{
		`caddy_http_requests_total{handler="reverse_proxy",host="example.com"} 9`,
		`caddy_http_requests_total{handler="http.handlers.geoip2region",host="example.com"} 9`,
		`caddy_http_requests_in_flight{handler="reverse_proxy",host="example.com"} 3`,
		`caddy_http_requests_in_flight{handler="http.handlers.geoip2region",host="example.com"} 3`,
	}, "\n")

	metrics, err := parsePrometheusMetrics(body)
	if err != nil {
		t.Fatalf("parse metrics: %v", err)
	}
	if metrics.RequestsTotal != 9 || metrics.RequestsInFlight != 3 {
		t.Fatalf("全局指标 requestsTotal=%d inFlight=%d, want 9/3（透传序列不得计入）",
			metrics.RequestsTotal, metrics.RequestsInFlight)
	}

	hosts, err := parseHostMetrics(body)
	if err != nil {
		t.Fatalf("parse host metrics: %v", err)
	}
	if len(hosts) != 1 {
		t.Fatalf("host 维度条目数=%d, want 1", len(hosts))
	}
	if hosts[0].RequestsTotal != 9 || hosts[0].RequestsInFlight != 3 {
		t.Fatalf("per-host requestsTotal=%d inFlight=%d, want 9/3",
			hosts[0].RequestsTotal, hosts[0].RequestsInFlight)
	}
}
