package services

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"lazy-balancer-v2/internal/db"
)

// geoip 透传序列剔除抽成纯函数后按四形态钉字节输出——
// 此前只有 TotalRequests==20 一条断言，分隔符偏差（尾部空行/末行被删/全行
// 被删/无换行）不会被发现。
func TestFilterGeoipPassSeries_shapes(t *testing.T) {
	geo := `caddy_http_requests_total{handler="http.handlers.geoip2region",host="example.com"} 20`
	keep := `caddy_http_requests_total{handler="reverse_proxy",host="example.com"} 20`

	cases := []struct {
		name  string
		input string
		want  string
	}{
		{"no trailing newline", keep + "\n" + geo + "\n" + keep, keep + "\n" + keep},
		{"trailing newline", keep + "\n" + geo + "\n" + keep + "\n", keep + "\n" + keep + "\n"},
		{"deleted last line", keep + "\n" + geo, keep},
		{"all lines deleted", geo + "\n" + geo, ""},
		{"single line no newline", geo, ""},
		{"no match passthrough", keep + "\n" + keep + "\n", keep + "\n" + keep + "\n"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := filterGeoipPassSeries(tc.input); got != tc.want {
				t.Fatalf("filter(%q)=%q, want %q", tc.input, got, tc.want)
			}
		})
	}
}

// 历史修复 联动：过滤后的文本必须同时用于 per-host 存储——此前只断言全局
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
