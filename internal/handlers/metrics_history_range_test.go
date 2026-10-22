package handlers

import "testing"

// 规则历史端点与全局历史端点的分桶口径必须单源：同窗口秒数 / 720 桶。
// 7d 曾两端各写一份桶宽（900s vs 840s），同一时间窗返回不同粒度序列。
func TestMetricsHistoryRangeBucketsMatchGlobalEndpoint(t *testing.T) {
	cases := []struct {
		rangeParam     string
		normalized     string
		wantBucketSecs int
	}{
		{"1h", "1h", 5},
		{"6h", "6h", 30},
		{"24h", "24h", 120},
		{"7d", "7d", 840},
		// 缺省/非法/超窗一律回退 24h（与 GET /metrics/history 的同一窗口比对）。
		{"", "24h", 120},
		{"30d", "24h", 120},
		{"bogus", "24h", 120},
	}
	for _, tc := range cases {
		modifier, bucketSeconds, buckets := metricsHistoryRange(tc.rangeParam)
		if buckets != metricsHistoryBuckets {
			t.Fatalf("range=%q 桶数=%d, want %d", tc.rangeParam, buckets, metricsHistoryBuckets)
		}
		if bucketSeconds != tc.wantBucketSecs {
			t.Fatalf("range=%q 桶宽=%ds, want %ds", tc.rangeParam, bucketSeconds, tc.wantBucketSecs)
		}
		// 与 GetMetricsHistory 的派生完全一致（parseMetricsInterval / 桶数）。
		_, windowSeconds := parseMetricsInterval(tc.normalized)
		if want := int(windowSeconds / metricsHistoryBuckets); bucketSeconds != want {
			t.Fatalf("range=%q 桶宽=%ds 与全局端点派生 %ds 不一致", tc.rangeParam, bucketSeconds, want)
		}
		if modifier != "-"+tc.normalized[:len(tc.normalized)-1]+map[byte]string{'h': " hours", 'd': " days"}[tc.normalized[len(tc.normalized)-1]] {
			t.Fatalf("range=%q modifier=%q 与窗口不匹配", tc.rangeParam, modifier)
		}
	}
}
