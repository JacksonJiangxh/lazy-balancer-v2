package services

import "strings"

// 测试专用指标入口（同包测试可访问未导出符号）。产品采集链只走
// aggregatePrometheusText 的单趟双族聚合：全局族与规则族共享一次全文遍历，
// 不存在「先单独解析全局族再解析规则族」的生产调用点。此处两个入口保留给
// 单元测试做目标形状断言，不得被生产代码复用（否则等于在采集链外再造一条
// 解析口径）。

// parsePrometheusMetrics 全局样本解析入口（测试）：单趟扫描。
func (m *MetricsService) parsePrometheusMetrics(text string) (parsedMetrics, error) {
	res := aggregatePrometheusText(text, prometheusScanGlobal)
	if res.globalErr != nil {
		return parsedMetrics{}, res.globalErr
	}
	return res.global, nil
}

// estimateLatencyPercentiles 从 cumulative bucket 直方图估算 p50/p95/p99
// （毫秒，测试）：单趟读取 bucket 行后交给 latencyPercentilesFromBuckets；
// 采集主路径在同一趟聚合里复用后者。
func estimateLatencyPercentiles(text string) (int, int, int, error) {
	byLE := map[float64]int64{}
	for line := range strings.SplitSeq(text, "\n") {
		if !strings.HasPrefix(line, "caddy_http_request_duration_seconds_bucket{") {
			continue
		}
		if err := parsePrometheusBucketSample(line, byLE); err != nil {
			return 0, 0, 0, err
		}
	}
	p50, p95, p99 := latencyPercentilesFromBuckets(byLE)
	return p50, p95, p99, nil
}
