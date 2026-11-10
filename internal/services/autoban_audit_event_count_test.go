package services

// 「今日封禁」折算的单源判据：汇总行携带本轮总数（前缀后的整数），逐 IP 行与
// 历史文案各计 1——无法识别的形态按 1 计是保守方向（不凭空放大统计）。

import "testing"

func TestAutobanAuditEventCount_shapes(t *testing.T) {
	cases := map[string]struct {
		detail string
		want   int
	}{
		"逐-IP 行": {detail: "IP：198.51.100.1；命中：5 次/10 分钟；结果：成功", want: 1},
		"汇总行":    {detail: "汇总：其余 300 个 IP 省略逐条记录（本轮共 800 个 IP，逐条上限 500；完整名单见预置 IP 列表）", want: 300},
		// 历史汇总文案（无机器可读前缀）不解析数字：按 1 计，保守方向。
		"历史汇总文案":   {detail: "本轮自动封禁共 800 个 IP，逐 IP 审计超过单轮上限 500，其余 300 个省略逐条记录（完整名单见预置 IP 列表）", want: 1},
		"空前缀数字":    {detail: "汇总：", want: 1},
		"空 detail": {detail: "", want: 1},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			if got := autobanAuditEventCount(tc.detail); got != tc.want {
				t.Fatalf("autobanAuditEventCount(%q)=%d, want %d", tc.detail, got, tc.want)
			}
		})
	}
}
