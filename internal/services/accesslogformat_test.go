package services

import (
	"testing"
)

// access_log_format DSL 解析器的四形态矩阵（此前全仓无直接用例，仅经
// handlers 间接消费）：空行忽略、缺箭头/单侧空记非法行号（1-based）、合法行
// 保留原始行号并按两侧 TrimSpace 归一。
func TestParseAccessLogFormat(t *testing.T) {
	cases := []struct {
		name    string
		format  string
		rules   []AccessLogFormatRule
		invalid []int
	}{
		{name: "空串无规则无非法", format: ""},
		{name: "纯空行/空白行忽略", format: "\n   \n\t\n"},
		{name: "单条 delete", format: "remote_ip -> delete", rules: []AccessLogFormatRule{{Line: 1, Path: "remote_ip", Action: "delete"}}},
		{name: "两侧空白归一", format: "  request.headers.X-Token  ->  x_token  ", rules: []AccessLogFormatRule{{Line: 1, Path: "request.headers.X-Token", Action: "x_token"}}},
		{name: "缺箭头记非法", format: "remote_ip delete", invalid: []int{1}},
		{name: "左空记非法", format: " -> delete", invalid: []int{1}},
		{name: "右空记非法", format: "remote_ip -> ", invalid: []int{1}},
		{
			name:    "混合：行号按原始行计（空行占号）",
			format:  "a -> b\n\nbad\nc -> d",
			rules:   []AccessLogFormatRule{{Line: 1, Path: "a", Action: "b"}, {Line: 4, Path: "c", Action: "d"}},
			invalid: []int{3},
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := ParseAccessLogFormat(tc.format)
			if len(got.Rules) != len(tc.rules) {
				t.Fatalf("rules=%v, want %v", got.Rules, tc.rules)
			}
			for i, want := range tc.rules {
				if got.Rules[i] != want {
					t.Fatalf("rule[%d]=%+v, want %+v", i, got.Rules[i], want)
				}
			}
			if len(got.Invalid) != len(tc.invalid) {
				t.Fatalf("invalid=%v, want %v", got.Invalid, tc.invalid)
			}
			for i, want := range tc.invalid {
				if got.Invalid[i] != want {
					t.Fatalf("invalid[%d]=%d, want %d", i, got.Invalid[i], want)
				}
			}
		})
	}
}

// 写侧校验口径：非法行必须带行号被点名（渲染层容忍跳过，写侧 400——两条
// 消费面共享本判据，行号归属错了用户改不到）。
func TestParseAccessLogFormat_invalidLineNumbersAreActionable(t *testing.T) {
	got := ParseAccessLogFormat("a -> b\nno-arrow-here\nc -> d")
	if len(got.Rules) != 2 {
		t.Fatalf("合法行=%v, want 两条", got.Rules)
	}
	if len(got.Invalid) != 1 || got.Invalid[0] != 2 {
		t.Fatalf("非法行号=%v, want [2]", got.Invalid)
	}
}
