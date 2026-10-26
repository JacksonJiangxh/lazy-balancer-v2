package dnsname

import "testing"

// 归一单源的行为表：三个消费者（ACME 权威应答比较、挑战登记键、清理账本）
// 对同一输入必须得到同一结果。连续尾点只去掉一个（畸形输入留给上层拒绝）。
func TestNormalizeName(t *testing.T) {
	for _, tc := range []struct{ in, want string }{
		{"example.com", "example.com"},
		{"Example.COM", "example.com"},
		{"  example.com  ", "example.com"},
		{"example.com.", "example.com"},
		{"Example.COM.", "example.com"},
		{"_acme-challenge.example.com.", "_acme-challenge.example.com"},
		{"example.com..", "example.com."},
		{"", ""},
		{".", ""},
	} {
		if got := NormalizeName(tc.in); got != tc.want {
			t.Errorf("NormalizeName(%q)=%q, want %q", tc.in, got, tc.want)
		}
	}
}

// 相对子域派生（provider API 的 sub_domain）：zone 与 FQDN 的书写形态（大小写/
// 尾点/首尾空白）都不得影响结果——保存前探针传小写 zone + 输入原样 FQDN。
func TestRelativeTo(t *testing.T) {
	for _, tc := range []struct{ name, zone, want string }{
		{"_acme-challenge.example.com.", "example.com.", "_acme-challenge"},
		{"_acme-challenge.www.example.com", "example.com", "_acme-challenge.www"},
		{"_acme-challenge.lb-test.Example.COM.", "example.com", "_acme-challenge.lb-test"},
		{"_ACME-Challenge.lb-test.example.com.", "Example.COM.", "_acme-challenge.lb-test"},
		{"  _acme-challenge.example.com  ", " example.com ", "_acme-challenge"},
		// 不属于 zone 的名字原样返回归一形态（归属校验由调用方负责）。
		{"_acme-challenge.other.net.", "example.com", "_acme-challenge.other.net"},
		{"_acme-challenge.example.com.", "", "_acme-challenge.example.com"},
	} {
		if got := RelativeTo(tc.name, tc.zone); got != tc.want {
			t.Errorf("RelativeTo(%q, %q)=%q, want %q", tc.name, tc.zone, got, tc.want)
		}
	}
}
