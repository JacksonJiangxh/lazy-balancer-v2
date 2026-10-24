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
