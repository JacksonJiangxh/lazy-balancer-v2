package services

// 第 76 轮 CERT 域冗余收敛：剩余天数口径单一出口钉。原 certjobs/certinfo/
// certificates/admintls/helpers 五份同表达式（R66/R67 已统一为向零截断），
// CertDaysRemaining 固化单一出口——回归口径：未过期 23h→0、恰好 48h→2、
// 过期 1 天 3 小时→-1（向零截断非 floor 的判别形态：-27h→-1 而 floor 会
// 给 -2）；过期判定不以返回值 ≤0 兼判（-1h→0）。

import (
	"testing"
	"time"
)

func TestCertDaysRemaining_truncationTowardZero(t *testing.T) {
	now := time.Date(2026, 10, 15, 12, 0, 0, 0, time.UTC)
	cases := []struct {
		name   string
		offset time.Duration
		want   int
	}{
		{"未过期23小时向零截断为0", 23 * time.Hour, 0},
		{"恰好48小时为2", 48 * time.Hour, 2},
		{"过期1小时仍为0", -1 * time.Hour, 0},
		{"过期27小时为-1非floor", -27 * time.Hour, -1},
		{"恰好48小时前为-2", -48 * time.Hour, -2},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := CertDaysRemaining(now.Add(tc.offset), now); got != tc.want {
				t.Fatalf("CertDaysRemaining(offset=%v)=%d, want %d", tc.offset, got, tc.want)
			}
		})
	}
}
