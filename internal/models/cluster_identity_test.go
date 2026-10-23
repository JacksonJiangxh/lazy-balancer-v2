package models

import (
	"database/sql"
	"encoding/json"
	"strings"
	"testing"
	"time"
	"unicode/utf8"
)

// 节点名归一：去首尾空白、剥离 C0/DEL/C1 控制字符、按 VARCHAR(100) 上限截断
// 到合法 UTF-8 边界。此前该函数（含 C1 剥离修复）零覆盖——回归无人拦。
func TestNormalizeClusterNodeName(t *testing.T) {
	long := strings.Repeat("名", ClusterNodeNameMaxLen+1)
	for _, tc := range []struct {
		name string
		in   string
		want string
	}{
		{name: "trim surrounding spaces", in: "  node-1\t\n", want: "node-1"},
		{name: "keep inner spaces", in: " edge node ", want: "edge node"},
		{name: "strip C0", in: "no\x00de\x1f-1", want: "node-1"},
		{name: "strip DEL", in: "node\x7f-1", want: "node-1"},
		{name: "strip C1", in: "node\u0085\u009f-1", want: "node-1"},
		{name: "only whitespace becomes empty", in: " \t\n\x00 ", want: ""},
		{name: "exact limit kept", in: strings.Repeat("a", ClusterNodeNameMaxLen), want: strings.Repeat("a", ClusterNodeNameMaxLen)},
		{name: "over limit truncated by rune", in: long, want: strings.Repeat("名", ClusterNodeNameMaxLen)},
		{name: "unicode kept", in: "节点-东京-01", want: "节点-东京-01"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got := NormalizeClusterNodeName(tc.in)
			if got != tc.want {
				t.Fatalf("NormalizeClusterNodeName(%q)=%q, want %q", tc.in, got, tc.want)
			}
			if !utf8.ValidString(got) {
				t.Fatalf("归一结果必须是合法 UTF-8: %q", got)
			}
			if n := utf8.RuneCountInString(got); n > ClusterNodeNameMaxLen {
				t.Fatalf("归一结果 %d rune 超出上限 %d", n, ClusterNodeNameMaxLen)
			}
		})
	}

	// 归一后为空 = 调用方必须拒绝（ErrInvalidClusterNodeName 是 handler 的
	// 400 文案来源）：空白/纯控制字符不得静默落成空名行。
	if got := NormalizeClusterNodeName(" \x00\x7f "); got != "" {
		t.Fatalf("纯控制字符 + 空白应归一为空串，got %q", got)
	}
}

// 信任锚的 IPv6/映射形态：方括号主机、IPv4-mapped 地址都必须按 IP 等价比较，
// 不同族/不同地址不得误判一致。
func TestClusterAccessURLHostMatchesIPIPv6Shapes(t *testing.T) {
	for _, tc := range []struct {
		name    string
		access  string
		ip      string
		matches bool
	}{
		{name: "loopback bracket host", access: "https://[::1]:8443", ip: "::1", matches: true},
		{name: "ipv4-mapped equals ipv4", access: "https://[::ffff:203.0.113.7]:443", ip: "203.0.113.7", matches: true},
		{name: "loopback vs ipv4 loopback", access: "https://[::1]:443", ip: "127.0.0.1", matches: false},
		{name: "bracket host without port", access: "https://[2001:db8::2]", ip: "2001:db8::2", matches: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := ClusterAccessURLHostMatchesIP(tc.access, tc.ip); got != tc.matches {
				t.Fatalf("ClusterAccessURLHostMatchesIP(%q,%q)=%v, want %v", tc.access, tc.ip, got, tc.matches)
			}
		})
	}
}

// JSONNullTime 反序列化是集群快照（ClusterCertificate.ExpiresAt/
// CAAvailableAfter）的解码路径：null/合法 RFC3339/畸形三种形状都必须有确定
// 行为。此前只有序列化侧覆盖。
func TestJSONNullTimeUnmarshalJSON(t *testing.T) {
	t.Run("null clears value", func(t *testing.T) {
		value := JSONNullTime{NullTime: sql.NullTime{Time: time.Now(), Valid: true}}
		if err := json.Unmarshal([]byte("null"), &value); err != nil {
			t.Fatalf("null: %v", err)
		}
		if value.Valid || !value.Time.IsZero() {
			t.Fatalf("null 应清空为无效值，got valid=%v time=%v", value.Valid, value.Time)
		}
	})
	t.Run("rfc3339 sets value", func(t *testing.T) {
		var value JSONNullTime
		if err := json.Unmarshal([]byte(`"2026-10-23T08:30:00Z"`), &value); err != nil {
			t.Fatalf("rfc3339: %v", err)
		}
		if !value.Valid {
			t.Fatal("合法时间应为有效值")
		}
		if want := time.Date(2026, 10, 23, 8, 30, 0, 0, time.UTC); !value.Time.Equal(want) {
			t.Fatalf("解析结果=%v, want %v", value.Time, want)
		}
	})
	t.Run("malformed rejected", func(t *testing.T) {
		for _, raw := range []string{`""`, `"not-a-time"`, `20261023`, `{"Time":"2026-10-23T08:30:00Z"}`} {
			var value JSONNullTime
			if err := json.Unmarshal([]byte(raw), &value); err == nil {
				t.Fatalf("畸形输入 %s 必须报错，got valid=%v time=%v", raw, value.Valid, value.Time)
			}
			if value.Valid {
				t.Fatalf("畸形输入 %s 不得置为有效值", raw)
			}
		}
	})
}
