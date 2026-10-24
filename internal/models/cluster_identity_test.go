package models

import (
	"database/sql"
	"encoding/json"
	"strings"
	"testing"
	"time"
	"unicode/utf8"
)

// 节点名归一：去首尾空白、剥离 C0/DEL/C1 控制字符与 Cf 格式字符、按
// VARCHAR(100) 上限截断到合法 UTF-8 边界。此前该函数（含 C1 剥离修复）零覆盖
// ——回归无人拦。
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
		// Cf 格式字符：双向覆盖可让 "主节点\u202E-xx" 在列表/审计里视觉重排、
		// 与真实主节点名混淆；零宽空格/BOM 则可伪造同名视觉。
		{name: "strip bidi override", in: "主节点\u202e-xx", want: "主节点-xx"},
		{name: "strip bidi isolate", in: "node\u2066\u2069-1", want: "node-1"},
		{name: "strip zero width", in: "no\u200bde\u200e-1", want: "node-1"},
		{name: "strip BOM", in: "\ufeffnode-1", want: "node-1"},
		// ZWJ 是 emoji 组合的合法组成，不得被当作格式字符剥掉。
		{name: "keep ZWJ", in: "节点\u200d01", want: "节点\u200d01"},
		// 例外字符单独构成名字 = 视觉空名：ZWJ 无可见基字符时必须归一到空
		// （调用方按无效名 400），而带可见字符时的 ZWJ 仍保留。
		{name: "only ZWJ becomes empty", in: "\u200d", want: ""},
		{name: "ZWJ with spaces becomes empty", in: "  \u200d \u200d  ", want: ""},
		{name: "trailing ZWJ after visible char kept", in: "节点\u200d", want: "节点\u200d"},
		{name: "only whitespace becomes empty", in: " \t\n\x00 ", want: ""},
		// 视觉空白填充字形（非 Cf、非 unicode.IsSpace）：整名只由它们组成时
		// 在列表/审计里是一行空白，必须归一到空；混在可见名里则直接剥离。
		{name: "braille blank becomes empty", in: "\u2800", want: ""},
		{name: "hangul filler becomes empty", in: "\u3164", want: ""},
		{name: "braille blank with spaces becomes empty", in: "  \u2800  ", want: ""},
		{name: "halfwidth hangul filler becomes empty", in: "\uffa0\uffa0", want: ""},
		{name: "blank glyphs stripped from visible name", in: "\u2800nodes\u3164", want: "nodes"},
		{name: "blank glyphs before visible char keep the char", in: strings.Repeat("\u2800", ClusterNodeNameMaxLen) + "a", want: "a"},
		// 顺序缺口：截断可能把可见字符裁掉、只剩隐形字符（判据必须在截断后）。
		{name: "truncation leaving only ZWJ becomes empty", in: strings.Repeat("\u200d", ClusterNodeNameMaxLen) + "a", want: ""},
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
