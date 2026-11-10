package services

import (
	"reflect"
	"testing"
)

// iterIPListTextLines 是渲染/UI/下载/编译四处的行过滤单源。切分实现从
// strings.Split 改为 bytes.IndexByte 原地扫描后，语义必须逐形态保持等价：
// 空文本、仅注释、空行、CRLF、无尾换行、行首空白、提前终止。
func TestIterIPListTextLines_semantics(t *testing.T) {
	cases := []struct {
		name string
		raw  string
		want []string
	}{
		{name: "empty", raw: "", want: nil},
		{name: "only newlines", raw: "\n\n\n", want: nil},
		{name: "comments only", raw: "# header\n; note\n  # indented\n", want: nil},
		{name: "entries", raw: "1.1.1.0/24\n2.2.2.2\n", want: []string{"1.1.1.0/24", "2.2.2.2"}},
		{name: "no trailing newline", raw: "1.1.1.0/24\n2.2.2.2", want: []string{"1.1.1.0/24", "2.2.2.2"}},
		{name: "crlf", raw: "1.1.1.0/24\r\n# x\r\n2.2.2.2\r\n", want: []string{"1.1.1.0/24", "2.2.2.2"}},
		{name: "leading and trailing spaces", raw: "  1.1.1.0/24  \n\t2.2.2.2\t\n", want: []string{"1.1.1.0/24", "2.2.2.2"}},
		{name: "blank between entries", raw: "1.1.1.0/24\n\n\n2.2.2.2\n", want: []string{"1.1.1.0/24", "2.2.2.2"}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			var got []string
			iterIPListTextLines([]byte(tc.raw), func(line string) bool {
				got = append(got, line)
				return true
			})
			if !reflect.DeepEqual(got, tc.want) {
				t.Fatalf("lines=%v, want %v", got, tc.want)
			}
		})
	}

	// 提前终止：回调返回 false 后不再消费后续行。
	var seen []string
	iterIPListTextLines([]byte("1.1.1.0/24\n2.2.2.2\n3.3.3.3\n"), func(line string) bool {
		seen = append(seen, line)
		return false
	})
	if !reflect.DeepEqual(seen, []string{"1.1.1.0/24"}) {
		t.Fatalf("early stop saw=%v, want 仅首行", seen)
	}
}
