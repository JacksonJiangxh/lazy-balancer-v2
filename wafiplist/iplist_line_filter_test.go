package wafiplist

import "testing"

// 行过滤单一事实源：跳过空行与 #/; 注释、TrimSpace 归一（CRLF 同口径），
// 行号按物理行从 1 起计（错误文案用），回调返回 false 立即终止。
func TestForEachIPListLine_skipsCommentsAndReportsPhysicalLineNumbers(t *testing.T) {
	raw := []byte("# comment\r\n\n 10.0.0.0/8 \n; semicolon\r\n192.168.0.1")

	type seen struct {
		no   int
		line string
	}
	var got []seen
	ForEachIPListLine(raw, func(no int, line string) bool {
		got = append(got, seen{no, line})
		return true
	})
	want := []seen{{3, "10.0.0.0/8"}, {5, "192.168.0.1"}}
	if len(got) != len(want) {
		t.Fatalf("有效行=%v, want %v", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("第 %d 个有效行=%+v, want %+v", i, got[i], want[i])
		}
	}

	calls := 0
	ForEachIPListLine(raw, func(int, string) bool {
		calls++
		return false
	})
	if calls != 1 {
		t.Fatalf("回调返回 false 必须立即终止，实际调用 %d 次", calls)
	}
}
