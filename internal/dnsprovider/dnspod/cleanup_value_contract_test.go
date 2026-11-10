package dnspod

import (
	"strings"
	"testing"
)

// 按值清理的空值语义在 ownership 路径（按名匹配→删同名全部）与内存兜底路径
// （只选空值条目）相反：入口必须 fail-fast，把「按名清理」限定在 CleanUp，
// 避免未来空值调用误删并发挑战的 TXT。
func TestProvider_CleanUpValue_rejectsEmptyChallengeValue(t *testing.T) {
	provider := New("id,token")
	for _, value := range []string{"", "   "} {
		err := provider.CleanUpValue(t.Context(), "example.com", "_acme-challenge.example.com.", value)
		if err == nil {
			t.Fatalf("CleanUpValue(%q) = nil, want 非空挑战值校验错误", value)
		}
		if !strings.Contains(err.Error(), "非空挑战值") {
			t.Fatalf("CleanUpValue(%q) error=%v, want 点名非空挑战值", value, err)
		}
	}
}
