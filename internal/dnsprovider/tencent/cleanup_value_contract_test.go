package tencent

import (
	"strings"
	"testing"
)

// 与 dnspod 侧同构：按值清理的空值必须 fail-fast（ownership 路径 MatchingValue("")
// 退化为按名匹配，内存兜底只选空值条目——同一入参两种语义）。
func TestProvider_CleanUpValue_rejectsEmptyChallengeValue(t *testing.T) {
	provider, err := New("secret-id", "secret-key")
	if err != nil {
		t.Fatalf("create provider: %v", err)
	}
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
