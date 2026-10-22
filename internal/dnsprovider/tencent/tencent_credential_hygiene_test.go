package tencent

import (
	"fmt"
	"strings"
	"testing"
)

// String/%+v 任何形态都不得回显凭据（与 dnspod.Provider 同口径——导出字段
// 时代任何一次日志/序列化即泄密）。
func TestProvider_StringRedactsCredential(t *testing.T) {
	provider, err := New("test-secret-id", "test-secret-key")
	if err != nil {
		t.Fatalf("new provider: %v", err)
	}
	for _, form := range []string{fmt.Sprintf("%s", provider), fmt.Sprintf("%+v", provider), provider.String()} {
		if strings.Contains(form, "test-secret-id") || strings.Contains(form, "test-secret-key") {
			t.Fatalf("字符串形态泄露凭据: %q", form)
		}
	}
	if !strings.Contains(provider.String(), provider.account) {
		t.Fatalf("脱敏形态应保留账户摘要以便排障: %q", provider.String())
	}
}
