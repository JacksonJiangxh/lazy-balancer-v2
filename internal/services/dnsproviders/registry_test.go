package dnsproviders

import (
	"strings"
	"testing"
)

// fakeProvider 只实现注册期需要的 Code/Name/ModuleName；其余能力本用例不触达。
type fakeProvider struct {
	BaseProvider
	code string
}

func (p *fakeProvider) Code() string                        { return p.code }
func (p *fakeProvider) Name() string                        { return p.code }
func (p *fakeProvider) ModuleName() string                  { return "module." + p.code }
func (p *fakeProvider) CredentialFields() []CredentialField { return nil }
func (p *fakeProvider) BuildCredentialsJSON(map[string]string) (map[string]interface{}, error) {
	return nil, nil
}

var _ Provider = (*fakeProvider)(nil)

// 重复 Code 是 init 期复制粘贴漏改的典型形态：此前静默覆盖（List 少一项、
// 字段表与 Validate 来自不同实现）。注册期必须 panic 快速失败。
func TestRegister_duplicateCodePanics(t *testing.T) {
	const code = "test-dup-provider-97"
	Register(&fakeProvider{code: code})
	got, ok := Get(code)
	if !ok || got.Code() != code {
		t.Fatalf("首次注册未生效: %v %v", got, ok)
	}

	defer func() {
		recovered := recover()
		if recovered == nil {
			t.Fatal("重复 Code 注册必须 panic（启动期快速失败）")
		}
		if message, _ := recovered.(string); !strings.Contains(message, "duplicate provider code") || !strings.Contains(message, code) {
			t.Fatalf("panic 文案=%v，必须点名 duplicate provider code 与冲突 Code", recovered)
		}
	}()
	Register(&fakeProvider{code: code})
}

// 注册成功且 List 按 Code 排序（map 遍历序不稳定会让响应顺序随进程漂移）。
func TestList_sortedByCode(t *testing.T) {
	list := List()
	if len(list) < 2 {
		t.Fatalf("注册表过小（%d）——扫描面失效", len(list))
	}
	last := ""
	for _, p := range list {
		if p.Code() <= last {
			t.Fatalf("List 未按 Code 严格递增排序: %q 之后是 %q", last, p.Code())
		}
		last = p.Code()
	}
}
