package dnsproviders

import (
	"context"
	"sort"
)

type CredentialField struct {
	Name        string `json:"name"`
	Label       string `json:"label"`
	Type        string `json:"type"`
	Required    bool   `json:"required"`
	Placeholder string `json:"placeholder,omitempty"`
	// VisibleWhen 声明字段可见性：{其它字段名: 允许取值}，全部条件命中才显示。
	// 前端据此渲染表单——原前端按 dnspod 的两种认证模式
	// 硬编码可见字段，后端新增 provider 时其 credential_fields 会被整体隐藏。
	// 为空 = 恒显示。
	VisibleWhen map[string][]string `json:"visible_when,omitempty"`
	// OptionLabels 为 select 字段的选项显示文案（值 → 文案）；缺失时前端回退
	// 原始值，不再硬编码到具体 provider。
	OptionLabels map[string]string `json:"option_labels,omitempty"`
}

type Provider interface {
	Code() string
	Name() string
	ModuleName() string
	CredentialFields() []CredentialField
	CredentialFieldOptions(field string) []string
	BuildCredentialsJSON(creds map[string]string) (map[string]interface{}, error)
	// Validate 以调用方请求 ctx 为上界执行保存前验证：客户端断开/超时必须
	// 立刻中止写入探测，不得跑满内部预算。
	Validate(ctx context.Context, creds map[string]string, testDomain string) error
}

type BaseProvider struct{}

func (b *BaseProvider) CredentialFieldOptions(field string) []string { return nil }

func (b *BaseProvider) Validate(ctx context.Context, creds map[string]string, testDomain string) error {
	return nil
}

var registry = map[string]Provider{}

func Register(p Provider) {
	registry[p.Code()] = p
}

func Get(code string) (Provider, bool) {
	p, ok := registry[code]
	return p, ok
}

func List() []Provider {
	list := make([]Provider, 0, len(registry))
	for _, p := range registry {
		list = append(list, p)
	}
	// map 遍历序不确定,/dns-providers 响应顺序随进程
	// 随机——按 Code(注册表键,唯一)排序输出稳定切片。
	sort.Slice(list, func(i, j int) bool { return list[i].Code() < list[j].Code() })
	return list
}
