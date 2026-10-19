package dnsproviders

import (
	"context"
	"strings"
	"testing"

	"lazy-balancer-v2/internal/dnsprovider"
)

// recordingDNSProvider 记录 provider 调用收到的 zone/FQDN（历史问题：输入域用于
// challenge FQDN，可注册根域用于 provider 调用）。
type recordingDNSProvider struct {
	presentZone  string
	presentFQDN  string
	cleanupZone  string
	cleanupFQDN  string
	presentCalls int
}

func (p *recordingDNSProvider) Present(_ context.Context, zone, tokenFQDN, _ string, _ int) error {
	p.presentZone = zone
	p.presentFQDN = tokenFQDN
	p.presentCalls++
	return nil
}

func (p *recordingDNSProvider) CleanUp(_ context.Context, zone, tokenFQDN string) error {
	p.cleanupZone = zone
	p.cleanupFQDN = tokenFQDN
	return nil
}

// 历史问题：DNSPod 凭证校验不得把用户输入整体当 zone——www 子域必须解析到可注册
// 根域（PSL），challenge FQDN 仍基于完整输入域，否则账户只管理 example.com 时
// 校验误报「domain not found」。
func TestDNSPod_Validate_usesRegisteredZoneForProviderCalls(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		wantZone string
		wantFQDN string
	}{
		{
			name:     "subdomain resolves to registered zone",
			input:    "www.example.com",
			wantZone: "example.com",
			wantFQDN: "_acme-challenge.lb-test.www.example.com.",
		},
		{
			name:     "two-level suffix",
			input:    "api.example.co.uk",
			wantZone: "example.co.uk",
			wantFQDN: "_acme-challenge.lb-test.api.example.co.uk.",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			fake := &recordingDNSProvider{}
			original := newDNSProviderFromCredentials
			newDNSProviderFromCredentials = func(string) (dnsprovider.Provider, error) { return fake, nil }
			t.Cleanup(func() { newDNSProviderFromCredentials = original })

			provider := &DNSPod{}
			credentials := map[string]string{"auth_mode": "dnspod", "app_id": "123", "app_token": "abc"}
			if err := provider.Validate(credentials, tt.input); err != nil {
				t.Fatalf("validate %q: %v", tt.input, err)
			}
			if fake.presentZone != tt.wantZone {
				t.Fatalf("Present zone=%q, want %q（provider 调用须用可注册根域）", fake.presentZone, tt.wantZone)
			}
			if fake.presentFQDN != tt.wantFQDN {
				t.Fatalf("Present FQDN=%q, want %q（challenge 名须基于完整输入域）", fake.presentFQDN, tt.wantFQDN)
			}
			if fake.cleanupZone != tt.wantZone || fake.cleanupFQDN != tt.wantFQDN {
				t.Fatalf("CleanUp zone/FQDN=%q/%q, want %q/%q", fake.cleanupZone, fake.cleanupFQDN, tt.wantZone, tt.wantFQDN)
			}
		})
	}
}

func TestDNSPod_Validate_rejects_whitespace_test_domain(t *testing.T) {
	// Given
	provider := &DNSPod{}
	credentials := map[string]string{"auth_mode": "dnspod", "app_id": "123", "app_token": "abc"}

	// When
	err := provider.Validate(credentials, "   ")

	// Then
	if err == nil || !strings.Contains(err.Error(), "测试域名不能为空") {
		t.Fatalf("validation error=%v, want empty-domain error", err)
	}
}

// 凭证字段的可见性/选项文案元数据（WS-13）：前端表单由 visible_when/
// option_labels 驱动（不再按 dnspod 两种认证模式硬编码字段名）。本测试钉住
// DNSPod 的元数据形态，并反向校验每个 visible_when 条件键都是同 provider 声明的
// select 字段（引用错键会让字段永远不显示）。
func TestDNSPod_CredentialFieldMetadata(t *testing.T) {
	fields := (&DNSPod{}).CredentialFields()
	byName := make(map[string]CredentialField, len(fields))
	for _, f := range fields {
		byName[f.Name] = f
	}

	authMode, ok := byName["auth_mode"]
	if !ok {
		t.Fatalf("DNSPod 缺 auth_mode 字段: %#v", fields)
	}
	if authMode.Type != "select" {
		t.Fatalf("auth_mode type=%q, want select", authMode.Type)
	}
	if got, want := authMode.OptionLabels["dnspod"], "DNSPod API"; got != want {
		t.Errorf("auth_mode option_labels[dnspod]=%q, want %q", got, want)
	}
	if got, want := authMode.OptionLabels["tencent_cloud"], "腾讯云 API"; got != want {
		t.Errorf("auth_mode option_labels[tencent_cloud]=%q, want %q", got, want)
	}

	cases := []struct {
		field string
		mode  string
	}{
		{"app_id", "dnspod"},
		{"app_token", "dnspod"},
		{"secret_id", "tencent_cloud"},
		{"secret_key", "tencent_cloud"},
	}
	for _, tc := range cases {
		f, ok := byName[tc.field]
		if !ok {
			t.Fatalf("DNSPod 缺字段 %q", tc.field)
		}
		modes, ok := f.VisibleWhen["auth_mode"]
		if !ok || len(modes) != 1 || modes[0] != tc.mode {
			t.Errorf("%s VisibleWhen=%v, want {auth_mode:[%s]}", tc.field, f.VisibleWhen, tc.mode)
		}
	}

	// 反向校验：visible_when 的每个条件键必须是已声明的 select 字段。
	for _, f := range fields {
		for key := range f.VisibleWhen {
			cond, ok := byName[key]
			if !ok {
				t.Errorf("%s VisibleWhen 引用未声明字段 %q", f.Name, key)
				continue
			}
			if cond.Type != "select" {
				t.Errorf("%s VisibleWhen 条件字段 %q type=%q, want select", f.Name, key, cond.Type)
			}
		}
	}
}
