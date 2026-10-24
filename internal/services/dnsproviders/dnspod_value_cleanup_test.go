package dnsproviders

// 保存前验证的清理必须按值定向（CleanUpValue），并发验证同一域名时不得删除
// 其他请求仍在使用的探针记录。

import (
	"context"
	"testing"

	"lazy-balancer-v2/internal/dnsprovider"
)

type valueAwareRecordingProvider struct {
	presentValue   string
	cleanupValue   string
	cleanupByName  int
	cleanupByValue int
}

func (p *valueAwareRecordingProvider) Present(_ context.Context, _, _, value string, _ int) error {
	p.presentValue = value
	return nil
}

func (p *valueAwareRecordingProvider) CleanUp(context.Context, string, string) error {
	p.cleanupByName++
	return nil
}

func (p *valueAwareRecordingProvider) CleanUpValue(_ context.Context, _, _, value string) error {
	p.cleanupByValue++
	p.cleanupValue = value
	return nil
}

func TestDNSPod_Validate_cleanupUsesValueAwareCapability(t *testing.T) {
	fake := &valueAwareRecordingProvider{}
	original := newDNSProviderFromCredentials
	newDNSProviderFromCredentials = func(string) (dnsprovider.Provider, error) { return fake, nil }
	t.Cleanup(func() { newDNSProviderFromCredentials = original })

	provider := &DNSPod{}
	credentials := map[string]string{"auth_mode": "dnspod", "app_id": "123", "app_token": "abc"}
	if err := provider.Validate(context.Background(), credentials, "example.com"); err != nil {
		t.Fatalf("validate: %v", err)
	}
	if fake.cleanupByValue != 1 || fake.cleanupByName != 0 {
		t.Fatalf("cleanupByValue=%d cleanupByName=%d, want 1/0（按值定向清理）", fake.cleanupByValue, fake.cleanupByName)
	}
	if fake.cleanupValue == "" || fake.cleanupValue != fake.presentValue {
		t.Fatalf("cleanupValue=%q presentValue=%q, 必须清理本次写入的探针值", fake.cleanupValue, fake.presentValue)
	}
}
