package dnsproviders

import (
	"context"
	"errors"
	"strings"
	"testing"

	"lazy-balancer-v2/internal/dnsprovider"
)

func TestDNSPodCredentials(t *testing.T) {
	p, ok := Get("dnspod")
	if !ok {
		t.Fatal("dnspod not registered")
	}
	_, err := p.BuildCredentialsJSON(map[string]string{})
	if err == nil {
		t.Fatal("expected error for empty credentials")
	}
	creds, err := p.BuildCredentialsJSON(map[string]string{"auth_mode": "dnspod", "app_id": "123", "app_token": "abc"})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if creds["api_token"] != "123,abc" {
		t.Fatalf("expected api_token 123,abc, got %v", creds["api_token"])
	}
	tencent, err := p.BuildCredentialsJSON(map[string]string{"auth_mode": "tencent_cloud", "secret_id": "sid", "secret_key": "skey"})
	if err != nil {
		t.Fatalf("unexpected error for tencent cloud: %v", err)
	}
	// tencent canonical 不再携带死字段 api_token(消费端只读
	// secret_id/secret_key)。
	if _, exists := tencent["api_token"]; exists {
		t.Fatalf("tencent canonical must not carry dead api_token, got %v", tencent)
	}
}

type cleanupFailingProvider struct{}

func (cleanupFailingProvider) Present(context.Context, string, string, string, int) error { return nil }
func (cleanupFailingProvider) CleanUp(context.Context, string, string) error {
	return errors.New("cleanup failed")
}

func TestDNSPod_Validate_returns_cleanup_error(t *testing.T) {
	// Given
	originalFactory := newDNSProviderFromCredentials
	newDNSProviderFromCredentials = func(string) (dnsprovider.Provider, error) {
		return cleanupFailingProvider{}, nil
	}
	t.Cleanup(func() { newDNSProviderFromCredentials = originalFactory })
	provider := &DNSPod{}

	// When
	err := provider.Validate(context.Background(), map[string]string{"auth_mode": "dnspod", "app_id": "123", "app_token": "abc"}, "example.com")

	// Then
	if err == nil || !strings.Contains(err.Error(), "cleanup failed") {
		t.Fatalf("cleanup error=%v, want cleanup failure", err)
	}
}

// 原断言 len(List())==1 既是脆性计数（新增任何 DNS
// 提供商即失败），又不验证注册表语义。改为钉「Get 命中 + List 含 dnspod + List
// 非空 + 按 Code 升序」。
func TestListProviders(t *testing.T) {
	provider, ok := Get("dnspod")
	if !ok || provider == nil {
		t.Fatal("dnspod must be registered")
	}
	if provider.Code() != "dnspod" {
		t.Fatalf("Get(dnspod).Code()=%q, want dnspod", provider.Code())
	}
	if _, ok := Get("no-such-provider"); ok {
		t.Fatal("unknown provider code must not resolve")
	}
	list := List()
	if len(list) == 0 {
		t.Fatal("List() must not be empty")
	}
	found := false
	for i, item := range list {
		if item.Code() == "dnspod" {
			found = true
		}
		if i > 0 && list[i-1].Code() > item.Code() {
			t.Fatalf("List() codes=%v, want 按 Code 升序", []string{list[i-1].Code(), item.Code()})
		}
	}
	if !found {
		t.Fatalf("List() must include dnspod, got %d providers", len(list))
	}
}
