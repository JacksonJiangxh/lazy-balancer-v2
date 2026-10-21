package dnsprovider

import (
	"strings"
	"testing"

	"lazy-balancer-v2/internal/dnsprovider/dnspod"
	"lazy-balancer-v2/internal/dnsprovider/tencent"
)

func TestNewProviderFromCredentials_infers_mode_from_credential_fields(t *testing.T) {
	// Given/When/Then: legacy rows migrated before the mode field existed
	// carry only the credential fields — infer instead of rejecting
	provider, err := NewProviderFromCredentials(`{"api_token":"123,abc"}`)
	if err != nil {
		t.Fatalf("infer dnspod from api_token: %v", err)
	}
	if _, ok := provider.(*dnspod.Provider); !ok {
		t.Fatalf("provider=%T, want *dnspod.Provider", provider)
	}

	provider, err = NewProviderFromCredentials(`{"secret_id":"id","secret_key":"key"}`)
	if err != nil {
		t.Fatalf("infer tencent from secret pair: %v", err)
	}
	if _, ok := provider.(*tencent.Provider); !ok {
		t.Fatalf("provider=%T, want *tencent.Provider", provider)
	}

	// Legacy UI form without auth_mode also infers dnspod from app_id/app_token
	provider, err = NewProviderFromCredentials(`{"app_id":"123","app_token":"abc"}`)
	if err != nil {
		t.Fatalf("infer dnspod from legacy app_id/app_token: %v", err)
	}
	if _, ok := provider.(*dnspod.Provider); !ok {
		t.Fatalf("provider=%T, want *dnspod.Provider", provider)
	}
}

func TestNewProviderFromCredentials_rejects_ambiguous_or_missing_credentials(t *testing.T) {
	// Given/When/Then: both credential families present is ambiguous
	if _, err := NewProviderFromCredentials(`{"api_token":"123,abc","secret_id":"id","secret_key":"key"}`); err == nil {
		t.Fatal("ambiguous credentials must be rejected")
	}
	// No credentials at all
	if _, err := NewProviderFromCredentials(`{}`); err == nil {
		t.Fatal("missing credentials must be rejected")
	}
	// Incomplete secret pair cannot select tencent and has no token either
	if _, err := NewProviderFromCredentials(`{"secret_id":"id"}`); err == nil {
		t.Fatal("incomplete secret pair must be rejected")
	}
}

func TestNewProviderFromCredentials_explicit_mode_still_wins(t *testing.T) {
	// Given/When: explicit mode with matching credentials
	provider, err := NewProviderFromCredentials(`{"mode":"tencent","secret_id":"id","secret_key":"key"}`)
	if err != nil {
		t.Fatalf("explicit mode: %v", err)
	}

	// Then
	if _, ok := provider.(*tencent.Provider); !ok {
		t.Fatalf("provider=%T, want *tencent.Provider", provider)
	}
}

// 历史修复（历史）：空 mode 无法推断时的错误文案必须可诊断分流——两类凭证
// 并存=歧义（需显式 mode 消歧），全缺/不完整=缺失（需补齐凭证）。原实现两者
// 同落 default 的「unsupported dns provider mode: 」（mode 为空），排障无法区分。
func TestNewProviderFromCredentials_emptyModeErrorDistinguishesAmbiguityFromMissing(t *testing.T) {
	_, ambiguousErr := NewProviderFromCredentials(`{"api_token":"123,abc","secret_id":"id","secret_key":"key"}`)
	if ambiguousErr == nil {
		t.Fatal("ambiguous credentials must be rejected")
	}
	_, missingErr := NewProviderFromCredentials(`{}`)
	if missingErr == nil {
		t.Fatal("missing credentials must be rejected")
	}
	if ambiguousErr.Error() == missingErr.Error() {
		t.Fatalf("歧义与缺失必须给出不同文案, both=%q", ambiguousErr.Error())
	}
	if !strings.Contains(ambiguousErr.Error(), "歧义") {
		t.Fatalf("歧义文案须含「歧义」, got %q", ambiguousErr.Error())
	}
	if !strings.Contains(missingErr.Error(), "缺失") {
		t.Fatalf("缺失文案须含「缺失」, got %q", missingErr.Error())
	}
	// 显式未知 mode 仍走原 unsupported 文案（非空 mode 不进歧义/缺失分流）。
	if _, err := NewProviderFromCredentials(`{"mode":"route53","api_token":"1,2"}`); err == nil ||
		!strings.Contains(err.Error(), "unsupported dns provider mode") {
		t.Fatalf("显式未知 mode 须保留原 unsupported 文案, got %v", err)
	}
}

// 历史问题（历史）：UI 形态（auth_mode + app_id/app_token 等）是唯一真相——
// 游离的消费层 mode 字段不得压过它。否则「保存前凭证测试」（UI 形态）与
// 真实签发（mode 优先）会使用两套不同凭据，验证结论不覆盖实际链路。
func TestNewProviderFromCredentials_authModeOverridesStrayMode(t *testing.T) {
	provider, err := NewProviderFromCredentials(`{"auth_mode":"dnspod","app_id":"123","app_token":"abc","mode":"tencent","secret_id":"sid","secret_key":"skey"}`)
	if err != nil {
		t.Fatalf("credentials with stray mode: %v", err)
	}
	dnspodProvider, ok := provider.(*dnspod.Provider)
	if !ok {
		t.Fatalf("provider=%T, want *dnspod.Provider（auth_mode 优先）", provider)
	}
	if dnspodProvider.LoginToken != "123,abc" {
		t.Fatalf("login token=%q, want 123,abc（UI 字段为凭据真相）", dnspodProvider.LoginToken)
	}
}

// 历史问题：UI 形态的 app_id/app_token 必须覆盖陈旧 api_token（掩码合并后
// 两形态并存的短暂状态），保证校验与签发使用同一组凭据。
func TestNewProviderFromCredentials_uiFieldsOverrideStaleAPIToken(t *testing.T) {
	provider, err := NewProviderFromCredentials(`{"auth_mode":"dnspod","api_token":"old,old","app_id":"123","app_token":"abc"}`)
	if err != nil {
		t.Fatalf("credentials with stale api_token: %v", err)
	}
	dnspodProvider, ok := provider.(*dnspod.Provider)
	if !ok {
		t.Fatalf("provider=%T, want *dnspod.Provider", provider)
	}
	if dnspodProvider.LoginToken != "123,abc" {
		t.Fatalf("login token=%q, want 123,abc（app_id/app_token 优先）", dnspodProvider.LoginToken)
	}
}
