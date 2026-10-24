package dnsproviders

// 保存前验证的 CleanUp 独立预算与随机探针值。

import (
	"context"
	"strings"
	"testing"
	"time"

	"lazy-balancer-v2/internal/dnsprovider"
)

// Given：buildCredentials 的 canonical 产出（mode/api_token 或 mode/secret 对）。
// When：把该产出再次喂回 BuildCredentialsJSON。
// Then：必须被接受且产出等价 canonical（此前 dnspod canonical 会落
// 「请选择认证方式」，任何「canonical 入库」的改动都会让测试端点误报 400）。
func TestDNSPod_BuildCredentialsJSON_acceptsCanonicalOutput(t *testing.T) {
	provider := &DNSPod{}
	cases := []map[string]string{
		{"auth_mode": "dnspod", "app_id": "123", "app_token": "abc"},
		{"auth_mode": "tencent_cloud", "secret_id": "sid", "secret_key": "skey"},
	}
	for _, input := range cases {
		canonical, err := provider.BuildCredentialsJSON(input)
		if err != nil {
			t.Fatalf("build canonical from %v: %v", input, err)
		}
		canonicalStrings := make(map[string]string, len(canonical))
		for key, value := range canonical {
			text, ok := value.(string)
			if !ok {
				t.Fatalf("canonical[%s]=%T, want string", key, value)
			}
			canonicalStrings[key] = text
		}
		again, err := provider.BuildCredentialsJSON(canonicalStrings)
		if err != nil {
			t.Fatalf("canonical %v must be accepted as input: %v", canonicalStrings, err)
		}
		if again["mode"] != canonical["mode"] {
			t.Fatalf("round-trip mode=%v, want %v", again["mode"], canonical["mode"])
		}
	}
	// 纯 canonical（无 auth_mode）直传形态。
	if _, err := provider.BuildCredentialsJSON(map[string]string{"mode": "dnspod", "api_token": "123,abc"}); err != nil {
		t.Fatalf("canonical dnspod form: %v", err)
	}
}

// budgetConsumingProvider 模拟「Present 烧尽整个验证预算」的传输层重试形态：
// 写记录成功但请求链在预算末尾返回；CleanUp 收到的 ctx 是判定修复的关键。
type budgetConsumingProvider struct {
	presentCtx     context.Context
	cleanupCtxErr  error
	cleanupBudget  time.Duration
	hasCleanupDead bool
	probeValue     string
	probeFVQDN     string
}

func (p *budgetConsumingProvider) Present(ctx context.Context, _ string, tokenFQDN, value string, _ int) error {
	p.presentCtx = ctx
	p.probeValue = value
	p.probeFVQDN = tokenFQDN
	<-ctx.Done() // 429/5xx 重试包络烧尽预算
	return nil
}

func (p *budgetConsumingProvider) CleanUp(ctx context.Context, _, _ string) error {
	// 调用时刻采样：ctx 的 cancel 常在函数返回时被 defer 触发，返回后再看
	// ctx.Err() 无法区分「共用已耗尽预算」与「独立预算已正常释放」。
	p.cleanupCtxErr = ctx.Err()
	if deadline, ok := ctx.Deadline(); ok {
		p.hasCleanupDead = true
		p.cleanupBudget = time.Until(deadline)
	}
	return nil
}

// Given：保存前验证的 Present 烧尽 30s 预算（传输层重试包络），记录实际写入成功。
// When：Validate 进入 CleanUp。
// Then：CleanUp 必须使用独立预算——共用同一 ctx 会因 ctx.Err() 立即失败，
// 用户看到「DNS 清理测试失败」的假失败。
func TestDNSPod_Validate_cleanupUsesIndependentBudget(t *testing.T) {
	originalTimeout := dnsProviderValidateTimeout
	dnsProviderValidateTimeout = 150 * time.Millisecond
	t.Cleanup(func() { dnsProviderValidateTimeout = originalTimeout })
	fake := &budgetConsumingProvider{}
	originalFactory := newDNSProviderFromCredentials
	newDNSProviderFromCredentials = func(string) (dnsprovider.Provider, error) { return fake, nil }
	t.Cleanup(func() { newDNSProviderFromCredentials = originalFactory })

	provider := &DNSPod{}
	credentials := map[string]string{"auth_mode": "dnspod", "app_id": "123", "app_token": "abc"}
	if err := provider.Validate(context.Background(), credentials, "example.com"); err != nil {
		t.Fatalf("validate: %v（清理失败不得报假失败）", err)
	}
	if !fake.hasCleanupDead {
		t.Fatal("CleanUp was not called with a budgeted context")
	}
	if fake.cleanupCtxErr != nil {
		t.Fatalf("cleanup ctx err=%v, want 独立预算下 ctx 未过期", fake.cleanupCtxErr)
	}
	if fake.cleanupBudget <= dnsProviderValidateTimeout || fake.cleanupBudget > dnsProviderValidateTimeout*retryEnvelopeFactor {
		t.Fatalf("cleanup budget=%v, want (%v, %v]（清理预算必须覆盖重试包络，与写入侧同倍数）",
			fake.cleanupBudget, dnsProviderValidateTimeout, dnsProviderValidateTimeout*retryEnvelopeFactor)
	}
}

// Given：两次保存前验证。
// When：观察探针写入值。
// Then：探针值带随机后缀（避免清理失败残留的同值记录使下一次写入/清理
// 产生歧义），两次调用取值不同。
func TestDNSPod_Validate_usesRandomProbeValue(t *testing.T) {
	originalTimeout := dnsProviderValidateTimeout
	dnsProviderValidateTimeout = 50 * time.Millisecond
	t.Cleanup(func() { dnsProviderValidateTimeout = originalTimeout })
	fake := &budgetConsumingProvider{}
	originalFactory := newDNSProviderFromCredentials
	newDNSProviderFromCredentials = func(string) (dnsprovider.Provider, error) { return fake, nil }
	t.Cleanup(func() { newDNSProviderFromCredentials = originalFactory })

	provider := &DNSPod{}
	credentials := map[string]string{"auth_mode": "dnspod", "app_id": "123", "app_token": "abc"}
	if err := provider.Validate(context.Background(), credentials, "example.com"); err != nil {
		t.Fatalf("first validate: %v", err)
	}
	first := fake.probeValue
	if err := provider.Validate(context.Background(), credentials, "example.com"); err != nil {
		t.Fatalf("second validate: %v", err)
	}
	second := fake.probeValue
	if !strings.HasPrefix(first, "lazy-balancer-test-") {
		t.Fatalf("probe value=%q, want lazy-balancer-test-<随机后缀>", first)
	}
	if first == second {
		t.Fatalf("probe values identical (%q), want 每次唯一", first)
	}
	if fake.probeFVQDN != "_acme-challenge.lb-test.example.com." {
		t.Fatalf("probe FQDN=%q", fake.probeFVQDN)
	}
}

// canceledProbeProvider 模拟「客户端断开后 Present 立即感知取消」的传输层。
type canceledProbeProvider struct {
	presentCtxErr error
	cleanupCalled bool
}

func (p *canceledProbeProvider) Present(ctx context.Context, _, _, _ string, _ int) error {
	p.presentCtxErr = ctx.Err()
	return ctx.Err()
}

func (p *canceledProbeProvider) CleanUp(context.Context, string, string) error {
	p.cleanupCalled = true
	return nil
}

// Given：调用方请求 ctx 已取消（客户端断开/请求超时）。
// When：保存前验证进入 Present。
// Then：Present 收到的 ctx 必须继承请求取消并立即失败——原实现从
// context.Background 派生预算，断开后仍会跑满 30s。
func TestDNSPod_Validate_honorsRequestContextCancellation(t *testing.T) {
	fake := &canceledProbeProvider{}
	originalFactory := newDNSProviderFromCredentials
	newDNSProviderFromCredentials = func(string) (dnsprovider.Provider, error) { return fake, nil }
	t.Cleanup(func() { newDNSProviderFromCredentials = originalFactory })

	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	provider := &DNSPod{}
	credentials := map[string]string{"auth_mode": "dnspod", "app_id": "123", "app_token": "abc"}
	err := provider.Validate(ctx, credentials, "example.com")
	if err == nil {
		t.Fatal("请求 ctx 已取消时必须立即失败")
	}
	if !strings.Contains(err.Error(), "DNS 写入测试失败") {
		t.Fatalf("error=%v, want DNS 写入测试失败（取消归因到写入探测）", err)
	}
	if fake.presentCtxErr == nil {
		t.Fatal("Present 收到的 ctx 未继承请求取消（客户端断开仍会跑满预算）")
	}
}
