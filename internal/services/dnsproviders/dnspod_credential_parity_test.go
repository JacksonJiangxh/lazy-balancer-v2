package dnsproviders

import (
	"encoding/json"
	"strings"
	"testing"

	"lazy-balancer-v2/internal/dnsprovider"
	"lazy-balancer-v2/internal/dnsprovider/dnspod"
	"lazy-balancer-v2/internal/dnsprovider/tencent"
)

// 同一份原始凭据 JSON 在「保存前验证」（本包 buildCredentials）与「真实签发」
// （dnsprovider 的 provider 构造）上必须同结论、同凭据。两侧各自推断的历史形态
// 会在两类凭据并存时给出相反答案（一侧静默选腾讯云、另一侧报歧义），表现为
// 「保存前测试通过但签发持续失败」或「测试用 A 账户、签发用 B 账户」。
func TestDNSPodCredentialInference_parityWithFactory(t *testing.T) {
	for _, shape := range []struct {
		name string
		raw  string
	}{
		{name: "app pair only", raw: `{"auth_mode":"dnspod","app_id":"123","app_token":"abc"}`},
		{name: "tencent pair only", raw: `{"auth_mode":"tencent_cloud","secret_id":"sid","secret_key":"skey"}`},
		{name: "ambiguous families without mode", raw: `{"api_token":"123,abc","secret_id":"sid","secret_key":"skey"}`},
		{name: "app pair overrides raw api_token", raw: `{"api_token":"old,old","app_id":"123","app_token":"abc"}`},
		{name: "explicit dnspod with both families", raw: `{"mode":"dnspod","api_token":"old,old","app_id":"123","app_token":"abc","secret_id":"sid","secret_key":"skey"}`},
		{name: "canonical dnspod", raw: `{"mode":"dnspod","api_token":"123,abc"}`},
		{name: "missing credentials", raw: `{}`},
		{name: "unsupported mode", raw: `{"mode":"route53","api_token":"1,2"}`},
	} {
		t.Run(shape.name, func(t *testing.T) {
			var fields map[string]string
			if err := json.Unmarshal([]byte(shape.raw), &fields); err != nil {
				t.Fatalf("decode shape: %v", err)
			}
			canonical, canonicalErr := dnsprovider.CanonicalCredentials(shape.raw)
			built, buildErr := (&DNSPod{}).buildCredentials(fields)

			// Then 1：是否拒绝必须一致
			if (canonicalErr == nil) != (buildErr == nil) {
				t.Fatalf("verdict mismatch: canonicalErr=%v buildErr=%v", canonicalErr, buildErr)
			}
			if canonicalErr != nil {
				return
			}
			// Then 2：归一结果一致（mode + 生效凭据）
			if built["mode"] != canonical.Mode {
				t.Fatalf("mode=%q, want %q", built["mode"], canonical.Mode)
			}
			switch canonical.Mode {
			case "dnspod":
				if built["api_token"] != canonical.APIToken {
					t.Fatalf("api_token=%q, want %q", built["api_token"], canonical.APIToken)
				}
			case "tencent":
				if built["secret_id"] != canonical.SecretID || built["secret_key"] != canonical.SecretKey {
					t.Fatalf("secret=(%q,%q), want (%q,%q)", built["secret_id"], built["secret_key"], canonical.SecretID, canonical.SecretKey)
				}
			default:
				t.Fatalf("unexpected canonical mode %q", canonical.Mode)
			}

			// Then 3：真实 provider 构造两侧同类型同凭据（保存前结论即签发结论）
			rawProvider, err := dnsprovider.NewProviderFromCredentials(shape.raw)
			if err != nil {
				t.Fatalf("construct provider from raw: %v", err)
			}
			builtJSON, err := json.Marshal(built)
			if err != nil {
				t.Fatalf("encode canonical: %v", err)
			}
			builtProvider, err := dnsprovider.NewProviderFromCredentials(string(builtJSON))
			if err != nil {
				t.Fatalf("construct provider from canonical: %v", err)
			}
			switch rawProvider := rawProvider.(type) {
			case *dnspod.Provider:
				builtDNSPod, ok := builtProvider.(*dnspod.Provider)
				if !ok || builtDNSPod.LoginToken() != rawProvider.LoginToken() {
					t.Fatalf("dnspod token mismatch: raw=%q canonical=%T", rawProvider.LoginToken(), builtProvider)
				}
			case *tencent.Provider:
				builtTencent, ok := builtProvider.(*tencent.Provider)
				if !ok || builtTencent.SecretID() != rawProvider.SecretID() {
					t.Fatalf("tencent secret mismatch: raw=%q canonical=%T", rawProvider.SecretID(), builtProvider)
				}
			default:
				t.Fatalf("unexpected provider type %T", rawProvider)
			}
		})
	}
}

// 两类凭据并存且无显式 mode 时必须拒绝（历史上静默选腾讯云，与签发侧
// 的「凭证歧义」结论相反）。
func TestDNSPodBuildCredentials_rejectsAmbiguousFamilies(t *testing.T) {
	_, err := (&DNSPod{}).buildCredentials(map[string]string{
		"api_token":  "123,abc",
		"secret_id":  "sid",
		"secret_key": "skey",
	})
	if err == nil {
		t.Fatal("ambiguous credential families must be rejected")
	}
	if !strings.Contains(err.Error(), "歧义") {
		t.Fatalf("error=%q, want 歧义 wording", err.Error())
	}
}
