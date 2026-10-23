package handlers

// 出站地址策略的三处收口：provider 入口（issuer）、出站客户端（每一次请求的
// 初始 URL）、公开状态端点（库中存量坏值）。库中 issuer 可由配置导入、自动
// 备份还原、集群快照或带外改库带入，写侧校验只覆盖面板保存路径。

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/coreos/go-oidc/v3/oidc"
	"golang.org/x/oauth2"
)

func TestOIDCProvider_rejectsNonCompliantIssuer(t *testing.T) {
	cases := []struct {
		name   string
		issuer string
	}{
		{"非 https 方案", "http://idp.example.test/"},
		{"伪 scheme", "httpxy://idp.example.test/"},
		{"空 host", "https:///path"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := oidcProvider(tc.issuer); err == nil || !strings.Contains(err.Error(), "服务地址不合规") {
				t.Fatalf("oidcProvider(%q) err=%v, want 合规拒绝（零出站）", tc.issuer, err)
			}
		})
	}
}

func TestOIDCOutboundClient_rejectsNonCompliantInitialURL(t *testing.T) {
	resp, err := oidcOutboundClient.Get("http://example.invalid/.well-known/openid-configuration")
	if resp != nil {
		resp.Body.Close()
	}
	if err == nil || !strings.Contains(err.Error(), "不合规") {
		t.Fatalf("oidcOutboundClient.Get err=%v, want 传输层策略拒绝（远早于 DNS）", err)
	}
}

func TestOIDCStatus_hidesNonCompliantStoredIssuer(t *testing.T) {
	router, _ := setupOIDCTest(t, newMockIdP(t))
	if err := saveOIDCConfig(OIDCConfig{
		Enabled: true, Issuer: "http://idp.example.test", ClientID: "cid", ClientSecret: "sec",
	}); err != nil {
		t.Fatalf("seed stored config: %v", err)
	}
	rec := httptest.NewRecorder()
	router.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/api/v1/auth/oidc/status", nil))
	if rec.Code != http.StatusOK {
		t.Fatalf("status code=%d body=%s", rec.Code, rec.Body.String())
	}
	if !strings.Contains(rec.Body.String(), `"enabled":false`) {
		t.Fatalf("body=%s, want enabled=false（不合规 issuer 不得宣告登录按钮）", rec.Body.String())
	}
}

func TestOIDCTokenExchange_rejectsDiscoveredNonCompliantTokenEndpoint(t *testing.T) {
	// 凭证外泄监听器：token_endpoint 被 discovery 文档指向它。
	var hits atomic.Int32
	exfil := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		hits.Add(1)
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"access_token":"a","token_type":"Bearer","expires_in":3600}`))
	}))
	defer exfil.Close()

	// discovery 服务本身合规（回环 http），但把 token_endpoint 指向
	// `localhost`（非 IP 形态的回环，策略不允许）——合法 https IdP 同样可以
	// 这样指向内网/本机。
	var discoveryURL string
	discovery := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/.well-known/openid-configuration" {
			http.NotFound(w, r)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{
			"issuer":"` + discoveryURL + `",
			"authorization_endpoint":"` + discoveryURL + `/authorize",
			"token_endpoint":"http://localhost:` + portOf(t, exfil.URL) + `/token",
			"jwks_uri":"` + discoveryURL + `/jwks",
			"response_types_supported":["code"],
			"subject_types_supported":["public"],
			"id_token_signing_alg_values_supported":["RS256"]
		}`))
	}))
	defer discovery.Close()
	discoveryURL = discovery.URL

	p, err := oidcProvider(discoveryURL)
	if err != nil {
		t.Fatalf("discovery over compliant loopback issuer: %v", err)
	}
	oauthCfg := oidcOAuthConfig(OIDCConfig{ClientID: "cid", ClientSecret: "top-secret"}, p, "http://127.0.0.1:9/callback")
	ctx := oidc.ClientContext(context.Background(), oidcOutboundClient)
	_, err = oauthCfg.Exchange(ctx, "code", oauth2.SetAuthURLParam("code_verifier", "verifier"))
	if err == nil {
		t.Fatal("token 交换必须失败：discovery 的 token_endpoint 不合规")
	}
	if !strings.Contains(err.Error(), "不合规") {
		t.Fatalf("err=%v, want 策略拒绝（而非网络错误）", err)
	}
	if got := hits.Load(); got != 0 {
		t.Fatalf("不合规 token_endpoint 收到 %d 次请求，want 0（client_secret 不得出站）", got)
	}
}

// portOf 取 httptest URL 的端口段，供拼装跨端口目标。
func portOf(t *testing.T, raw string) string {
	t.Helper()
	idx := strings.LastIndex(raw, ":")
	if idx < 0 {
		t.Fatalf("url %q has no port", raw)
	}
	return raw[idx+1:]
}
