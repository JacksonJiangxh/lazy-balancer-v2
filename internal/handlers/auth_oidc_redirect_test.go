package handlers

// OIDC 出站链路的两条契约：
//  1. 回调配置读失败/未启用发生在浏览器整页导航上——一律 302 回前端错误页，
//     不渲染裸 JSON（否则用户停在一个 JSON 页面）。
//  2. discovery/JWKS/token 的初始 URL 通过 scheme 策略不代表重定向目标合规：
//     一次 302 就能把请求引到 http://非回环地址（token 交换还会带上
//     client_secret）。三处共用同一 CheckRedirect，回环例外与既有策略一致。

import (
	"context"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/coreos/go-oidc/v3/oidc"
	"golang.org/x/oauth2"

	"lazy-balancer-v2/internal/db"
)

func assertOIDCCallbackErrorRedirect(t *testing.T, rec *httptest.ResponseRecorder, wantMsg string) {
	t.Helper()
	if rec.Code != http.StatusFound {
		t.Fatalf("status=%d body=%s, want 302（回调失败须回前端错误页）", rec.Code, rec.Body.String())
	}
	loc := rec.Header().Get("Location")
	if !strings.Contains(loc, "#/oidc/callback?error=") {
		t.Fatalf("redirect=%q, want 前端错误页 error fragment", loc)
	}
	u, err := url.Parse(loc)
	if err != nil {
		t.Fatalf("parse redirect: %v", err)
	}
	q := u.Fragment
	if i := strings.Index(q, "?"); i >= 0 {
		q = q[i+1:]
	}
	vals, err := url.ParseQuery(q)
	if err != nil {
		t.Fatalf("parse fragment: %v", err)
	}
	if got := vals.Get("error"); got != wantMsg {
		t.Fatalf("error=%q, want %q", got, wantMsg)
	}
}

func TestOIDCCallback_configStatesRedirectToFrontend(t *testing.T) {
	idp := newMockIdP(t)
	router, _ := setupOIDCTest(t, idp)

	// 形状一：未启用（零配置）——此前 404 裸 JSON。
	rec := httptest.NewRecorder()
	router.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/api/v1/auth/oidc/callback?code=x&state=y", nil))
	assertOIDCCallbackErrorRedirect(t, rec, "OIDC 未启用")

	// 形状二：配置读取失败（存储损坏）——此前 500 裸 JSON。
	if _, err := db.DB.Exec("UPDATE global_config SET oidc_config='{broken' WHERE id=1"); err != nil {
		t.Fatalf("corrupt oidc config: %v", err)
	}
	rec = httptest.NewRecorder()
	router.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/api/v1/auth/oidc/callback?code=x&state=y", nil))
	assertOIDCCallbackErrorRedirect(t, rec, "OIDC 配置读取失败")
}

func TestOIDCCheckRedirect_revalidatesSchemePolicy(t *testing.T) {
	cases := []struct {
		name    string
		target  string
		hops    int
		wantErr bool
	}{
		{name: "https 目标放行", target: "https://idp.example.com/token", hops: 1},
		{name: "回环 http 放行（本机 mock）", target: "http://127.0.0.1:8443/jwks", hops: 1},
		{name: "非回环 http 拒绝", target: "http://example.invalid/jwks", hops: 1, wantErr: true},
		{name: "跳数封顶", target: "https://idp.example.com/token", hops: 10, wantErr: true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodGet, tc.target, nil)
			via := make([]*http.Request, tc.hops)
			err := oidcCheckRedirect(req, via)
			if (err != nil) != tc.wantErr {
				t.Fatalf("oidcCheckRedirect(%q, hops=%d) err=%v, wantErr=%v", tc.target, tc.hops, err, tc.wantErr)
			}
		})
	}
}

func TestOIDCProvider_discoveryRedirectOutsidePolicyRejected(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, "http://example.invalid/.well-known/openid-configuration", http.StatusFound)
	}))
	t.Cleanup(srv.Close)
	oidcProviderInvalidate(srv.URL)
	t.Cleanup(func() { oidcProviderInvalidate(srv.URL) })

	_, err := oidcProvider(srv.URL)
	if err == nil || !strings.Contains(err.Error(), "重定向目标不合规") {
		t.Fatalf("discovery 302 到非回环 http 必须被拒绝: %v", err)
	}
}

func TestProbeOIDCJWKS_rejectsRedirectOutsidePolicy(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, "http://example.invalid/jwks.json", http.StatusFound)
	}))
	t.Cleanup(srv.Close)

	if err := probeOIDCJWKS(srv.URL); err == nil || !strings.Contains(err.Error(), "重定向目标不合规") {
		t.Fatalf("jwks 302 到非回环 http 必须被拒绝: %v", err)
	}
}

func TestProbeClientCredentials_rejectsRedirectOutsidePolicy(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, "http://example.invalid/token", http.StatusFound)
	}))
	t.Cleanup(srv.Close)

	if _, err := probeClientCredentials(srv.URL, "client-id", "client-secret"); err == nil ||
		!strings.Contains(err.Error(), "重定向目标不合规") {
		t.Fatalf("token 端点 302 到非回环 http 必须被拒绝: %v", err)
	}
}

func TestOIDCTokenExchange_rejectsRedirectOutsidePolicy(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, "http://example.invalid/token", http.StatusFound)
	}))
	t.Cleanup(srv.Close)

	cfg := oauth2.Config{
		ClientID:     "client-id",
		ClientSecret: "client-secret",
		Endpoint:     oauth2.Endpoint{TokenURL: srv.URL},
		RedirectURL:  "http://127.0.0.1/callback",
	}
	ctx := oidc.ClientContext(context.Background(), oidcOutboundClient)
	if _, err := cfg.Exchange(ctx, "code"); err == nil || !strings.Contains(err.Error(), "重定向目标不合规") {
		t.Fatalf("令牌交换 302 到非回环 http 必须被拒绝: %v", err)
	}
}

// 回环重定向仍须跟随（本机 mock/测试形态不被元策略误伤）。
func TestProbeOIDCJWKS_followsLoopbackRedirect(t *testing.T) {
	final := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"keys":[{"kty":"RSA"}]}`))
	}))
	t.Cleanup(final.Close)
	entry := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, final.URL+"/jwks.json", http.StatusFound)
	}))
	t.Cleanup(entry.Close)

	if err := probeOIDCJWKS(entry.URL); err != nil {
		t.Fatalf("回环 http 重定向必须放行: %v", err)
	}
}
