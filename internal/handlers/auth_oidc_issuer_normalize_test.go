package handlers

// issuer 读侧归一钉测：库值可由配置导入/自动备份还原/集群快照/带外改库带入
// 未归一形态（写侧 normalizeOIDCIssuer 只覆盖面板保存路径）。归一若只在写/测试
// 路径生效，就会出现「管理员点测试通过、真实登录必然失败」——discovery 用未
// 归一值恒 404，错误文案还被归一成「服务不可达」误导排障。

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"lazy-balancer-v2/internal/db"
)

// Given 库中 issuer 带尾斜杠（带外写入形态）。
// When 读取配置。
// Then 归一值生效（尾斜杠剥离），原值保留供历史身份行兼容查询。
func TestLoadOIDCConfig_normalizesIssuerOnRead(t *testing.T) {
	setupOIDCTest(t, newMockIdP(t))
	raw := `{"enabled":true,"issuer":"https://login.microsoftonline.com/tenant/","client_id":"c","client_secret":"s"}`
	if _, err := db.DB.Exec(`UPDATE global_config SET oidc_config=? WHERE id=1`, raw); err != nil {
		t.Fatalf("raw write oidc config: %v", err)
	}
	cfg, err := loadOIDCConfig()
	if err != nil {
		t.Fatalf("load oidc config: %v", err)
	}
	if cfg.Issuer != "https://login.microsoftonline.com/tenant/v2.0" {
		t.Fatalf("issuer=%q, want 归一值（去尾斜杠 + Entra 补 /v2.0）", cfg.Issuer)
	}
	if cfg.rawIssuer != "https://login.microsoftonline.com/tenant/" {
		t.Fatalf("rawIssuer=%q, want 库中原值", cfg.rawIssuer)
	}
}

// Given 库中 issuer 带尾斜杠（旧登录/探测路径会拼出 //.well-known 而失败）。
// When 走完 login→callback 全链。
// Then 登录成功——消费路径必须使用读侧归一值。
func TestOIDCLoginFlow_worksWithUnnormalizedStoredIssuer(t *testing.T) {
	idp := newMockIdP(t)
	router, _ := setupOIDCTest(t, idp)
	raw := `{"enabled":true,"issuer":"` + idp.issuer + `/","client_id":"test-client","client_secret":"super-secret-123"}`
	if _, err := db.DB.Exec(`UPDATE global_config SET oidc_config=? WHERE id=1`, raw); err != nil {
		t.Fatalf("raw write oidc config: %v", err)
	}

	front := runOIDCLoginFlow(t, router)
	if !strings.Contains(front, "#/oidc/callback?token=") {
		t.Fatalf("带尾斜杠的库内 issuer 必须能登录（读侧归一），got redirect: %s", front)
	}
}

// 归一值同时作为 discovery 缓存键：保存归一后的配置后，探测与真实登录共用
// 同一缓存条目（不会一边命中、一边回源）。此用例守住「缓存键=归一值」的口径。
func TestOIDCSettingsTest_usesNormalizedIssuerCacheKey(t *testing.T) {
	idp := newMockIdP(t)
	router, _ := setupOIDCTest(t, idp)
	putOIDCConfig(t, router, `{"issuer":"`+idp.issuer+`","client_id":"test-client","client_secret":"super-secret-123","enabled":true}`)

	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/api/v1/settings/oidc/test", strings.NewReader(`{}`))
	req.Header.Set("Content-Type", "application/json")
	router.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK || !strings.Contains(rec.Body.String(), `"ok":true`) {
		t.Fatalf("test endpoint=%d body=%s, want ok", rec.Code, rec.Body.String())
	}

	// 缓存键必须是归一值（去尾斜杠）：未归一键会留下陈旧条目，保存侧失效时
	// 打不中同一键。
	oidcProvMu.Lock()
	_, normalizedHit := oidcProvCach[normalizeOIDCIssuer(idp.issuer)]
	_, rawHit := oidcProvCach[idp.issuer+"/"]
	oidcProvMu.Unlock()
	if !normalizedHit {
		t.Fatal("discovery 缓存键必须是归一后的 issuer")
	}
	if rawHit {
		t.Fatal("缓存中不得存在未归一 issuer 的条目")
	}

	// 登录链同样使用归一键（配置中带尾斜杠时仍然命中缓存，不回源到 //.well-known）
	if _, err := db.DB.Exec(`UPDATE global_config SET oidc_config=? WHERE id=1`,
		`{"enabled":true,"issuer":"`+idp.issuer+`/","client_id":"test-client","client_secret":"super-secret-123"}`); err != nil {
		t.Fatalf("raw write oidc config: %v", err)
	}
	front := runOIDCLoginFlow(t, router)
	if !strings.Contains(front, "#/oidc/callback?token=") {
		t.Fatalf("登录链未使用归一 issuer（缓存未命中/发现失败），got: %s", front)
	}
}

// Entra 补 /v2.0 特例的命中面：浏览器地址栏/IdP 门户复制来的 issuer 常带
// :443，且主权云主机与全球主机并列——按主机名（去端口）判定，否则 v1 端点
// 无发现文档 → 恒登录失败且被归一为「服务不可达」。
func TestNormalizeOIDCIssuer_matchesHostByHostname(t *testing.T) {
	cases := []struct {
		raw  string
		want string
	}{
		{"https://login.microsoftonline.com/tenant", "https://login.microsoftonline.com/tenant/v2.0"},
		{"https://login.microsoftonline.com:443/tenant", "https://login.microsoftonline.com:443/tenant/v2.0"},
		{"https://Login.MicrosoftOnline.US/tenant/", "https://Login.MicrosoftOnline.US/tenant/v2.0"},
		{"https://login.partner.microsoftonline.cn/tenant", "https://login.partner.microsoftonline.cn/tenant/v2.0"},
		{"https://login.chinacloudapi.cn/tenant", "https://login.chinacloudapi.cn/tenant/v2.0"},
		{"https://login.microsoftonline.com/tenant/v2.0", "https://login.microsoftonline.com/tenant/v2.0"},
		// 非 Entra 主机逐字保留（只去尾斜杠/空白，不猜路径）。
		{"https://idp.example.com/tenant/", "https://idp.example.com/tenant"},
		{"https://idp.example.com/v2.0", "https://idp.example.com/v2.0"},
		// 子域名不命中（避免把任意外观相似的域当 Entra）。
		{"https://evil.login.microsoftonline.com/tenant", "https://evil.login.microsoftonline.com/tenant"},
	}
	for _, tc := range cases {
		t.Run(tc.raw, func(t *testing.T) {
			if got := normalizeOIDCIssuer(tc.raw); got != tc.want {
				t.Fatalf("normalizeOIDCIssuer(%q)=%q, want %q", tc.raw, got, tc.want)
			}
		})
	}
}
