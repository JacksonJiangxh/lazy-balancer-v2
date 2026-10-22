package handlers

// OIDC 访问白名单（可选 email 域/组名单）钉测：缺省空=不限制（历史行为）；
// 配置后每次回调判定（IdP 侧变更即时生效），不在名单内拒登且不发生 JIT
// 开户；IdP 未返回对应声明 = fail-visible 拒登。写侧规范化与校验同钉。

import (
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"lazy-balancer-v2/internal/db"
)

// runOIDCLoginFlow 走完 login→callback 全链，返回 callback 的 302 Location。
func runOIDCLoginFlow(t *testing.T, router http.Handler) string {
	t.Helper()
	rec := httptest.NewRecorder()
	router.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/api/v1/auth/oidc/login", nil))
	if rec.Code != http.StatusFound {
		t.Fatalf("login should redirect, got %d %s", rec.Code, rec.Body.String())
	}
	authURL := rec.Header().Get("Location")
	u, _ := url.Parse(authURL)
	state := u.Query().Get("state")
	if state == "" {
		t.Fatal("authorize url missing state")
	}
	code := simulateIdPIssuesCode(t, authURL)
	rec = httptest.NewRecorder()
	router.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/api/v1/auth/oidc/callback?code="+code+"&state="+state, nil))
	if rec.Code != http.StatusFound {
		t.Fatalf("callback should redirect, got %d body=%s", rec.Code, rec.Body.String())
	}
	return rec.Header().Get("Location")
}

// 域名单命中 → 正常 JIT 开户登录。
func TestOIDCCallback_whitelistDomainAllowed(t *testing.T) {
	idp := newMockIdP(t)
	router, _ := setupOIDCTest(t, idp)
	putOIDCConfig(t, router, `{"issuer":"`+idp.issuer+`","client_id":"test-client","client_secret":"s","enabled":true,"allowed_email_domains":["example.com"]}`)

	front := runOIDCLoginFlow(t, router)
	if !strings.Contains(front, "#/oidc/callback?token=") {
		t.Fatalf("whitelisted domain must login, got redirect: %s", front)
	}
	var cnt int
	if err := db.DB.QueryRow("SELECT COUNT(*) FROM users WHERE auth_provider='oidc'").Scan(&cnt); err != nil {
		t.Fatal(err)
	}
	if cnt != 1 {
		t.Fatalf("oidc users=%d, want 1（白名单命中应 JIT 开户）", cnt)
	}
}

// 域名单未命中 → 拒登（302 错误页）、无 JIT 开户、审计留痕。
func TestOIDCCallback_whitelistDomainRejected(t *testing.T) {
	idp := newMockIdP(t)
	router, _ := setupOIDCTest(t, idp)
	putOIDCConfig(t, router, `{"issuer":"`+idp.issuer+`","client_id":"test-client","client_secret":"s","enabled":true,"allowed_email_domains":["corp.example.org"]}`)

	front := runOIDCLoginFlow(t, router)
	if !strings.Contains(front, "error=") {
		t.Fatalf("non-whitelisted domain must be rejected, got redirect: %s", front)
	}
	if !strings.Contains(front, url.QueryEscape("账号不在允许登录的范围")) {
		t.Fatalf("rejection message mismatch: %s", front)
	}
	var cnt int
	if err := db.DB.QueryRow("SELECT COUNT(*) FROM users WHERE auth_provider='oidc'").Scan(&cnt); err != nil {
		t.Fatal(err)
	}
	if cnt != 0 {
		t.Fatalf("oidc users=%d, want 0（白名单拒绝不得 JIT 开户）", cnt)
	}
	var audits int
	if err := db.AuditDB.QueryRow(`SELECT COUNT(*) FROM audit_log WHERE action='认证拒绝' AND detail LIKE '%OIDC 白名单拒绝%'`).Scan(&audits); err != nil {
		t.Fatalf("query audit: %v", err)
	}
	if audits == 0 {
		t.Fatal("白名单拒绝未留审计")
	}
}

// 配置了组名单但 IdP 未返回 groups 声明 → fail-visible 拒登（不静默放行）。
func TestOIDCCallback_whitelistGroupsMissingClaimRejected(t *testing.T) {
	idp := newMockIdP(t)
	router, _ := setupOIDCTest(t, idp)
	putOIDCConfig(t, router, `{"issuer":"`+idp.issuer+`","client_id":"test-client","client_secret":"s","enabled":true,"allowed_groups":["ops"]}`)

	front := runOIDCLoginFlow(t, router)
	if !strings.Contains(front, url.QueryEscape("账号不在允许登录的范围")) {
		t.Fatalf("missing groups claim must be rejected (fail-visible), got: %s", front)
	}
}

// 白名单缺省（不配置）→ 不限制，历史行为不变。
func TestOIDCCallback_noWhitelistUnchanged(t *testing.T) {
	idp := newMockIdP(t)
	router, _ := setupOIDCTest(t, idp)
	putOIDCConfig(t, router, `{"issuer":"`+idp.issuer+`","client_id":"test-client","client_secret":"s","enabled":true}`)

	front := runOIDCLoginFlow(t, router)
	if !strings.Contains(front, "#/oidc/callback?token=") {
		t.Fatalf("no whitelist must keep historical behavior, got: %s", front)
	}
}

// 写侧：无效域条目 400；规范化（trim/小写/去重）生效；GET 回显白名单；
// 审计字段级 delta 含白名单变更。
func TestOIDCSettings_whitelistValidationAndEcho(t *testing.T) {
	idp := newMockIdP(t)
	router, _ := setupOIDCTest(t, idp)
	putOIDCConfig(t, router, `{"issuer":"`+idp.issuer+`","client_id":"test-client","client_secret":"s","enabled":true}`)

	// 无效域条目 → 400
	req := httptest.NewRequest(http.MethodPut, "/api/v1/settings/oidc", strings.NewReader(`{"allowed_email_domains":["bad domain!"]}`))
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	router.ServeHTTP(rec, req)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("invalid domain entry: status=%d body=%s, want 400", rec.Code, rec.Body.String())
	}

	// 规范化：大写/空白/重复 → 小写去重（域）；组名 trim 去重但大小写敏感
	// （"Ops" 与 "ops" 是不同组，均保留）。
	putOIDCConfig(t, router, `{"allowed_email_domains":[" Example.COM ","example.com","corp.org"],"allowed_groups":[" Ops ","Ops","ops"]}`)

	rec = httptest.NewRecorder()
	router.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/api/v1/settings/oidc", nil))
	body := rec.Body.String()
	if !strings.Contains(body, `"allowed_email_domains":["example.com","corp.org"]`) {
		t.Fatalf("domains not normalized: %s", body)
	}
	if !strings.Contains(body, `"allowed_groups":["Ops","ops"]`) {
		t.Fatalf("groups not normalized (case-sensitive dedupe): %s", body)
	}

	// 审计 delta 含白名单变更（值非敏感，落值便于追溯）
	var detail string
	if err := db.AuditDB.QueryRow(`SELECT detail FROM audit_log WHERE action='更新' AND resource='OIDC 配置' ORDER BY id DESC LIMIT 1`).Scan(&detail); err != nil {
		t.Fatalf("read audit: %v", err)
	}
	if !strings.Contains(detail, "允许的 email 域") || !strings.Contains(detail, "允许的组") {
		t.Fatalf("audit detail missing whitelist delta: %q", detail)
	}

	// 空数组=清除（恢复不限制）
	putOIDCConfig(t, router, `{"allowed_email_domains":[],"allowed_groups":[]}`)
	rec = httptest.NewRecorder()
	router.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/api/v1/settings/oidc", nil))
	if strings.Contains(rec.Body.String(), "example.com") {
		t.Fatalf("empty array must clear whitelist: %s", rec.Body.String())
	}
}
