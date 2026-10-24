package handlers

// OIDC 访问白名单（可选 email 域/组名单）钉测：缺省空=不限制（历史行为）；
// 配置后每次回调判定（IdP 侧变更即时生效），不在名单内拒登且不发生 JIT
// 开户；IdP 未返回对应声明 = fail-visible 拒登。写侧规范化与校验同钉。

import (
	"encoding/json"
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

// 域名单读侧再规范化：带外写入/旧值（未小写、带空格）不得让白名单恒不匹配
// （fail-visible 方向安全但全员拒登属可用性自伤）。
func TestOIDCAccessAllowed_normalizesDomainListAtRead(t *testing.T) {
	cfg := OIDCConfig{AllowedEmailDomains: []string{" Example.COM ", "corp.example.org"}}
	ok, reason := oidcAccessAllowed(cfg, oidcAccessClaims{
		Email: "user@example.com", EmailVerified: true, EmailVerifiedSeen: true,
	})
	if !ok {
		t.Fatalf("allowed=%v reason=%q, want 命中（读侧 trim+小写）", ok, reason)
	}
	if ok, _ := oidcAccessAllowed(cfg, oidcAccessClaims{
		Email: "user@evil.example", EmailVerified: true, EmailVerifiedSeen: true,
	}); ok {
		t.Fatal("未命中域不得放行")
	}
}

// 配置了域名单时 email_verified 是硬门：false 与缺失（IdP 不返回该声明）
// 都必须 fail-visible 拒登——域白名单信任的是「IdP 已验证邮箱归属」，否则
// 任何能改 profile 邮箱的人把地址指向允许域即通过。
func TestOIDCAccessAllowed_requiresVerifiedEmail(t *testing.T) {
	cfg := OIDCConfig{AllowedEmailDomains: []string{"example.com"}}
	cases := []struct {
		name    string
		claims  oidcAccessClaims
		wantOK  bool
		wantSub string
	}{
		{"verified", oidcAccessClaims{Email: "user@example.com", EmailVerified: true, EmailVerifiedSeen: true}, true, ""},
		{"unverified", oidcAccessClaims{Email: "user@example.com", EmailVerified: false, EmailVerifiedSeen: true}, false, "email_verified=false"},
		{"missing claim", oidcAccessClaims{Email: "user@example.com"}, false, "未返回 email_verified"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			ok, reason := oidcAccessAllowed(cfg, tc.claims)
			if ok != tc.wantOK {
				t.Fatalf("allowed=%v, want %v (reason=%q)", ok, tc.wantOK, reason)
			}
			if tc.wantSub != "" && !strings.Contains(reason, tc.wantSub) {
				t.Fatalf("reason=%q, want 含 %q", reason, tc.wantSub)
			}
		})
	}
}

// email_verified 的解析容忍布尔与字符串两种形态（部分 IdP 返回 "true"）；
// 未知形态按「未验证」处理（fail-closed）。
func TestOIDCEmailVerified_parsesBoolAndStringForms(t *testing.T) {
	cases := []struct {
		raw          string
		wantVerified bool
		wantKnown    bool
	}{
		{`true`, true, true},
		{`false`, false, true},
		{`"true"`, true, true},
		{`"false"`, false, true},
		{`null`, false, false},
		{``, false, false},
		{`"yes"`, false, false},
	}
	for _, tc := range cases {
		verified, known := oidcEmailVerified(json.RawMessage(tc.raw))
		if verified != tc.wantVerified || known != tc.wantKnown {
			t.Fatalf("raw=%q → (%v,%v), want (%v,%v)", tc.raw, verified, known, tc.wantVerified, tc.wantKnown)
		}
	}
}

// 端到端：IdP 返回 email_verified=false 时，域名单即使命中也必须拒登
// （未验证的自定义邮箱可被任意指向允许域），且不发生 JIT 开户、审计写明原因。
func TestOIDCCallback_unverifiedEmailRejected(t *testing.T) {
	for _, mode := range []string{"false", "absent"} {
		t.Run(mode, func(t *testing.T) {
			idp := newMockIdP(t)
			idp.emailVerifiedMode.Store(mode)
			router, _ := setupOIDCTest(t, idp)
			putOIDCConfig(t, router, `{"issuer":"`+idp.issuer+`","client_id":"test-client","client_secret":"s","enabled":true,"allowed_email_domains":["example.com"]}`)

			front := runOIDCLoginFlow(t, router)
			if !strings.Contains(front, "error=") {
				t.Fatalf("未验证邮箱必须拒登（mode=%s），got redirect: %s", mode, front)
			}
			var cnt int
			if err := db.DB.QueryRow("SELECT COUNT(*) FROM users WHERE auth_provider='oidc'").Scan(&cnt); err != nil {
				t.Fatal(err)
			}
			if cnt != 0 {
				t.Fatalf("oidc users=%d, want 0（未验证邮箱不得开户）", cnt)
			}
			var audits int
			if err := db.AuditDB.QueryRow(`SELECT COUNT(*) FROM audit_log WHERE action='认证拒绝' AND detail LIKE '%email_verified%'`).Scan(&audits); err != nil {
				t.Fatal(err)
			}
			if audits == 0 {
				t.Fatal("拒登审计必须写明 email_verified 原因")
			}
		})
	}
}

// groups 声明形态归一：IdP 以空白/逗号分隔的字符串返回（自建 Keycloak 自定义
// mapper、SAML 桥接、部分 ADFS 部署常见）不得导致 claims 解析失败——否则配置
// 组白名单后全员拒登，且原因只落在服务端日志。
func TestOIDCCallback_groupsDelimitedStringAccepted(t *testing.T) {
	idp := newMockIdP(t)
	idp.groupsClaim.Store(`"ops, dev"`)
	router, _ := setupOIDCTest(t, idp)
	putOIDCConfig(t, router, `{"issuer":"`+idp.issuer+`","client_id":"test-client","client_secret":"s","enabled":true,"allowed_groups":["dev"]}`)

	front := runOIDCLoginFlow(t, router)
	if !strings.Contains(front, "#/oidc/callback?token=") {
		t.Fatalf("分隔字符串形态的 groups 必须命中白名单并登录, got: %s", front)
	}
}

// 数组元素逐项 trim：IdP 的 " ops " 不得因逐字比较失败拒登。
func TestOIDCCallback_groupsArrayTrimmed(t *testing.T) {
	idp := newMockIdP(t)
	idp.groupsClaim.Store(`[" ops "]`)
	router, _ := setupOIDCTest(t, idp)
	putOIDCConfig(t, router, `{"issuer":"`+idp.issuer+`","client_id":"test-client","client_secret":"s","enabled":true,"allowed_groups":["ops"]}`)

	front := runOIDCLoginFlow(t, router)
	if !strings.Contains(front, "#/oidc/callback?token=") {
		t.Fatalf("数组元素 trim 后必须命中白名单, got: %s", front)
	}
}

// groups 声明存在但形态不可解析（数字/对象）→ 拒登，且审计 reason 与「未返回
// 声明」区分开（管理员能定位到 IdP 声明类型不兼容）。
func TestOIDCCallback_groupsMalformedRejected(t *testing.T) {
	idp := newMockIdP(t)
	idp.groupsClaim.Store(`42`)
	router, _ := setupOIDCTest(t, idp)
	putOIDCConfig(t, router, `{"issuer":"`+idp.issuer+`","client_id":"test-client","client_secret":"s","enabled":true,"allowed_groups":["ops"]}`)

	front := runOIDCLoginFlow(t, router)
	if !strings.Contains(front, "error=") {
		t.Fatalf("不可解析的 groups 必须拒登, got: %s", front)
	}
	var audits int
	if err := db.AuditDB.QueryRow(`SELECT COUNT(*) FROM audit_log WHERE action='认证拒绝' AND detail LIKE '%groups 声明类型不支持%'`).Scan(&audits); err != nil {
		t.Fatalf("query audit: %v", err)
	}
	if audits == 0 {
		t.Fatal("拒登审计必须写明「groups 声明类型不支持」而非「未返回声明」")
	}
}

// oidcGroups 单元面：数组 / 分隔字符串 / 缺失 / 不可解析四形态。
func TestOIDCGroups_parsesIdPShapes(t *testing.T) {
	cases := []struct {
		name      string
		raw       string
		want      []string
		malformed bool
	}{
		{"数组", `["ops","dev"]`, []string{"ops", "dev"}, false},
		{"数组去空白去空项", `[" ops ","", "  "]`, []string{"ops"}, false},
		{"逗号分隔字符串", `"ops,dev,sre"`, []string{"ops", "dev", "sre"}, false},
		{"空白与分号分隔", `"ops dev;sre"`, []string{"ops", "dev", "sre"}, false},
		{"缺失", ``, nil, false},
		{"null", `null`, nil, false},
		{"空数组", `[]`, nil, false},
		{"数字", `42`, nil, true},
		{"对象", `{"a":"b"}`, nil, true},
		{"数字数组", `[1,2]`, nil, true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, malformed := oidcGroups([]byte(tc.raw))
			if malformed != tc.malformed {
				t.Fatalf("malformed=%v, want %v", malformed, tc.malformed)
			}
			if strings.Join(got, "|") != strings.Join(tc.want, "|") {
				t.Fatalf("groups=%v, want %v", got, tc.want)
			}
		})
	}
}

// malformed 在 oidcAccessAllowed 层与「缺失」分判：配置组名单时表述不同。
func TestOIDCAccessAllowed_malformedGroupsReason(t *testing.T) {
	cfg := OIDCConfig{AllowedGroups: []string{"ops"}}
	if ok, reason := oidcAccessAllowed(cfg, oidcAccessClaims{GroupsMalformed: true}); ok || !strings.Contains(reason, "类型不支持") {
		t.Fatalf("allowed=%v reason=%q, want 拒登且写明类型不支持", ok, reason)
	}
	if ok, reason := oidcAccessAllowed(cfg, oidcAccessClaims{}); ok || !strings.Contains(reason, "未返回") {
		t.Fatalf("allowed=%v reason=%q, want 拒登且写明未返回声明", ok, reason)
	}
}
