package handlers

// 显示名是 IdP 派生的展示属性（非授权前提）：重复登录按最新 claims 刷新，
// 刷新写失败不得中断登录——与 last_login 记账同口径（登录已签发，记账失败只
// 留痕），下次登录自愈。旧实现把写失败升级为「更新用户资料失败」302，用户
// 可见面是登录失败，排障方向被引向认证而非存储。

import (
	"bytes"
	"log"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"lazy-balancer-v2/internal/db"
)

func TestOIDCCallback_displayNameRefreshFailureDoesNotBlockLogin(t *testing.T) {
	idp := newMockIdP(t)
	router, _ := setupOIDCTest(t, idp)
	putOIDCConfig(t, router, `{"issuer":"`+idp.issuer+`","client_id":"test-client","client_secret":"s","enabled":true}`)
	doLogin := func() *httptest.ResponseRecorder {
		rec := httptest.NewRecorder()
		router.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/api/v1/auth/oidc/login", nil))
		u, _ := url.Parse(rec.Header().Get("Location"))
		code := simulateIdPIssuesCode(t, u.String())
		rec = httptest.NewRecorder()
		router.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/api/v1/auth/oidc/callback?code="+code+"&state="+u.Query().Get("state"), nil))
		return rec
	}
	readDisplayName := func() string {
		var name string
		if err := db.DB.QueryRow("SELECT COALESCE(display_name,'') FROM users WHERE auth_provider='oidc'").Scan(&name); err != nil {
			t.Fatalf("read oidc user display_name: %v", err)
		}
		return name
	}

	// 首登 JIT 开户；再登录一次走「既有身份 + 刷新」分支，落一个已知旧值。
	idp.claimName.Store("初始显示名")
	if rec := doLogin(); rec.Code != http.StatusFound {
		t.Fatalf("first login status=%d body=%s", rec.Code, rec.Body.String())
	}
	if rec := doLogin(); rec.Code != http.StatusFound {
		t.Fatalf("second login status=%d body=%s", rec.Code, rec.Body.String())
	}
	if got := readDisplayName(); got != "初始显示名" {
		t.Fatalf("display_name=%q, want 初始显示名（重复登录按 claims 刷新）", got)
	}

	// 制造 display_name 写失败（只拦 UPDATE OF display_name，登录链其余写不受影响）。
	if _, err := db.DB.Exec(`CREATE TRIGGER fail_oidc_display_name_update BEFORE UPDATE OF display_name ON users BEGIN SELECT RAISE(ABORT, 'display_name write disabled'); END`); err != nil {
		t.Fatalf("create failing trigger: %v", err)
	}
	var logBuf bytes.Buffer
	origOut := log.Writer()
	log.SetOutput(&logBuf)
	t.Cleanup(func() { log.SetOutput(origOut) })

	idp.claimName.Store("新显示名")
	rec := doLogin()
	if rec.Code != http.StatusFound || !strings.Contains(rec.Header().Get("Location"), "token=") {
		t.Fatalf("display_name 写失败不得中断登录: status=%d location=%q body=%s", rec.Code, rec.Header().Get("Location"), rec.Body.String())
	}
	if !strings.Contains(logBuf.String(), "显示名") {
		t.Fatalf("display_name 写失败必须留痕, captured log=%q", logBuf.String())
	}
	if got := readDisplayName(); got != "初始显示名" {
		t.Fatalf("display_name=%q, want 保持旧值（写失败不得半写）", got)
	}

	// 存储恢复后下次登录自愈。
	if _, err := db.DB.Exec(`DROP TRIGGER fail_oidc_display_name_update`); err != nil {
		t.Fatalf("drop trigger: %v", err)
	}
	if rec := doLogin(); rec.Code != http.StatusFound {
		t.Fatalf("recovery login status=%d body=%s", rec.Code, rec.Body.String())
	}
	if got := readDisplayName(); got != "新显示名" {
		t.Fatalf("display_name=%q, want 新显示名（下次登录自愈）", got)
	}
}
