package handlers

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// strings.HasPrefix(issuer, "http")——「httpxy://evil」可写入并被 discovery/
// 回调链路消费。改 url.Parse + Scheme∈{http,https} 白名单;http/https 正常、
// 空 issuer(清除语义)行为不变。
func TestOIDCSettingsUpdate_rejectsNonHTTPScheme(t *testing.T) {
	// Given
	idp := newMockIdP(t)
	router, _ := setupOIDCTest(t, idp)
	putRaw := func(body string) *httptest.ResponseRecorder {
		req := httptest.NewRequest(http.MethodPut, "/api/v1/settings/oidc", strings.NewReader(body))
		req.Header.Set("Content-Type", "application/json")
		rec := httptest.NewRecorder()
		router.ServeHTTP(rec, req)
		return rec
	}

	// When / Then 1:httpxy scheme 必须 400(现行经 HasPrefix 放行)
	if rec := putRaw(`{"issuer":"httpxy://evil.example.com"}`); rec.Code != http.StatusBadRequest {
		t.Fatalf("httpxy issuer status=%d body=%s, want 400", rec.Code, rec.Body.String())
	}
	// When / Then 2:无 scheme 的裸主机名同样 400
	if rec := putRaw(`{"issuer":"evil.example.com"}`); rec.Code != http.StatusBadRequest {
		t.Fatalf("schemaless issuer status=%d body=%s, want 400", rec.Code, rec.Body.String())
	}
	// 回归:http issuer(mock IdP)照常保存(enabled 缺席保持 false——
	// 启用前置门「启用时 issuer 必填」是既有不变量,不属于本项范围)
	putOIDCConfig(t, router, `{"issuer":"`+idp.issuer+`","client_id":"test-client","client_secret":"super-secret-123"}`)
	// 回归:空 issuer(清除语义)不 400
	if rec := putRaw(`{"issuer":""}`); rec.Code != http.StatusOK {
		t.Fatalf("empty issuer status=%d body=%s, want 200", rec.Code, rec.Body.String())
	}
}

// 纯空白 client_secret 不是「未提供」：实现若先按原串判空、后 TrimSpace，
// "   " 会进入赋值分支并把已存密钥覆盖成空串——保存还返回成功，用户下次
// 「保存并启用」只见「缺 Client Secret」，排障方向指向配置缺失而非本次误操作。
// 文档语义是「空 client_secret=保持现值」，纯空白必须同义（secret 无清除语义，
// 仅 DELETE 可清）。
func TestOIDCSettingsUpdate_blankClientSecretKeepsStoredSecret(t *testing.T) {
	idp := newMockIdP(t)
	router, _ := setupOIDCTest(t, idp)
	putOIDCConfig(t, router, `{"issuer":"`+idp.issuer+`","client_id":"test-client","client_secret":"super-secret-123"}`)
	putRaw := func(body string) *httptest.ResponseRecorder {
		req := httptest.NewRequest(http.MethodPut, "/api/v1/settings/oidc", strings.NewReader(body))
		req.Header.Set("Content-Type", "application/json")
		rec := httptest.NewRecorder()
		router.ServeHTTP(rec, req)
		return rec
	}

	for _, blank := range []string{"   ", "\t", " \n "} {
		if rec := putRaw(fmt.Sprintf(`{"client_secret":%q}`, blank)); rec.Code != http.StatusOK {
			t.Fatalf("blank secret %q status=%d body=%s, want 200（保持现值）", blank, rec.Code, rec.Body.String())
		}
		cfg, err := loadOIDCConfig()
		if err != nil {
			t.Fatalf("read stored config: %v", err)
		}
		if cfg.ClientSecret != "super-secret-123" {
			t.Fatalf("blank secret %q 覆盖了已存密钥：stored=%q, want super-secret-123", blank, cfg.ClientSecret)
		}
	}

	// 回归：真实新值仍按 trim 后落库（空白不进入密钥本体）。
	putOIDCConfig(t, router, `{"client_secret":"  new-secret-456  "}`)
	cfg, err := loadOIDCConfig()
	if err != nil {
		t.Fatalf("read stored config: %v", err)
	}
	if cfg.ClientSecret != "new-secret-456" {
		t.Fatalf("stored=%q, want new-secret-456（非空白值照常替换并 trim）", cfg.ClientSecret)
	}
}
