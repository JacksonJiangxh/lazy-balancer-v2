package handlers

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// 纯空白 issuer 与空串同义（清除语义）：归一后判空，否则输入框残留空格会
// 走进 URL 校验分支得到「服务地址须为 https URL」的误导报错。
func TestOIDCSettingsUpdate_blankIssuerClearsConfig(t *testing.T) {
	idp := newMockIdP(t)
	router, _ := setupOIDCTest(t, idp)
	putOIDCConfig(t, router, `{"issuer":"`+idp.issuer+`","client_id":"test-client","client_secret":"super-secret-123"}`)

	req := httptest.NewRequest(http.MethodPut, "/api/v1/settings/oidc", strings.NewReader(`{"issuer":"   "}`))
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	router.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("blank issuer status=%d body=%s, want 200（清除语义）", rec.Code, rec.Body.String())
	}
	cfg, err := loadOIDCConfig()
	if err != nil {
		t.Fatalf("reload oidc config: %v", err)
	}
	if cfg.Issuer != "" {
		t.Fatalf("issuer=%q, want 空（纯空白等价于清除）", cfg.Issuer)
	}
}
