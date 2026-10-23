package handlers

// OIDC 自由文本字段上限：保存侧超限 400，公开状态端点对存量坏值按同一预算
// 截断（带外写入的历史值可能是任意长度）。

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"lazy-balancer-v2/internal/db"
)

func TestOIDCSettingsUpdate_rejectsOversizedFreeTextFields(t *testing.T) {
	router, _ := setupOIDCTest(t, newMockIdP(t))
	cases := []struct {
		name string
		body string
	}{
		{"display_name", `{"display_name":"` + strings.Repeat("长", oidcDisplayNameMaxRunes+1) + `"}`},
		{"client_id", `{"client_id":"` + strings.Repeat("c", 256) + `"}`},
		{"issuer", `{"issuer":"https://` + strings.Repeat("a", 512) + `"}`},
		{"client_secret", `{"client_secret":"` + strings.Repeat("s", 513) + `"}`},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodPut, "/api/v1/settings/oidc", strings.NewReader(tc.body))
			req.Header.Set("Content-Type", "application/json")
			rec := httptest.NewRecorder()
			router.ServeHTTP(rec, req)
			if rec.Code != http.StatusBadRequest {
				t.Fatalf("status=%d body=%s, want 400", rec.Code, rec.Body.String())
			}
			if !strings.Contains(rec.Body.String(), "过长") {
				t.Fatalf("message=%s, want 超限友好文案", rec.Body.String())
			}
		})
	}

	// 边界内照常保存（30 字符展示名 = 前端 maxlength 上限）。
	body := `{"display_name":"` + strings.Repeat("长", oidcDisplayNameMaxRunes) + `"}`
	req := httptest.NewRequest(http.MethodPut, "/api/v1/settings/oidc", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	router.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("status=%d body=%s, want 200（上限值本身合法）", rec.Code, rec.Body.String())
	}
}

func TestOIDCStatus_truncatesOversizedStoredDisplayName(t *testing.T) {
	router, _ := setupOIDCTest(t, newMockIdP(t))
	oversized := strings.Repeat("x", 100000)
	if err := saveOIDCConfig(OIDCConfig{
		Enabled: true, Issuer: "https://idp.example.com", ClientID: "cid", ClientSecret: "sec",
		DisplayName: oversized,
	}); err != nil {
		t.Fatalf("seed stored config: %v", err)
	}
	// 前置：坏值确实落库（不是被写侧悄悄拦住）。
	var stored string
	if err := db.DB.QueryRow(`SELECT COALESCE(oidc_config,'') FROM global_config WHERE id=1`).Scan(&stored); err != nil {
		t.Fatalf("read stored config: %v", err)
	}
	if !strings.Contains(stored, oversized) {
		t.Fatal("fixture 未真正写入超长展示名")
	}

	rec := httptest.NewRecorder()
	router.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/api/v1/auth/oidc/status", nil))
	if rec.Code != http.StatusOK {
		t.Fatalf("status code=%d body=%s", rec.Code, rec.Body.String())
	}
	if rec.Body.Len() >= 1024 {
		t.Fatalf("公开响应体 %d 字节，want <1KB（展示名须截断）", rec.Body.Len())
	}
	var resp struct {
		Data struct {
			Enabled     bool   `json:"enabled"`
			DisplayName string `json:"display_name"`
		} `json:"data"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatalf("decode status: %v", err)
	}
	if !resp.Data.Enabled {
		t.Fatal("合规 issuer 应保持 enabled=true")
	}
	if runes := []rune(resp.Data.DisplayName); len(runes) > oidcDisplayNameMaxRunes {
		t.Fatalf("display_name %d 字符，want ≤%d", len(runes), oidcDisplayNameMaxRunes)
	}
}
