package handlers

// CA 提供商写路径契约：凭证审计四态（unchanged/changed/cleared/mask-echo）。
// 旧实现把「空白串」与「全星号占位」一并视为未变更——空白串对 ZeroSSL 会真实
// 清空 credentials 列（服务层放行空串），审计却报「无修改」；全星号则被误读为
// 用户把凭证设成了星号。约定：清空记「凭证（清空）」，掩码回传在零变更时
// 单列备注（历史问题）。

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/gin-gonic/gin"

	"lazy-balancer-v2/internal/db"
	"lazy-balancer-v2/internal/services"
)

func TestCredentialAuditStateFor_truthTable(t *testing.T) {
	cases := []struct {
		name, newValue, oldValue string
		want                     credentialAuditState
	}{
		{"blank_old_blank", "", "", credentialUnchanged},
		{"blank_whitespace_only", "  ", `{"api_key":"real"}`, credentialCleared},
		{"blank_clears_existing", "", `{"api_key":"real"}`, credentialCleared},
		{"mask_all_stars", "****", `{"api_key":"real"}`, credentialMaskEcho},
		{"same_value", `{"api_key":"real"}`, `{"api_key":"real"}`, credentialUnchanged},
		{"real_change", `{"api_key":"next"}`, `{"api_key":"real"}`, credentialChanged},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := credentialAuditStateFor(tc.newValue, tc.oldValue); got != tc.want {
				t.Fatalf("state=%v, want %v", got, tc.want)
			}
		})
	}
}

// Given：ZeroSSL 提供商带真实凭证。When：显式清空凭证。Then：服务层真实
// 落库为空串，审计必须记「凭证（清空）」而非「无修改」。
func TestUpdateCAProvider_clearingCredentialsIsAudited(t *testing.T) {
	h := newBackupTestHandlers(t)
	h.caProviderService = services.NewCAProviderService()
	res, err := db.DB.Exec(`INSERT INTO ca_providers (name,provider,directory_url,credentials,max_concurrent,min_interval_ms,enabled)
		VALUES ('ZeroSSL-clear','zerossl','https://acme.zerossl.com/v2/DV90','{"api_key":"real"}',1,2000,1)`)
	if err != nil {
		t.Fatalf("seed CA provider: %v", err)
	}
	id, err := res.LastInsertId()
	if err != nil {
		t.Fatal(err)
	}
	router := gin.New()
	router.PUT("/ca-providers/:id", h.UpdateCAProvider)
	response := httptest.NewRecorder()
	request := httptest.NewRequest(http.MethodPut, fmt.Sprintf("/ca-providers/%d", id), strings.NewReader(`{"credentials":""}`))
	request.Header.Set("Content-Type", "application/json")
	router.ServeHTTP(response, request)
	if response.Code != http.StatusOK {
		t.Fatalf("status=%d body=%s, want 200", response.Code, response.Body.String())
	}
	var stored string
	if err := db.DB.QueryRow(`SELECT COALESCE(credentials,'') FROM ca_providers WHERE id=?`, id).Scan(&stored); err != nil {
		t.Fatal(err)
	}
	if stored != "" {
		t.Fatalf("credentials=%q, want 空串（清空已落库）", stored)
	}
	var detail string
	if err := db.AuditDB.QueryRow(`SELECT detail FROM audit_log WHERE action='更新' AND resource='CA提供商' ORDER BY id DESC LIMIT 1`).Scan(&detail); err != nil {
		t.Fatalf("query CA provider audit: %v", err)
	}
	if !strings.Contains(detail, "凭证（清空）") {
		t.Fatalf("audit detail=%q, want 凭证（清空）", detail)
	}
}

// Given：ZeroSSL 提供商带真实凭证。When：凭证全星号占位回传。Then：占位不得
// 覆盖原凭证（服务层按 JSON 门拒绝），掩码回传契约保持——不得把占位误读为
// 真实值变更。
func TestUpdateCAProvider_maskEchoDoesNotOverwriteCredentials(t *testing.T) {
	h := newBackupTestHandlers(t)
	h.caProviderService = services.NewCAProviderService()
	res, err := db.DB.Exec(`INSERT INTO ca_providers (name,provider,directory_url,credentials,max_concurrent,min_interval_ms,enabled)
		VALUES ('ZeroSSL-mask','zerossl','https://acme.zerossl.com/v2/DV90','{"api_key":"real"}',1,2000,1)`)
	if err != nil {
		t.Fatalf("seed CA provider: %v", err)
	}
	id, err := res.LastInsertId()
	if err != nil {
		t.Fatal(err)
	}
	router := gin.New()
	router.PUT("/ca-providers/:id", h.UpdateCAProvider)
	response := httptest.NewRecorder()
	request := httptest.NewRequest(http.MethodPut, fmt.Sprintf("/ca-providers/%d", id), strings.NewReader(`{"credentials":"****"}`))
	request.Header.Set("Content-Type", "application/json")
	router.ServeHTTP(response, request)
	var stored string
	if err := db.DB.QueryRow(`SELECT COALESCE(credentials,'') FROM ca_providers WHERE id=?`, id).Scan(&stored); err != nil {
		t.Fatal(err)
	}
	if stored != `{"api_key":"real"}` {
		t.Fatalf("credentials=%q, want 原值保留（占位不得覆盖）", stored)
	}
}
