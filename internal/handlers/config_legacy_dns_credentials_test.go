package handlers

import (
	"database/sql"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/gin-gonic/gin"
	"lazy-balancer-v2/internal/db"
)

// global_config.dns_credentials 是遗留列：读路径不回显、写路径已移除，
// 请求体携带该键不得落库，也不得在变更清单/预览面声称「DNS凭证」被修改。
func TestUpdateConfig_ignoresLegacyGlobalDNSCredentials(t *testing.T) {
	// Given：库里预置一个旧版本残留值（升级用户形态）。
	handler := newBackupTestHandlers(t)
	gin.SetMode(gin.TestMode)
	router := gin.New()
	router.PUT("/config", handler.UpdateConfig)
	if _, err := db.DB.Exec(`UPDATE global_config SET dns_credentials='legacy-id,legacy-token' WHERE id=1`); err != nil {
		t.Fatalf("seed legacy credentials: %v", err)
	}

	// When
	req := httptest.NewRequest(http.MethodPut, "/config", strings.NewReader(`{"source":"acme","dns_credentials":"new-id,new-token"}`))
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	router.ServeHTTP(rec, req)

	// Then 1：请求本身成功（旧语义会写入该列）。
	if rec.Code != http.StatusOK {
		t.Fatalf("status=%d body=%s, want 200", rec.Code, rec.Body.String())
	}
	var stored sql.NullString
	if err := db.DB.QueryRow(`SELECT dns_credentials FROM global_config WHERE id=1`).Scan(&stored); err != nil {
		t.Fatalf("read stored credentials: %v", err)
	}
	if stored.String == "new-id,new-token" {
		t.Fatal("遗留列 dns_credentials 仍被写入（请求体值已落库）")
	}
	// Then 2：变更清单不得把该键算作「DNS凭证」变更。
	var body struct {
		Message string `json:"message"`
		Data    struct {
			Changed bool     `json:"changed"`
			Changes []string `json:"changes"`
		} `json:"data"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	if body.Message != "配置无变化" {
		t.Fatalf("message=%q, want 配置无变化（仅遗留键时不得声称有变更）", body.Message)
	}
	for _, change := range body.Data.Changes {
		if change == "DNS凭证" {
			t.Fatalf("变更清单仍包含 DNS凭证: %v", body.Data.Changes)
		}
	}
}
