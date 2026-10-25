package handlers

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/gin-gonic/gin"
	"lazy-balancer-v2/internal/db"
)

// global_config.dns_credentials 是退役列（启动迁移删除列、读写两面收口、
// 备份三面排除）：请求体携带该键不得落库，也不得在变更清单/预览面声称
// 「DNS凭证」被修改——否则旧客户端仍以为可以写全局 DNS 凭证。
func TestUpdateConfig_ignoresLegacyGlobalDNSCredentials(t *testing.T) {
	// Given
	handler := newBackupTestHandlers(t)
	gin.SetMode(gin.TestMode)
	router := gin.New()
	router.PUT("/config", handler.UpdateConfig)

	// When
	req := httptest.NewRequest(http.MethodPut, "/config", strings.NewReader(`{"source":"acme","dns_credentials":"new-id,new-token"}`))
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	router.ServeHTTP(rec, req)

	// Then 1：请求本身成功（旧语义会写入该列）。
	if rec.Code != http.StatusOK {
		t.Fatalf("status=%d body=%s, want 200", rec.Code, rec.Body.String())
	}
	// Then 2：列已随退役删除——请求体值无处落库，且列不存在。
	var columnCount int
	if err := db.DB.QueryRow(`SELECT COUNT(*) FROM pragma_table_info('global_config') WHERE name='dns_credentials'`).Scan(&columnCount); err != nil {
		t.Fatalf("query global_config schema: %v", err)
	}
	if columnCount != 0 {
		t.Fatal("global_config.dns_credentials 列仍存在（退役列必须由启动迁移删除）")
	}
	// Then 3：变更清单不得把该键算作「DNS凭证」变更。
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
