package handlers

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/gin-gonic/gin"
)

// 导入侧 upstream_keepalive_timeout 缺非负门——写侧拒绝
// 负值，负值落库后基础设置保存恒 400、规则编辑被同门卡死。
func TestValidateV2BackupRuntimeSettings_normalizesNegativeKeepalive(t *testing.T) {
	config := map[string]any{"upstream_keepalive_timeout": int64(-5)}
	if err := validateV2BackupRuntimeSettings(config, nil); err != nil {
		t.Fatalf("runtime settings: %v", err)
	}
	if got, ok := backupInteger(config["upstream_keepalive_timeout"]); !ok || got != 0 {
		t.Fatalf("keepalive=%v, want 0（负数必须归零）", config["upstream_keepalive_timeout"])
	}

	// 回归形状：合法值原样保留（不得把钳制扩大成恒零）。
	config = map[string]any{"upstream_keepalive_timeout": int64(60)}
	if err := validateV2BackupRuntimeSettings(config, nil); err != nil {
		t.Fatalf("runtime settings: %v", err)
	}
	if got, _ := backupInteger(config["upstream_keepalive_timeout"]); got != 60 {
		t.Fatalf("keepalive=%d, want 60", got)
	}
}

// github_proxy_url 与 oidc_config 必须前移到导入门。
func TestValidateV2BackupRuntimeSettings_rejectsUnsafeGlobalWriteSideValues(t *testing.T) {
	if err := validateV2BackupRuntimeSettings(map[string]any{"github_proxy_url": "http://evil.example/steal/"}, nil); err == nil {
		t.Fatal("白名单外 GitHub 代理地址必须 400")
	}
	if err := validateV2BackupRuntimeSettings(map[string]any{"oidc_config": "{not-json"}, nil); err == nil {
		t.Fatal("损坏 OIDC 配置必须 400")
	}
	if err := validateV2BackupRuntimeSettings(map[string]any{"oidc_config": `{"enabled":true,"issuer":"","client_id":""}`}, nil); err == nil {
		t.Fatal("启用但缺 issuer/client_id 的 OIDC 配置必须 400")
	}
	// 回归形状：空 OIDC（未配置）与合法白名单代理放行。
	okConfigs := []map[string]any{
		{"oidc_config": ""},
		{"github_proxy_url": "https://v4.gh-proxy.org/"},
	}
	for _, cfg := range okConfigs {
		if err := validateV2BackupRuntimeSettings(cfg, nil); err != nil {
			t.Fatalf("config=%v 应放行: %v", cfg, err)
		}
	}
}

// nodes 重复身份行必须在行级门 400 点名，而不是事务内
// UNIQUE 约束失败以 500 整体回滚。
func TestValidateV2BackupNodeRows_rejectsDuplicateIdentity(t *testing.T) {
	rows := []map[string]any{
		{"name": "n1", "ip_address": "10.0.0.5", "port": int64(8000)},
		{"name": "n2", "ip_address": "10.0.0.5", "port": int64(8000)},
	}
	err := validateV2BackupNodeRows(rows)
	if err == nil {
		t.Fatal("重复 (ip_address, port) 行必须 400")
	}
	if !strings.Contains(err.Error(), "第 1 行") || !strings.Contains(err.Error(), "重复") {
		t.Fatalf("err=%v, want 点名重复行", err)
	}
	// 回归形状：不同身份放行（端口缺省按 schema 默认 8000 归并身份）。
	ok := []map[string]any{
		{"name": "n1", "ip_address": "10.0.0.5", "port": int64(8000)},
		{"name": "n2", "ip_address": "10.0.0.6"},
	}
	if err := validateV2BackupNodeRows(ok); err != nil {
		t.Fatalf("不同身份应放行: %v", err)
	}
}

// 证书物化只针对 manual 源——acme_dns 行不得把私钥
// 物化到 /app/certs（DB 已不引用的残留材料）。
func TestCollectImportCertificates_skipsNonManualTLSSource(t *testing.T) {
	rows := []map[string]any{
		{"caddy_id": "lb_acme", "name": "acme", "domain": "acme.test", "protocol": "http", "enable_tls": int64(1), "tls_source": "acme_dns", "tls_cert": "CERT", "tls_key": "KEY"},
		{"caddy_id": "lb_manual", "name": "manual", "domain": "manual.test", "protocol": "http", "enable_tls": int64(1), "tls_source": "manual", "tls_cert": "CERT", "tls_key": "KEY"},
		{"caddy_id": "lb_tls_off", "name": "off", "domain": "off.test", "protocol": "http", "enable_tls": int64(0), "tls_source": "manual", "tls_cert": "CERT", "tls_key": "KEY"},
		{"caddy_id": "lb_tcp", "name": "tcp", "domain": "", "protocol": "tcp", "enable_tls": int64(1), "tls_source": "manual", "tls_cert": "CERT", "tls_key": "KEY"},
	}
	certs, _ := collectImportCertificates(rows)
	if len(certs) != 1 || certs[0].ruleID != "lb_manual" {
		t.Fatalf("certs=%+v, want 仅 lb_manual（acme_dns/未启 TLS/TCP 均不得物化）", certs)
	}
}

// v2 导入空体必须报「内容为空」，而不是落入通用格式错误。
func TestImportConfigBackup_emptyBodyIsExplicit(t *testing.T) {
	h := newBackupTestHandlers(t)
	gin.SetMode(gin.TestMode)
	router := gin.New()
	router.POST("/config/import", h.ImportConfigBackup)

	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/config/import", strings.NewReader(""))
	req.Header.Set("Content-Type", "application/json")
	router.ServeHTTP(rec, req)

	if rec.Code != http.StatusBadRequest {
		t.Fatalf("status=%d body=%s, want 400", rec.Code, rec.Body.String())
	}
	if !strings.Contains(rec.Body.String(), "内容为空") {
		t.Fatalf("body=%s, want 显式「内容为空」", rec.Body.String())
	}
}

// BOM 剥离先于 lbbak 魔数检测——BOM+lbbak 必须得到
// 「请使用 /api/v1/config/import」指引而非「不是有效的 JSON」。
func TestImportV1Config_BOMWrappedLbbakGetsV2Hint(t *testing.T) {
	h := newBackupTestHandlers(t)
	gin.SetMode(gin.TestMode)
	router := gin.New()
	router.POST("/config/import/v1", h.ImportV1Config)

	body := append([]byte{0xef, 0xbb, 0xbf, 0x1f, 0x8b}, []byte("fake-gzip-body")...)
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/config/import/v1", strings.NewReader(string(body)))
	req.Header.Set("Content-Type", "application/json")
	router.ServeHTTP(rec, req)

	if rec.Code != http.StatusBadRequest {
		t.Fatalf("status=%d, want 400", rec.Code)
	}
	if !strings.Contains(rec.Body.String(), "lbbak") {
		t.Fatalf("body=%s, want lbbak 端点指引（BOM 必须先剥离）", rec.Body.String())
	}
}
