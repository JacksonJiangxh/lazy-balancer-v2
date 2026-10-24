package handlers

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"

	"github.com/gin-gonic/gin"

	"lazy-balancer-v2/internal/db"
)

func putCertificateConfig(t *testing.T, h *Handlers, id int64, body string) *httptest.ResponseRecorder {
	t.Helper()
	router := gin.New()
	router.PUT("/certificate-configs/:id", h.UpdateCertificateConfig)
	response := httptest.NewRecorder()
	request := httptest.NewRequest(http.MethodPut, "/certificate-configs/"+strconv.FormatInt(id, 10), strings.NewReader(body))
	request.Header.Set("Content-Type", "application/json")
	router.ServeHTTP(response, request)
	return response
}

func seedCertificateConfigRow(t *testing.T, name, credentials string) int64 {
	t.Helper()
	result, err := db.DB.Exec(`INSERT INTO certificate_configs (name,dns_provider,dns_credentials,enabled)
		VALUES (?, 'dnspod', ?, 1)`, name, credentials)
	if err != nil {
		t.Fatalf("seed certificate config: %v", err)
	}
	id, err := result.LastInsertId()
	if err != nil {
		t.Fatalf("read certificate config id: %v", err)
	}
	return id
}

func storedCertificateCredentials(t *testing.T, id int64) (name, raw string, stored map[string]string) {
	t.Helper()
	if err := db.DB.QueryRow("SELECT name, COALESCE(dns_credentials,'') FROM certificate_configs WHERE id=?", id).Scan(&name, &raw); err != nil {
		t.Fatalf("read certificate config: %v", err)
	}
	stored = map[string]string{}
	if err := json.Unmarshal([]byte(raw), &stored); err != nil {
		t.Fatalf("stored credentials %q are not valid JSON: %v", raw, err)
	}
	return name, raw, stored
}

// Given 库内 dns_credentials 不是合法 JSON（带外改库/损坏的集群快照）。
// When 管理员提交完整新凭证（无掩码占位）。
// Then 200 且整列覆写：损坏行必须能从写路径自愈，否则名称/启用态/凭据都改
// 不了，只能删除重建（被规则引用时还被 409）。
func TestUpdateCertificateConfig_fullCredentialsRepairCorruptedStorage(t *testing.T) {
	h := newBackupTestHandlers(t)
	id := seedCertificateConfigRow(t, "legacy", "not-json")

	response := putCertificateConfig(t, h, id,
		`{"name":"repaired","dns_credentials":{"auth_mode":"dnspod","app_id":"new-id","app_token":"new-token"}}`)
	if response.Code != http.StatusOK {
		t.Fatalf("status=%d body=%s, want 200（完整新凭证应可覆盖损坏列）", response.Code, response.Body.String())
	}

	name, _, stored := storedCertificateCredentials(t, id)
	if name != "repaired" {
		t.Fatalf("name=%q, want repaired", name)
	}
	if stored["app_id"] != "new-id" || stored["app_token"] != "new-token" {
		t.Fatalf("stored credentials=%v, want submitted pair", stored)
	}
}

// Given 库内配置使用 DNSPod 认证族（app_id/app_token）。
// When 管理员把认证方式切到腾讯云并提交新族凭据。
// Then 旧族字段从库中删除（不是留在 JSON 里等切回时复活），且审计 detail
// 点名被清除的字段（数据删除影响必须可追溯）。
func TestUpdateCertificateConfig_prunesOtherAuthFamilyOnModeSwitch(t *testing.T) {
	h := newBackupTestHandlers(t)
	id := seedCertificateConfigRow(t, "switch", `{"auth_mode":"dnspod","app_id":"old-id","app_token":"old-token"}`)

	response := putCertificateConfig(t, h, id,
		`{"dns_credentials":{"auth_mode":"tencent_cloud","secret_id":"sid","secret_key":"skey"}}`)
	if response.Code != http.StatusOK {
		t.Fatalf("status=%d body=%s, want 200", response.Code, response.Body.String())
	}

	_, _, stored := storedCertificateCredentials(t, id)
	for _, stale := range []string{"app_id", "app_token", "api_token", "mode"} {
		if _, ok := stored[stale]; ok {
			t.Fatalf("stale field %q retained after auth-mode switch: %v", stale, stored)
		}
	}
	if stored["auth_mode"] != "tencent_cloud" || stored["secret_id"] != "sid" || stored["secret_key"] != "skey" {
		t.Fatalf("stored credentials=%v, want tencent family only", stored)
	}

	detail := latestAuditDetail(t, "更新", "DNS配置")
	for _, want := range []string{"清除旧认证方式凭据", "app_id", "app_token"} {
		if !strings.Contains(detail, want) {
			t.Fatalf("audit detail=%q, want %q（删除影响必须留痕）", detail, want)
		}
	}
}

// Given 同一认证族内的稀疏 PATCH（掩码字段回传）。
// When 保存配置。
// Then 未提交的字段仍从库值继承——切换族的清理不得扩大成「同族也丢字段」。
func TestUpdateCertificateConfig_sameAuthFamilyKeepsUnsubmittedCredentials(t *testing.T) {
	h := newBackupTestHandlers(t)
	id := seedCertificateConfigRow(t, "sparse", `{"auth_mode":"dnspod","app_id":"old-id","app_token":"old-token"}`)

	response := putCertificateConfig(t, h, id,
		`{"dns_credentials":{"auth_mode":"dnspod","app_id":"old-id","app_token":"***"}}`)
	if response.Code != http.StatusOK {
		t.Fatalf("status=%d body=%s, want 200", response.Code, response.Body.String())
	}

	_, _, stored := storedCertificateCredentials(t, id)
	if stored["app_token"] != "old-token" || stored["app_id"] != "old-id" {
		t.Fatalf("stored credentials=%v, want库值继承", stored)
	}
}

// Given certificate_configs.enabled 为 NULL（ALTER 遗留/带外改库）。
// When 规则绑定校验 ACME 引用。
// Then 按启用处理——与列表展示（COALESCE(enabled,1)）及编辑基线同口径；
// 展示「启用」的行必须能绑定，禁用行仍拒绝。
func TestValidateRuleACMEReferences_treatsNullEnabledAsEnabled(t *testing.T) {
	newBackupTestHandlers(t)
	if _, err := db.DB.Exec(`INSERT INTO certificate_configs (id,name,dns_provider,dns_credentials,enabled) VALUES
		(41,'null-enabled','dnspod','{}',NULL),
		(42,'disabled','dnspod','{}',0)`); err != nil {
		t.Fatalf("seed certificate configs: %v", err)
	}

	input := acmeReferenceInput{EnableTLS: true, TLSSource: "acme_dns", ACMEConfigID: 41}
	if err := validateRuleACMEReferences(input); err != nil {
		t.Fatalf("NULL enabled 配置在展示/编辑基线为启用，绑定校验必须同口径: %v", err)
	}

	input.ACMEConfigID = 42
	err := validateRuleACMEReferences(input)
	if err == nil || !strings.Contains(err.Error(), "不存在或已禁用") {
		t.Fatalf("disabled config err=%v, want 不存在或已禁用", err)
	}
}
