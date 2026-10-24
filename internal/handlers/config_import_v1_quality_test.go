package handlers

// v1 导入的证书质量告警、证书产物清理口径与事务内早退审计，以及受信代理
// 校验的 DB 故障分类（非载荷错误不得回 400 + 底层错误文本）。

import (
	"database/sql"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/gin-gonic/gin"

	"lazy-balancer-v2/internal/db"
	"lazy-balancer-v2/internal/services"
)

// v1CertBackupJSON 构造一条带手动证书的 v1（nginx 版）备份。
func v1CertBackupJSON(t *testing.T, ruleName, domain, certPEM, keyPEM string) []byte {
	t.Helper()
	fixture := map[string]any{
		"proxy_config": map[string]any{"config": []any{
			map[string]any{"pk": 1, "fields": map[string]any{
				"proxy_name": ruleName, "protocol": true, "listen": 8581,
				"server_name": domain, "status": true, "ssl": true,
				"ssl_cert": certPEM, "ssl_key": keyPEM, "upstream_list": []int{1},
			}},
		}},
		"upstream_config": map[string]any{"config": []any{
			map[string]any{"pk": 1, "fields": map[string]any{"status": true, "address": "127.0.0.1", "port": 9581, "weight": 100}},
		}},
	}
	body, err := json.Marshal(fixture)
	if err != nil {
		t.Fatalf("marshal v1 fixture: %v", err)
	}
	return body
}

func exportCertificateFixture(t *testing.T) (certPEM, keyPEM string) {
	t.Helper()
	now := time.Now()
	certPEM, keyPEM, err := generateTestCert("other.example.test", now.Add(-48*time.Hour), now.Add(-24*time.Hour))
	if err != nil {
		t.Fatalf("generate cert: %v", err)
	}
	return certPEM, keyPEM
}

// Given v1 备份里的手动证书已过期且不覆盖规则域名。
// When 预览导入。
// Then 预览 warnings 与「规则保存 / v2 导入」同源给出质量告警（v1 此前零判定）。
func TestValidateConfigImport_v1WarnsCertificateQuality(t *testing.T) {
	h := newBackupTestHandlers(t)
	certPEM, keyPEM := exportCertificateFixture(t)
	body := v1CertBackupJSON(t, "v1-cert-rule", "mismatch.example.test", certPEM, keyPEM)

	gin.SetMode(gin.TestMode)
	router := gin.New()
	router.POST("/config/validate", h.ValidateConfigImport)
	request := httptest.NewRequest(http.MethodPost, "/config/validate", strings.NewReader(string(body)))
	request.Header.Set("Content-Type", "application/json")
	recorder := httptest.NewRecorder()
	router.ServeHTTP(recorder, request)

	if recorder.Code != http.StatusOK {
		t.Fatalf("status=%d body=%s, want 200", recorder.Code, recorder.Body.String())
	}
	var resp struct {
		Data struct {
			Valid    bool     `json:"valid"`
			Warnings []string `json:"warnings"`
		} `json:"data"`
	}
	if err := json.Unmarshal(recorder.Body.Bytes(), &resp); err != nil {
		t.Fatalf("parse response: %v", err)
	}
	if !resp.Data.Valid {
		t.Fatalf("valid=false body=%s", recorder.Body.String())
	}
	joined := strings.Join(resp.Data.Warnings, "；")
	for _, want := range []string{"证书已过期", "证书域名与规则域名不匹配", "规则 v1-cert-rule"} {
		if !strings.Contains(joined, want) {
			t.Fatalf("预览 warnings=%q, want 含 %q", joined, want)
		}
	}
}

// Given 同上备份。
// When 实际导入。
// Then 导入响应 warnings 带同一组证书质量告警（不阻断导入，仍 200）。
func TestImportV1Config_warnsCertificateQuality(t *testing.T) {
	h := newBackupTestHandlers(t)
	certDir := t.TempDir()
	t.Cleanup(services.SetCertDirForTest(certDir))
	certPEM, keyPEM := exportCertificateFixture(t)
	body := v1CertBackupJSON(t, "v1-cert-rule", "mismatch.example.test", certPEM, keyPEM)

	gin.SetMode(gin.TestMode)
	router := gin.New()
	router.POST("/config/import/v1", h.ImportV1Config)
	request := httptest.NewRequest(http.MethodPost, "/config/import/v1", strings.NewReader(string(body)))
	request.Header.Set("Content-Type", "application/json")
	recorder := httptest.NewRecorder()
	router.ServeHTTP(recorder, request)

	if recorder.Code != http.StatusOK {
		t.Fatalf("status=%d body=%s, want 200（证书质量告警不阻断导入）", recorder.Code, recorder.Body.String())
	}
	var resp struct {
		Data struct {
			Warnings []string `json:"warnings"`
		} `json:"data"`
	}
	if err := json.Unmarshal(recorder.Body.Bytes(), &resp); err != nil {
		t.Fatalf("parse response: %v", err)
	}
	joined := strings.Join(resp.Data.Warnings, "；")
	for _, want := range []string{"证书已过期", "证书域名与规则域名不匹配", "规则 v1-cert-rule（"} {
		if !strings.Contains(joined, want) {
			t.Fatalf("导入 warnings=%q, want 含 %q", joined, want)
		}
	}
}

// Given 任意 v1 备份。
// When 预览导入。
// Then 文案如实说明旧规则的证书任务/证书材料/日志会随规则替换清理
// （此前写「证书任务保持不变」，与 collectPostCommitCleanup 的实际行为相反）。
func TestValidateConfigImport_v1DeclaresCertArtifactsCleanup(t *testing.T) {
	h := newBackupTestHandlers(t)
	body := v1ImportFailureBackup("v1-copy-probe")

	gin.SetMode(gin.TestMode)
	router := gin.New()
	router.POST("/config/validate", h.ValidateConfigImport)
	request := httptest.NewRequest(http.MethodPost, "/config/validate", strings.NewReader(body))
	request.Header.Set("Content-Type", "application/json")
	recorder := httptest.NewRecorder()
	router.ServeHTTP(recorder, request)

	if recorder.Code != http.StatusOK {
		t.Fatalf("status=%d body=%s, want 200", recorder.Code, recorder.Body.String())
	}
	raw := recorder.Body.String()
	if !strings.Contains(raw, "证书任务、证书材料与日志将随规则替换一并清理") {
		t.Fatalf("预览缺少证书产物清理说明：%s", raw)
	}
	if strings.Contains(raw, "证书任务保持不变") {
		t.Fatalf("预览仍声称「证书任务保持不变」：%s", raw)
	}
}

// Given 导入事务内 DELETE 旧规则失败（磁盘/锁故障形态）。
// When v1 导入。
// Then 500 且操作审计留「导入失败」+ 失败阶段（此前该分支零留痕）。
func TestImportV1Config_earlyCleanupFailureIsAudited(t *testing.T) {
	h := newBackupTestHandlers(t)
	// 必须有既有规则：SQLite 的 BEFORE DELETE 触发器只在确实删除行时触发，
	// 空表 DELETE 不会失败。
	if _, err := db.DB.Exec(`
		INSERT INTO lb_rules (caddy_id,name,domain,protocol,listen_port,enabled) VALUES
		('lb_audit_old','old','old.example.test','http',8582,1)`); err != nil {
		t.Fatalf("seed existing rule: %v", err)
	}
	if _, err := db.DB.Exec(`CREATE TRIGGER fail_lb_rules_delete BEFORE DELETE ON lb_rules BEGIN SELECT RAISE(ABORT, 'injected delete failure'); END;`); err != nil {
		t.Fatalf("create trigger: %v", err)
	}

	gin.SetMode(gin.TestMode)
	router := gin.New()
	router.POST("/config/import/v1", h.ImportV1Config)
	request := httptest.NewRequest(http.MethodPost, "/config/import/v1", strings.NewReader(v1ImportFailureBackup("v1-audit-probe")))
	request.Header.Set("Content-Type", "application/json")
	recorder := httptest.NewRecorder()
	router.ServeHTTP(recorder, request)

	if recorder.Code != http.StatusInternalServerError {
		t.Fatalf("status=%d body=%s, want 500", recorder.Code, recorder.Body.String())
	}
	var detail string
	if err := db.AuditDB.QueryRow(`SELECT detail FROM audit_log WHERE action='导入失败' AND resource='配置备份' ORDER BY id DESC LIMIT 1`).Scan(&detail); err != nil {
		t.Fatalf("操作审计缺少事务内早退失败留痕: %v", err)
	}
	if !strings.Contains(detail, "清理旧规则") {
		t.Fatalf("审计 detail=%q, want 含失败阶段「清理旧规则」", detail)
	}
}

// Given 受信代理校验需要读库（读存量网段/引用展开），而 DB 读取故障。
// When 预览配置更新。
// Then 500 + 固定文案并留痕；不得回 400 让管理员误改载荷，也不得透出底层
// 错误文本（SQL/驱动细节）。
func TestPreviewConfigUpdate_trustedProxyReadFailureReturns500(t *testing.T) {
	h := newBackupTestHandlers(t)
	gin.SetMode(gin.TestMode)
	router := gin.New()
	router.POST("/config/preview", h.PreviewConfigUpdate)

	origDB := db.DB
	broken := sql.OpenDB(rowsErrStubConnector{
		match: func(q string) bool { return strings.Contains(q, "FROM global_config WHERE id=1") },
		cols:  1,
	})
	t.Cleanup(func() { _ = broken.Close() })
	db.DB = broken
	t.Cleanup(func() { db.DB = origDB })

	request := httptest.NewRequest(http.MethodPost, "/config/preview",
		strings.NewReader(`{"source":"caddy","trusted_proxy_ranges":"[\"203.0.113.0/24\"]"}`))
	request.Header.Set("Content-Type", "application/json")
	recorder := httptest.NewRecorder()
	router.ServeHTTP(recorder, request)

	if recorder.Code != http.StatusInternalServerError {
		t.Fatalf("status=%d body=%s, want 500（DB 故障不得映射成载荷非法）", recorder.Code, recorder.Body.String())
	}
	raw := recorder.Body.String()
	if !strings.Contains(raw, "读取受信代理配置失败") {
		t.Fatalf("body=%s, want 固定文案「读取受信代理配置失败」", raw)
	}
	for _, leak := range []string{"注入的迭代失败", "sql:", "SQL"} {
		if strings.Contains(raw, leak) {
			t.Fatalf("body=%s 透出了底层错误文本 %q", raw, leak)
		}
	}

	// 回归形状：DB 正常时非法网段仍是 400 且文案不变。
	db.DB = origDB
	bad := httptest.NewRequest(http.MethodPost, "/config/preview",
		strings.NewReader(`{"source":"caddy","trusted_proxy_ranges":"[\"0.0.0.0/0\"]"}`))
	bad.Header.Set("Content-Type", "application/json")
	badRecorder := httptest.NewRecorder()
	router.ServeHTTP(badRecorder, bad)
	if badRecorder.Code != http.StatusBadRequest {
		t.Fatalf("status=%d body=%s, want 400（纯载荷错误保持 400）", badRecorder.Code, badRecorder.Body.String())
	}
	if !strings.Contains(badRecorder.Body.String(), "过宽") {
		t.Fatalf("body=%s, want 原有网段过宽提示", badRecorder.Body.String())
	}
}

// Given 备份导入链中的受信代理门需要读库，而 DB 读取故障。
// When 导入 v2 备份。
// Then 500 + 固定文案（此前一律「备份校验失败」400 并透出 SQL 文本）。
func TestImportConfigBackup_trustedProxyReadFailureReturns500(t *testing.T) {
	h := newBackupTestHandlers(t)
	completeTables := make(map[string][]map[string]any, len(configBackupTables))
	for _, table := range configBackupTables {
		completeTables[table] = []map[string]any{}
	}
	completeTables["users"] = []map[string]any{{"id": 1, "username": "admin", "password_hash": "hash", "role": "admin", "is_enabled": 1}}
	importCfg := map[string]any{
		"trusted_proxy_ranges": `["203.0.113.0/24"]`,
	}
	backup := configBackup{
		Meta:   configBackupMeta{App: "lazy-balancer-v2", Version: 2, ExportedAt: "2026-10-19T00:00:00Z"},
		Config: importCfg,
		Tables: completeTables,
	}
	backup.Meta.Checksum = checksumBackupPayload(t, completeTables, importCfg)
	body, err := json.Marshal(backup)
	if err != nil {
		t.Fatalf("marshal backup: %v", err)
	}

	gin.SetMode(gin.TestMode)
	router := gin.New()
	router.POST("/config/import", h.ImportConfigBackup)

	origDB := db.DB
	broken := sql.OpenDB(rowsErrStubConnector{
		match: func(q string) bool { return strings.Contains(q, "FROM global_config WHERE id=1") },
		cols:  1,
	})
	t.Cleanup(func() { _ = broken.Close() })
	db.DB = broken
	t.Cleanup(func() { db.DB = origDB })

	request := httptest.NewRequest(http.MethodPost, "/config/import", strings.NewReader(string(body)))
	request.Header.Set("Content-Type", "application/json")
	recorder := httptest.NewRecorder()
	router.ServeHTTP(recorder, request)

	if recorder.Code != http.StatusInternalServerError {
		t.Fatalf("status=%d body=%s, want 500（DB 故障不得说成备份内容非法）", recorder.Code, recorder.Body.String())
	}
	raw := recorder.Body.String()
	if !strings.Contains(raw, "读取受信代理配置失败") {
		t.Fatalf("body=%s, want 固定文案「读取受信代理配置失败」", raw)
	}
	if strings.Contains(raw, "注入的迭代失败") {
		t.Fatalf("body=%s 透出了底层错误文本", raw)
	}
}
