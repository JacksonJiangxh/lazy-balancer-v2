package handlers

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/gin-gonic/gin"

	"lazy-balancer-v2/internal/db"
	"lazy-balancer-v2/internal/services"
)

// fileSourceImportBackup 构造携带启用 file 规则行的 v2 备份 JSON：
// tls_source=file + enable_tls=1 + enabled=1 + 启用上游 + http 端口。
func fileSourceImportBackup(t *testing.T, certPEM, keyPEM, certPath, keyPath string) string {
	t.Helper()
	return fileSourceBackupWithSource(t, "file", certPEM, keyPEM, certPath, keyPath)
}

// fileSourceBackupWithSource 同上，但 tls_source 可注入（白名单反用例需在
// 校验和计算前改值——序列化后改字符串会破坏校验和）。
func fileSourceBackupWithSource(t *testing.T, tlsSource, certPEM, keyPEM, certPath, keyPath string) string {
	t.Helper()
	rule := map[string]any{
		"caddy_id": "lb_file_import", "name": "file-import",
		"protocol": "http", "domain": "file-import.example.test", "listen_port": float64(18443),
		"strategy": "weighted_round_robin", "enabled": true, "enable_tls": true,
		"tls_source": tlsSource,
		"tls_cert":   certPEM, "tls_key": keyPEM,
		"tls_cert_path": certPath, "tls_key_path": keyPath,
	}
	return completeBackupJSON(t, map[string][]map[string]any{
		"lb_rules":   {rule},
		"upstreams":  {{"rule_id": "lb_file_import", "host": "127.0.0.1", "port": float64(9000), "enabled": true, "protocol": "http"}},
		"path_rules": {},
	})
}

func postFileSourceImport(t *testing.T, h *Handlers, body string) *httptest.ResponseRecorder {
	t.Helper()
	gin.SetMode(gin.TestMode)
	router := gin.New()
	router.POST("/config/import", h.ImportConfigBackup)
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/config/import", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	router.ServeHTTP(rec, req)
	return rec
}

// useTemporaryCertDirForTest 把引用证书白名单根目录重定向到用例临时目录
// （与 services 侧夹具同款：测试的源文件路径必须落在白名单目录内才能回填）。
func useTemporaryCertDirForTest(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	restore := services.SetCertDirForTest(dir)
	t.Cleanup(restore)
	return dir
}

// importWarnings 解析导入响应的 warnings 数组。
func importWarnings(t *testing.T, body string) []string {
	t.Helper()
	var envelope struct {
		Data struct {
			Warnings []string `json:"warnings"`
		} `json:"data"`
	}
	if err := json.Unmarshal([]byte(body), &envelope); err != nil {
		t.Fatalf("unmarshal import response: %v", err)
	}
	return envelope.Data.Warnings
}

func warningsJoined(warnings []string) string {
	return strings.Join(warnings, "；")
}

// 正用例：内容与摄取源路径齐备的启用 file 行照常导入；内容在传输归一后清空
// （防私钥随备份扩散，裁定维持现状），提交后按本机源文件回填，且警告注明该行为。
func TestImportConfigBackup_fileRuleWithContentImportsAndBackfills(t *testing.T) {
	h := newBackupTestHandlers(t)
	dir := useTemporaryCertDirForTest(t)
	certPEM, keyPEM, err := generateTestCert("file-import.example.test", time.Now().Add(-time.Hour), time.Now().Add(720*time.Hour))
	if err != nil {
		t.Fatalf("generate cert: %v", err)
	}
	certPath := filepath.Join(dir, "import.crt")
	keyPath := filepath.Join(dir, "import.key")
	if err := os.WriteFile(certPath, []byte(certPEM), 0644); err != nil {
		t.Fatalf("write cert: %v", err)
	}
	if err := os.WriteFile(keyPath, []byte(keyPEM), 0600); err != nil {
		t.Fatalf("write key: %v", err)
	}

	response := postFileSourceImport(t, h, fileSourceImportBackup(t, certPEM, keyPEM, certPath, keyPath))
	if response.Code != http.StatusOK {
		t.Fatalf("import status=%d body=%s, want 200", response.Code, response.Body.String())
	}
	var storedCert, storedKey, storedSource string
	if err := db.DB.QueryRow(`SELECT COALESCE(tls_cert,''), COALESCE(tls_key,''), COALESCE(tls_source,'') FROM lb_rules WHERE caddy_id='lb_file_import'`).Scan(&storedCert, &storedKey, &storedSource); err != nil {
		t.Fatalf("read imported rule: %v", err)
	}
	if storedSource != "file" {
		t.Fatalf("tls_source=%q, want file", storedSource)
	}
	if storedCert != certPEM || storedKey != keyPEM {
		t.Fatal("提交后应按本机源文件回填证书内容（导入链无启动回填兜底）")
	}
	joined := warningsJoined(importWarnings(t, response.Body.String()))
	if !strings.Contains(joined, "引用证书") || !strings.Contains(joined, "回填") {
		t.Fatalf("导入警告应注明引用证书内容清空与回填行为, warnings=%s", joined)
	}
}

// 正用例②：只带摄取源路径（无内容）的启用 file 行同样放行——还原后由
// IngestMissingReferencedCerts 按路径回填；源文件可用时导入后内容即非空。
func TestImportConfigBackup_fileRuleWithPathOnlyImportsAndBackfills(t *testing.T) {
	h := newBackupTestHandlers(t)
	dir := useTemporaryCertDirForTest(t)
	certPEM, keyPEM, err := generateTestCert("file-path-only.example.test", time.Now().Add(-time.Hour), time.Now().Add(720*time.Hour))
	if err != nil {
		t.Fatalf("generate cert: %v", err)
	}
	certPath := filepath.Join(dir, "pathonly.crt")
	keyPath := filepath.Join(dir, "pathonly.key")
	if err := os.WriteFile(certPath, []byte(certPEM), 0644); err != nil {
		t.Fatalf("write cert: %v", err)
	}
	if err := os.WriteFile(keyPath, []byte(keyPEM), 0600); err != nil {
		t.Fatalf("write key: %v", err)
	}

	response := postFileSourceImport(t, h, fileSourceImportBackup(t, "", "", certPath, keyPath))
	if response.Code != http.StatusOK {
		t.Fatalf("import status=%d body=%s, want 200（仅路径的启用 file 行应放行供还原回填）", response.Code, response.Body.String())
	}
	var storedCert string
	if err := db.DB.QueryRow(`SELECT COALESCE(tls_cert,'') FROM lb_rules WHERE caddy_id='lb_file_import'`).Scan(&storedCert); err != nil {
		t.Fatalf("read imported rule: %v", err)
	}
	if storedCert != certPEM {
		t.Fatalf("导入后应按源文件回填内容, got %d bytes, want %d", len(storedCert), len(certPEM))
	}
}

// 反用例①：内容与路径皆缺的启用 file 行整包 400（渲染无 TLS policy 且无从回填）。
func TestImportConfigBackup_fileRuleWithoutContentOrPathRejected(t *testing.T) {
	h := newBackupTestHandlers(t)
	response := postFileSourceImport(t, h, fileSourceImportBackup(t, "", "", "", ""))
	if response.Code != http.StatusBadRequest {
		t.Fatalf("status=%d body=%s, want 400", response.Code, response.Body.String())
	}
	if !strings.Contains(response.Body.String(), "引用证书文件模式") {
		t.Fatalf("错误文案应点名引用证书文件模式缺材料: %s", response.Body.String())
	}
}

// 反用例②：只有证书内容、缺私钥（含路径也没有）的启用 file 行整包 400。
func TestImportConfigBackup_fileRuleMissingKeyRejected(t *testing.T) {
	h := newBackupTestHandlers(t)
	certPEM, _, err := generateTestCert("file-half.example.test", time.Now().Add(-time.Hour), time.Now().Add(720*time.Hour))
	if err != nil {
		t.Fatalf("generate cert: %v", err)
	}
	response := postFileSourceImport(t, h, fileSourceImportBackup(t, certPEM, "", "", ""))
	if response.Code != http.StatusBadRequest {
		t.Fatalf("status=%d body=%s, want 400", response.Code, response.Body.String())
	}
	if !strings.Contains(response.Body.String(), "引用证书文件模式") {
		t.Fatalf("错误文案应点名引用证书文件模式缺材料: %s", response.Body.String())
	}
}

// 预览对称：内容/路径皆缺的启用 file 行在预览端同样报不可导入（预览与导入
// 同一门序，不得预览通过、导入才 400）。
func TestValidateConfigImport_fileRuleWithoutContentOrPathRejected(t *testing.T) {
	h := newBackupTestHandlers(t)
	body := fileSourceImportBackup(t, "", "", "", "")
	rec := postImportShared(t, h.ValidateConfigImport, "/config/import/validate", body)
	if rec.Code != http.StatusOK {
		t.Fatalf("validate status=%d body=%s", rec.Code, rec.Body.String())
	}
	valid, errMsg, warnings := decodeValidateEnvelope(t, rec.Body.String())
	if valid {
		t.Fatalf("预览必须判不可导入（与导入同门）, error=%q warnings=%v", errMsg, warnings)
	}
	if !strings.Contains(errMsg, "引用证书文件模式") {
		t.Fatalf("预览错误应点名引用证书文件模式缺材料: %s", errMsg)
	}
}

// decodeValidateEnvelope 解析预览端点的 APIResponse envelope（importValidateResponse
// 在 data 字段内）。
func decodeValidateEnvelope(t *testing.T, body string) (valid bool, errMsg string, warnings []string) {
	t.Helper()
	var envelope struct {
		Data struct {
			Valid    bool     `json:"valid"`
			Error    string   `json:"error"`
			Warnings []string `json:"warnings"`
		} `json:"data"`
	}
	if err := json.Unmarshal([]byte(body), &envelope); err != nil {
		t.Fatalf("unmarshal validate response: %v", err)
	}
	return envelope.Data.Valid, envelope.Data.Error, envelope.Data.Warnings
}

// 错误文案与保存侧同风格：垃圾 tls_source 值在导入端被白名单门整包 400。
func TestImportConfigBackup_fileJunkTLSSourceRejected(t *testing.T) {
	h := newBackupTestHandlers(t)
	body := fileSourceBackupWithSource(t, "junk", "CERT", "KEY", "/app/certs/x.crt", "/app/certs/x.key")
	response := postFileSourceImport(t, h, body)
	if response.Code != http.StatusBadRequest {
		t.Fatalf("status=%d body=%s, want 400", response.Code, response.Body.String())
	}
	if !strings.Contains(response.Body.String(), "manual、acme_dns 或 file") {
		t.Fatalf("错误文案应与保存侧同口径: %s", response.Body.String())
	}
}

// services.IngestMissingReferencedCerts 幂等：重复导入（回填后再跑）零命中，
// 已有内容的行不被触碰——供导入链与启动回填共用同一语义。
func TestIngestMissingReferencedCerts_idempotentAfterImportBackfill(t *testing.T) {
	h := newBackupTestHandlers(t)
	dir := useTemporaryCertDirForTest(t)
	certPEM, keyPEM, err := generateTestCert("idem.example.test", time.Now().Add(-time.Hour), time.Now().Add(720*time.Hour))
	if err != nil {
		t.Fatalf("generate cert: %v", err)
	}
	certPath := filepath.Join(dir, "idem.crt")
	keyPath := filepath.Join(dir, "idem.key")
	if err := os.WriteFile(certPath, []byte(certPEM), 0644); err != nil {
		t.Fatalf("write cert: %v", err)
	}
	if err := os.WriteFile(keyPath, []byte(keyPEM), 0600); err != nil {
		t.Fatalf("write key: %v", err)
	}
	response := postFileSourceImport(t, h, fileSourceImportBackup(t, certPEM, keyPEM, certPath, keyPath))
	if response.Code != http.StatusOK {
		t.Fatalf("import status=%d body=%s", response.Code, response.Body.String())
	}
	if again := services.IngestMissingReferencedCerts(); again != 0 {
		t.Fatalf("内容已入库的行重跑回填应零命中, got %d", again)
	}
}
