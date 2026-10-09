package handlers

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/gin-gonic/gin"

	"lazy-balancer-v2/internal/db"
	"lazy-balancer-v2/internal/services"
)

// newReferencedCertRouter 构造创建规则的测试路由，并把证书目录重定向到临时目录。
func newReferencedCertRouter(t *testing.T) (*gin.Engine, string) {
	t.Helper()
	handler := newRuleFeatureTestHandlers(t)
	gin.SetMode(gin.TestMode)
	router := gin.New()
	router.POST("/rules", handler.CreateRule)
	dir := t.TempDir()
	restore := services.SetCertDirForTest(dir)
	t.Cleanup(restore)
	return router, dir
}

// postReferencedCertRule 以 tls_source=file 提交创建请求。
func postReferencedCertRule(t *testing.T, router *gin.Engine, certPath, keyPath string) *httptest.ResponseRecorder {
	t.Helper()
	payload := map[string]any{
		"name":          "file-src",
		"protocol":      "http",
		"domain":        "file-src.test",
		"listen_port":   19444,
		"enable_tls":    true,
		"tls_source":    "file",
		"tls_cert_path": certPath,
		"tls_key_path":  keyPath,
		"upstreams":     []map[string]any{{"host": "127.0.0.1", "port": 9000, "enabled": true}},
	}
	body, err := json.Marshal(payload)
	if err != nil {
		t.Fatalf("marshal payload: %v", err)
	}
	request := httptest.NewRequest(http.MethodPost, "/rules", strings.NewReader(string(body)))
	request.Header.Set("Content-Type", "application/json")
	response := httptest.NewRecorder()
	router.ServeHTTP(response, request)
	return response
}

// writeReferencedPair 在 dir 内写一对配对证书/私钥文件。
func writeReferencedPair(t *testing.T, dir, cn string) (string, string) {
	t.Helper()
	certPEM, keyPEM := selfSignedPEM(t, cn)
	certPath := filepath.Join(dir, cn+".crt")
	keyPath := filepath.Join(dir, cn+".key")
	if err := os.WriteFile(certPath, []byte(certPEM), 0644); err != nil {
		t.Fatalf("write cert: %v", err)
	}
	if err := os.WriteFile(keyPath, []byte(keyPEM), 0600); err != nil {
		t.Fatalf("write key: %v", err)
	}
	return certPath, keyPath
}

// Given: 证书目录内的合法成品证书文件
// When: 以 tls_source=file 创建规则
// Then: 创建成功，路径落库且内联 PEM 字段清空（形态互斥）
func TestCreateRule_referencedCertFilePersistsPaths(t *testing.T) {
	router, dir := newReferencedCertRouter(t)
	certPath, keyPath := writeReferencedPair(t, dir, "file-src.test")

	rec := postReferencedCertRule(t, router, certPath, keyPath)
	if rec.Code != http.StatusCreated && rec.Code != http.StatusOK {
		t.Fatalf("create status=%d body=%s", rec.Code, rec.Body.String())
	}

	var storedCertPath, storedKeyPath, storedCert, storedKey string
	if err := db.DB.QueryRow(`SELECT tls_cert_path, tls_key_path, COALESCE(tls_cert,''), COALESCE(tls_key,'')
		FROM lb_rules WHERE name='file-src'`).Scan(&storedCertPath, &storedKeyPath, &storedCert, &storedKey); err != nil {
		t.Fatalf("read persisted rule: %v", err)
	}
	if storedCertPath != certPath || storedKeyPath != keyPath {
		t.Fatalf("paths=(%q,%q), want (%q,%q)", storedCertPath, storedKeyPath, certPath, keyPath)
	}
	if storedCert != "" || storedKey != "" {
		t.Fatalf("file 模式不应落 PEM（形态互斥），got cert=%q key=%q", storedCert, storedKey)
	}
}

// Given: 证书文件位于白名单目录之外
// When: 以 tls_source=file 创建规则
// Then: 400 拒绝且规则未落库
func TestCreateRule_referencedCertOutsideDirRejected(t *testing.T) {
	router, _ := newReferencedCertRouter(t)
	outside := t.TempDir()
	certPath, keyPath := writeReferencedPair(t, outside, "outside.test")

	rec := postReferencedCertRule(t, router, certPath, keyPath)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("status=%d body=%s, want 400", rec.Code, rec.Body.String())
	}
	var count int
	if err := db.DB.QueryRow(`SELECT COUNT(*) FROM lb_rules WHERE name='file-src'`).Scan(&count); err != nil {
		t.Fatalf("count rules: %v", err)
	}
	if count != 0 {
		t.Fatalf("越界路径不应落库, count=%d", count)
	}
}

// Given: 证书目录内不存在该文件
// When: 以 tls_source=file 创建规则
// Then: 400 拒绝
func TestCreateRule_referencedCertMissingFileRejected(t *testing.T) {
	router, dir := newReferencedCertRouter(t)
	_, keyPath := writeReferencedPair(t, dir, "present.test")

	rec := postReferencedCertRule(t, router, filepath.Join(dir, "missing.crt"), keyPath)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("status=%d body=%s, want 400", rec.Code, rec.Body.String())
	}
}

// Given: 证书与私钥不配对（两套不同密钥对拼装，均在白名单目录内）
// When: 以 tls_source=file 创建规则
// Then: 400 拒绝
func TestCreateRule_referencedCertMismatchedPairRejected(t *testing.T) {
	router, dir := newReferencedCertRouter(t)
	certPath, _ := writeReferencedPair(t, dir, "pair-a.test")
	_, otherKeyPath := writeReferencedPair(t, dir, "pair-b.test")

	rec := postReferencedCertRule(t, router, certPath, otherKeyPath)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("status=%d body=%s, want 400", rec.Code, rec.Body.String())
	}
}
