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
		// 批 1+2 后健康检查族 0 值一律 400，按表单初值显式携带。
		"health_check_interval": 10, "health_check_timeout": 2,
		"health_check_unhealthy_threshold": 3, "health_check_healthy_threshold": 2,
		"upstreams": []map[string]any{{"host": "127.0.0.1", "port": 9000, "enabled": true}},
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
// Then: 创建成功，路径落库；PEM 内容不落库（路径引用架构，重构 JJC-20261125-001：
// 保存门只校验文件，运行时由渲染层 load_files 引用本地文件）
func TestCreateRule_referencedCertStoresPathOnly(t *testing.T) {
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
		t.Fatalf("file 模式库中不得存 PEM 内容（路径引用架构）, cert=%d bytes key=%d bytes",
			len(storedCert), len(storedKey))
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

// newFileSourceUpdateRouter 构造带 PUT /rules/:caddy_id 的测试路由，并把证书目录重定向到临时目录。
func newFileSourceUpdateRouter(t *testing.T) (*gin.Engine, string) {
	t.Helper()
	handler := newRuleFeatureTestHandlers(t)
	gin.SetMode(gin.TestMode)
	router := gin.New()
	router.PUT("/rules/:caddy_id", handler.UpdateRule)
	dir := t.TempDir()
	restore := services.SetCertDirForTest(dir)
	t.Cleanup(restore)
	return router, dir
}

// putUpdateRulePayload 以 JSON 载荷提交 PUT /rules/:caddy_id。
func putUpdateRulePayload(t *testing.T, router *gin.Engine, caddyID string, payload map[string]any) *httptest.ResponseRecorder {
	t.Helper()
	body, err := json.Marshal(payload)
	if err != nil {
		t.Fatalf("marshal payload: %v", err)
	}
	request := httptest.NewRequest(http.MethodPut, "/rules/"+caddyID, strings.NewReader(string(body)))
	request.Header.Set("Content-Type", "application/json")
	response := httptest.NewRecorder()
	router.ServeHTTP(response, request)
	return response
}

// seedFileSourceRule seed 一条 manual 规则并经 PUT 摄取为 file 源（路径+内容落库），
// 返回摄取源路径供后续断言比对。
func seedFileSourceRule(t *testing.T, router *gin.Engine, dir, caddyID, cn string) (string, string) {
	t.Helper()
	certPath, keyPath := writeReferencedPair(t, dir, cn)
	seedAuditRule(t, caddyID, caddyID+"-name", cn, 19450, true, "manual", false)
	seedAuditUpstream(t, caddyID)
	rec := putUpdateRulePayload(t, router, caddyID, map[string]any{
		"enable_tls":    true,
		"tls_source":    "file",
		"tls_cert_path": certPath,
		"tls_key_path":  keyPath,
	})
	if rec.Code != http.StatusOK {
		t.Fatalf("seed file-source rule %s: status=%d body=%s", caddyID, rec.Code, rec.Body.String())
	}
	return certPath, keyPath
}

// queryStoredTLSPaths 读取落库的引用型证书路径列。
func queryStoredTLSPaths(t *testing.T, caddyID string) (string, string) {
	t.Helper()
	var certPath, keyPath string
	if err := db.DB.QueryRow(`SELECT COALESCE(tls_cert_path,''), COALESCE(tls_key_path,'') FROM lb_rules WHERE caddy_id=?`, caddyID).Scan(&certPath, &keyPath); err != nil {
		t.Fatalf("read persisted rule %s: %v", caddyID, err)
	}
	return certPath, keyPath
}

// TestUpdateRule_FileSourceEmptyPathRetention V4 三态钉测（JJC-20261120-001 方案 C）：
// file→file 同模式空路径 PUT 不得清空 DB 路径列（models.go「引用型证书路径列
// 空串=保留存量路径」契约）。三态：
// ① enable_tls=true + 空路径 + 文件在 → 200 且路径/内容保持（既有沿用语义正向钉）；
// ② enable_tls=false + file + 空路径 + 文件在 → 200 且 DB 路径列保留
//   （修复前红=路径列被无条件写清空）；
// ③ enable_tls=false + 空路径 + 源文件已删 → 200 且路径保留、无 400
//   （插入点判别器：合并块若落在摄取分支门之前，沿用填充的路径会把析取支顶开
//   → 文件校验 400 红；落归一区后门关、跳过校验 → 200 绿）。
func TestUpdateRule_FileSourceEmptyPathRetention(t *testing.T) {
	t.Run("case1_tls_on_empty_path_keeps_paths_and_no_content", func(t *testing.T) {
		router, dir := newFileSourceUpdateRouter(t)
		wantCertPath, wantKeyPath := seedFileSourceRule(t, router, dir, "lb_retention_c1", "retention-c1.test")

		rec := putUpdateRulePayload(t, router, "lb_retention_c1", map[string]any{
			"enable_tls":    true,
			"tls_source":    "file",
			"tls_cert_path": "",
			"tls_key_path":  "",
		})
		if rec.Code != http.StatusOK {
			t.Fatalf("update status=%d body=%s, want 200", rec.Code, rec.Body.String())
		}
		gotCertPath, gotKeyPath := queryStoredTLSPaths(t, "lb_retention_c1")
		if gotCertPath != wantCertPath || gotKeyPath != wantKeyPath {
			t.Fatalf("paths=(%q,%q), want (%q,%q)", gotCertPath, gotKeyPath, wantCertPath, wantKeyPath)
		}
		var storedCert, storedKey string
		if err := db.DB.QueryRow(`SELECT COALESCE(tls_cert,''), COALESCE(tls_key,'') FROM lb_rules WHERE caddy_id='lb_retention_c1'`).Scan(&storedCert, &storedKey); err != nil {
			t.Fatalf("read persisted content: %v", err)
		}
		if storedCert != "" || storedKey != "" {
			t.Fatalf("file 模式沿用路径保存不得回填 PEM 内容, cert=%d bytes key=%d bytes", len(storedCert), len(storedKey))
		}
	})

	t.Run("case2_tls_off_empty_path_keeps_paths", func(t *testing.T) {
		router, dir := newFileSourceUpdateRouter(t)
		wantCertPath, wantKeyPath := seedFileSourceRule(t, router, dir, "lb_retention_c2", "retention-c2.test")

		rec := putUpdateRulePayload(t, router, "lb_retention_c2", map[string]any{
			"enable_tls":    false,
			"tls_source":    "file",
			"tls_cert_path": "",
			"tls_key_path":  "",
		})
		if rec.Code != http.StatusOK {
			t.Fatalf("update status=%d body=%s, want 200", rec.Code, rec.Body.String())
		}
		gotCertPath, gotKeyPath := queryStoredTLSPaths(t, "lb_retention_c2")
		if gotCertPath != wantCertPath || gotKeyPath != wantKeyPath {
			t.Fatalf("关 TLS + 空路径 PUT 后 DB 路径列被清空（应保留存量）: got=(%q,%q), want=(%q,%q)", gotCertPath, gotKeyPath, wantCertPath, wantKeyPath)
		}
	})

	t.Run("case3_tls_off_deleted_source_file_no_400", func(t *testing.T) {
		router, dir := newFileSourceUpdateRouter(t)
		wantCertPath, wantKeyPath := seedFileSourceRule(t, router, dir, "lb_retention_c3", "retention-c3.test")
		// 源文件删除：file 源证据消失，关 TLS 保存必须不触发文件校验（无 400）
		for _, p := range []string{wantCertPath, wantKeyPath} {
			if err := os.Remove(p); err != nil {
				t.Fatalf("remove source file: %v", err)
			}
		}

		rec := putUpdateRulePayload(t, router, "lb_retention_c3", map[string]any{
			"enable_tls":    false,
			"tls_source":    "file",
			"tls_cert_path": "",
			"tls_key_path":  "",
		})
		if rec.Code != http.StatusOK {
			t.Fatalf("update status=%d body=%s, want 200（文件已删时关 TLS 保存不应 400）", rec.Code, rec.Body.String())
		}
		gotCertPath, gotKeyPath := queryStoredTLSPaths(t, "lb_retention_c3")
		if gotCertPath != wantCertPath || gotKeyPath != wantKeyPath {
			t.Fatalf("文件已删 + 空路径 PUT 后 DB 路径列被清空（应保留存量）: got=(%q,%q), want=(%q,%q)", gotCertPath, gotKeyPath, wantCertPath, wantKeyPath)
		}
	})
}

// Given: 存量规则（manual 来源）与证书目录内一对合法成品证书
// When: 通过 PUT 切换到 tls_source=file 并提交容器内路径
// Then: 更新成功、路径落库、库中无 PEM 内容——守卫以 CreateRule 同口径放过 file 来源，
// 且保存链不再摄取内容（路径引用架构，重构 JJC-20261125-001）
// （回归：UpdateRule 的来源白名单曾漏列 file，导致前端「引用证书文件」保存恒 400）
func TestUpdateRule_referencedCertStoresPathOnly(t *testing.T) {
	handler := newRuleFeatureTestHandlers(t)
	dir := t.TempDir()
	restore := services.SetCertDirForTest(dir)
	t.Cleanup(restore)
	certPath, keyPath := writeReferencedPair(t, dir, "file-update.test")

	seedAuditRule(t, "lb_file_update", "file-update", "file-update.test", 19445, true, "manual", false)
	seedAuditUpstream(t, "lb_file_update")

	payload := map[string]any{
		"enable_tls":    true,
		"tls_source":    "file",
		"tls_cert_path": certPath,
		"tls_key_path":  keyPath,
	}
	body, err := json.Marshal(payload)
	if err != nil {
		t.Fatalf("marshal payload: %v", err)
	}
	router := gin.New()
	router.PUT("/rules/:caddy_id", handler.UpdateRule)
	request := httptest.NewRequest(http.MethodPut, "/rules/lb_file_update", strings.NewReader(string(body)))
	request.Header.Set("Content-Type", "application/json")
	response := httptest.NewRecorder()
	router.ServeHTTP(response, request)

	if response.Code != http.StatusOK {
		t.Fatalf("update status=%d body=%s, want 200 (file 来源不应被来源白名单拒绝)", response.Code, response.Body.String())
	}
	var storedSource, storedCertPath, storedKeyPath, storedCert, storedKey string
	if err := db.DB.QueryRow(`SELECT tls_source, COALESCE(tls_cert_path,''), COALESCE(tls_key_path,''), COALESCE(tls_cert,''), COALESCE(tls_key,'')
		FROM lb_rules WHERE caddy_id='lb_file_update'`).Scan(&storedSource, &storedCertPath, &storedKeyPath, &storedCert, &storedKey); err != nil {
		t.Fatalf("read persisted rule: %v", err)
	}
	if storedSource != "file" {
		t.Fatalf("tls_source=%q, want file", storedSource)
	}
	if storedCertPath != certPath || storedKeyPath != keyPath {
		t.Fatalf("paths=(%q,%q), want (%q,%q)", storedCertPath, storedKeyPath, certPath, keyPath)
	}
	if storedCert != "" || storedKey != "" {
		t.Fatalf("file 模式保存后库中不得存 PEM 内容, cert=%d bytes key=%d bytes", len(storedCert), len(storedKey))
	}
}
