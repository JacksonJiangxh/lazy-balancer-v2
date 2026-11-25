package handlers

import (
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"

	"github.com/gin-gonic/gin"

	"lazy-balancer-v2/internal/db"
	"lazy-balancer-v2/internal/services"
)

// 启用门（重构 JJC-20261125-001）：file 模式库只存路径、不存 PEM——
// 启用判据改为「路径非空 + 文件当前存在且可解析配对」，不得再报
// 「证书内容未入库，请重新保存规则以从文件摄取」。
func TestEnableRule_fileSourcePathOnlyGate(t *testing.T) {
	t.Run("valid_files_enable", func(t *testing.T) {
		router, dir := newFileSourceEnableRouter(t)
		seedFilePathOnlyRule(t, router, dir, "lb_enable_ok", "enable-ok.test", 19451)

		rec := postEnableRule(t, router, "lb_enable_ok")
		if rec.Code != http.StatusOK {
			t.Fatalf("enable status=%d body=%s, want 200（路径就绪的 file 规则应可启用）", rec.Code, rec.Body.String())
		}
		if strings.Contains(rec.Body.String(), "未入库") {
			t.Fatalf("启用响应仍含旧「内容未入库」文案: %s", rec.Body.String())
		}
	})

	t.Run("missing_files_rejected_clearly", func(t *testing.T) {
		router, dir := newFileSourceEnableRouter(t)
		certPath, keyPath := seedFilePathOnlyRule(t, router, dir, "lb_enable_gone", "enable-gone.test", 19452)
		for _, path := range []string{certPath, keyPath} {
			if err := os.Remove(path); err != nil {
				t.Fatalf("remove %s: %v", path, err)
			}
		}

		rec := postEnableRule(t, router, "lb_enable_gone")
		if rec.Code != http.StatusBadRequest {
			t.Fatalf("enable status=%d body=%s, want 400（文件缺失 fail-closed）", rec.Code, rec.Body.String())
		}
		body := rec.Body.String()
		if strings.Contains(body, "未入库") {
			t.Fatalf("文件缺失不得再报旧「内容未入库」文案: %s", body)
		}
		if !strings.Contains(body, "引用证书文件") {
			t.Fatalf("错误文案应点名引用证书文件不可用: %s", body)
		}
	})
}

func newFileSourceEnableRouter(t *testing.T) (*gin.Engine, string) {
	t.Helper()
	handler := newRuleFeatureTestHandlers(t)
	gin.SetMode(gin.TestMode)
	router := gin.New()
	router.PUT("/rules/:caddy_id", handler.UpdateRule)
	router.POST("/rules/:caddy_id/enable", handler.EnableRule)
	dir := t.TempDir()
	restore := services.SetCertDirForTest(dir)
	t.Cleanup(restore)
	return router, dir
}

// seedFilePathOnlyRule seed 一条启用中的 manual 规则，经 PUT 切为 file 源（只落路径），
// 返回源文件路径供后续删除构造「文件缺失」场景。
func seedFilePathOnlyRule(t *testing.T, router *gin.Engine, dir, caddyID, cn string, port int) (string, string) {
	t.Helper()
	certPath, keyPath := writeReferencedPair(t, dir, cn)
	seedAuditRule(t, caddyID, caddyID+"-name", cn, port, false, "manual", false)
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
	var storedCert string
	if err := db.DB.QueryRow(`SELECT COALESCE(tls_cert,'') FROM lb_rules WHERE caddy_id=?`, caddyID).Scan(&storedCert); err != nil {
		t.Fatalf("read seeded content: %v", err)
	}
	if storedCert != "" {
		t.Fatalf("前置：file 模式保存后库中不应有 PEM 内容, got %d bytes", len(storedCert))
	}
	return certPath, keyPath
}

func postEnableRule(t *testing.T, router *gin.Engine, caddyID string) *httptest.ResponseRecorder {
	t.Helper()
	rec := httptest.NewRecorder()
	request := httptest.NewRequest(http.MethodPost, "/rules/"+caddyID+"/enable", nil)
	router.ServeHTTP(rec, request)
	return rec
}
