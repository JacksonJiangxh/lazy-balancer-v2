package handlers

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/gin-gonic/gin"
)

// 证书配置与 CA 提供商写端点全族在导入窗口内必须 409 fast-fail：排空结束后、
// 导入事务开启前提交的写入会被全量替换静默覆盖；事务开启后提交则排队至
// 导入提交再按陈旧 id 改写导入结果。证书配置的 Update/Delete 虽取 caddyOpMu，
// 也不因此获得 fast-fail——门必须在取锁之前。
func TestCertificateWrites409DuringImport(t *testing.T) {
	h := newBackupTestHandlers(t)
	gin.SetMode(gin.TestMode)
	router := gin.New()
	router.POST("/certificates/configs", h.CreateCertificateConfig)
	router.PUT("/certificate-configs/:id", h.UpdateCertificateConfig)
	router.DELETE("/certificate-configs/:id", h.DeleteCertificateConfig)
	router.PUT("/ca-providers/:id", h.UpdateCAProvider)
	router.POST("/certificates/issue", h.IssueCertificate)

	beginImportWindowForTest(t)

	calls := []struct{ method, path, body string }{
		{"POST", "/certificates/configs", `{"name":"dns","dns_provider":"dnspod","dns_credentials":{"id":"1","token":"t"},"enabled":true}`},
		{"PUT", "/certificate-configs/1", `{"name":"dns-updated","enabled":true}`},
		{"DELETE", "/certificate-configs/1", ""},
		{"PUT", "/ca-providers/1", `{"enabled":false}`},
		// 签发是证书任务写族成员：导入窗口内必须与重试/删除同样 fast-fail，
		// 不得挂到排空+导入事务结束后再按导入前快照逐目标 upsert。
		{"POST", "/certificates/issue", `{"caddy_id":"lb_import_window"}`},
	}
	for _, call := range calls {
		rec := httptest.NewRecorder()
		req := httptest.NewRequest(call.method, call.path, strings.NewReader(call.body))
		req.Header.Set("Content-Type", "application/json")
		router.ServeHTTP(rec, req)
		if rec.Code != http.StatusConflict {
			t.Fatalf("%s %s status=%d body=%s, want 409（导入窗口内写端点必须 fast-fail）", call.method, call.path, rec.Code, rec.Body.String())
		}
	}
}

// 对照：导入窗口外两个端点照常处理（不可把 409 门做成恒拒）。
func TestCertificateWritesAllowedOutsideImportWindow(t *testing.T) {
	h := newBackupTestHandlers(t)
	gin.SetMode(gin.TestMode)
	router := gin.New()
	router.POST("/certificates/configs", h.CreateCertificateConfig)

	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/certificates/configs",
		strings.NewReader(`{"name":"dns-outside","dns_provider":"dnspod","dns_credentials":{"id":"1","token":"t"},"enabled":true}`))
	req.Header.Set("Content-Type", "application/json")
	router.ServeHTTP(rec, req)
	if rec.Code == http.StatusConflict {
		t.Fatalf("status=409, want 非冲突（导入窗口外必须放行）: %s", rec.Body.String())
	}
}
