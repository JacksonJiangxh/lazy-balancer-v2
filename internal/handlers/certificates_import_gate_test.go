package handlers

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/gin-gonic/gin"
)

// 证书配置与 CA 提供商两个写端点在导入窗口内必须
// 409 fast-fail——此前既不取 caddyOpMu 也不走导入门，排空结束后、导入事务
// 开启前提交的写入会被全量替换静默覆盖。
func TestCertificateWrites409DuringImport(t *testing.T) {
	h := newBackupTestHandlers(t)
	gin.SetMode(gin.TestMode)
	router := gin.New()
	router.POST("/certificates/configs", h.CreateCertificateConfig)
	router.PUT("/ca-providers/:id", h.UpdateCAProvider)

	configImportBeginMu.Lock()
	defer configImportBeginMu.Unlock()

	calls := []struct{ method, path, body string }{
		{"POST", "/certificates/configs", `{"name":"dns","dns_provider":"dnspod","dns_credentials":{"id":"1","token":"t"},"enabled":true}`},
		{"PUT", "/ca-providers/1", `{"enabled":false}`},
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

// 非法 access_url 是客户端可修正的输入错误，必须
// 400 并回可行动文案——此前落默认 500「更新地址节点失败」。
func TestUpdateClusterNodeAccessURL_invalidURLIs400(t *testing.T) {
	h := newBackupTestHandlers(t)
	gin.SetMode(gin.TestMode)
	router := gin.New()
	router.PUT("/cluster/nodes/:id/access-url", h.UpdateClusterNodeAccessURL)

	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPut, "/cluster/nodes/1/access-url",
		strings.NewReader(`{"access_url":"http://user:pass@10.0.0.2:8000/?q=1"}`))
	req.Header.Set("Content-Type", "application/json")
	router.ServeHTTP(rec, req)

	if rec.Code != http.StatusBadRequest {
		t.Fatalf("status=%d body=%s, want 400（非法访问地址是输入错误）", rec.Code, rec.Body.String())
	}
	if !strings.Contains(rec.Body.String(), "访问地址") {
		t.Fatalf("body=%s, want 访问地址相关文案（不得落 500 通用失败）", rec.Body.String())
	}
}
