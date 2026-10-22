package handlers

// 导入窗口写门覆盖面：除用户/密钥/证书/CA/集群/节点族外，写入 global_config
// 与版本/源表的设置端点同样在导入全量替换范围内——自动备份设置、OIDC 设置
// （保存/删除）、规则库自动更新、四族库排程、自动封禁配置在窗口内提交都会被
// 导入静默覆盖或撞写锁 500，必须与同族端点一样 409 fast-fail。

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/gin-gonic/gin"
)

func TestSettingsWrites409DuringImport(t *testing.T) {
	h := newBackupTestHandlers(t)
	gin.SetMode(gin.TestMode)
	router := gin.New()
	router.PUT("/settings/auto-backup", h.UpdateAutoBackupSettings)
	router.PUT("/settings/oidc", h.OIDCSettingsUpdate)
	router.DELETE("/settings/oidc", h.OIDCSettingsDelete)
	router.PUT("/security/crs/auto-update", h.UpdateCRSAutoUpdate)
	router.PUT("/security/crs/schedule", h.UpdateCRSSchedule)
	router.PUT("/security/ip2region/schedule", h.UpdateIP2RegionSchedule)
	router.PUT("/security/threat/schedule", h.UpdateThreatSchedule)
	router.PUT("/security/crawler/schedule", h.UpdateCrawlerSchedule)
	router.PUT("/security/autoban", h.UpdateAutobanConfig)

	// 模拟导入会话持锁（configImportBusy 的探测对象）。
	configImportBeginMu.Lock()
	defer configImportBeginMu.Unlock()

	calls := []struct{ method, path, body string }{
		{"PUT", "/settings/auto-backup", `{"enabled":true,"frequency":"daily","time":"03:00","day":1,"keep":7,"sections":["rules"]}`},
		{"PUT", "/settings/oidc", `{"enabled":true,"issuer":"https://idp.example","client_id":"cid"}`},
		{"DELETE", "/settings/oidc", ""},
		{"PUT", "/security/crs/auto-update", `{"auto_update":true}`},
		{"PUT", "/security/crs/schedule", `{"days":[1,2],"time":"04:00"}`},
		{"PUT", "/security/ip2region/schedule", `{"days":[1,2],"time":"04:00"}`},
		{"PUT", "/security/threat/schedule", `{"days":[1,2],"time":"04:00"}`},
		{"PUT", "/security/crawler/schedule", `{"days":[1,2],"time":"04:00"}`},
		{"PUT", "/security/autoban", `{"enabled":true}`},
	}
	for _, call := range calls {
		recorder := httptest.NewRecorder()
		request := httptest.NewRequest(call.method, call.path, strings.NewReader(call.body))
		request.Header.Set("Content-Type", "application/json")
		router.ServeHTTP(recorder, request)
		if recorder.Code != http.StatusConflict {
			t.Fatalf("%s %s status=%d body=%s, want 409（导入窗口内设置写端点必须 fast-fail）",
				call.method, call.path, recorder.Code, recorder.Body.String())
		}
		if !strings.Contains(recorder.Body.String(), "配置导入进行中") {
			t.Fatalf("%s %s body=%s, want 配置导入进行中 文案", call.method, call.path, recorder.Body.String())
		}
	}
}

// 对照：窗口外同一端点不被 409 门恒拒（门只按导入会话持锁判定）。
func TestSettingsWritesAllowedOutsideImportWindow(t *testing.T) {
	h := newBackupTestHandlers(t)
	gin.SetMode(gin.TestMode)
	router := gin.New()
	router.PUT("/security/autoban", h.UpdateAutobanConfig)

	recorder := httptest.NewRecorder()
	request := httptest.NewRequest(http.MethodPut, "/security/autoban", strings.NewReader(`{not-json`))
	request.Header.Set("Content-Type", "application/json")
	router.ServeHTTP(recorder, request)
	if recorder.Code == http.StatusConflict {
		t.Fatalf("窗口外请求被 409 门恒拒: body=%s", recorder.Body.String())
	}
}
