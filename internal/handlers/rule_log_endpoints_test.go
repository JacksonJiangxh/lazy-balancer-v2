package handlers

// 规则日志两端点：规则不存在 404（与 metrics-history 同口径），读故障 500
// 且留痕；日志文件尚不存在仍是正常空（规则刚创建/尚无流量）。

import (
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"

	"github.com/gin-gonic/gin"

	"lazy-balancer-v2/internal/db"
	"lazy-balancer-v2/internal/services"
)

func newRuleLogTestRouter(t *testing.T) (*gin.Engine, string) {
	t.Helper()
	handler := newRuleFeatureTestHandlers(t)
	gin.SetMode(gin.TestMode)
	router := gin.New()
	router.GET("/rules/:caddy_id/logs", handler.GetRuleLogs)
	router.GET("/rules/:caddy_id/log-stream", handler.GetRuleLogStream)
	dir := t.TempDir()
	restore := services.SetRuleLogDirForTest(dir)
	t.Cleanup(restore)
	return router, dir
}

func TestRuleLogEndpoints_rejectUnknownRule(t *testing.T) {
	router, _ := newRuleLogTestRouter(t)

	for _, endpoint := range []string{"/rules/lb_missing/logs", "/rules/lb_missing/log-stream"} {
		response := httptest.NewRecorder()
		router.ServeHTTP(response, httptest.NewRequest(http.MethodGet, endpoint, nil))
		if response.Code != http.StatusNotFound {
			t.Fatalf("%s status=%d body=%s, want 404", endpoint, response.Code, response.Body.String())
		}
	}
}

func TestRuleLogEndpoints_emptyFileIsNormal(t *testing.T) {
	router, _ := newRuleLogTestRouter(t)
	if _, err := db.DB.Exec(`INSERT INTO lb_rules (caddy_id,name,protocol,listen_port,enabled) VALUES ('lb_logok','logok','http',18800,1)`); err != nil {
		t.Fatalf("seed rule: %v", err)
	}

	logsResp := httptest.NewRecorder()
	router.ServeHTTP(logsResp, httptest.NewRequest(http.MethodGet, "/rules/lb_logok/logs", nil))
	if logsResp.Code != http.StatusOK {
		t.Fatalf("logs status=%d body=%s, want 200（无日志文件=正常空）", logsResp.Code, logsResp.Body.String())
	}
	streamResp := httptest.NewRecorder()
	router.ServeHTTP(streamResp, httptest.NewRequest(http.MethodGet, "/rules/lb_logok/log-stream", nil))
	if streamResp.Code != http.StatusOK {
		t.Fatalf("log-stream status=%d body=%s, want 200", streamResp.Code, streamResp.Body.String())
	}
}

func TestRuleLogEndpoints_readFailureMapsTo500(t *testing.T) {
	router, dir := newRuleLogTestRouter(t)
	if _, err := db.DB.Exec(`INSERT INTO lb_rules (caddy_id,name,protocol,listen_port,enabled) VALUES ('lb_logbad','logbad','http',18801,1)`); err != nil {
		t.Fatalf("seed rule: %v", err)
	}
	path := filepath.Join(dir, services.RuleLogFileComponent("lb_logbad")+".log")
	if err := os.WriteFile(path, []byte("line\n"), 0o600); err != nil {
		t.Fatalf("seed log file: %v", err)
	}
	if os.Geteuid() == 0 {
		t.Skip("root 不受文件权限限制，无法构造权限故障")
	}
	if err := os.Chmod(path, 0o000); err != nil {
		t.Fatalf("chmod: %v", err)
	}
	t.Cleanup(func() { _ = os.Chmod(path, 0o600) })

	for _, endpoint := range []string{"/rules/lb_logbad/logs", "/rules/lb_logbad/log-stream"} {
		response := httptest.NewRecorder()
		router.ServeHTTP(response, httptest.NewRequest(http.MethodGet, endpoint, nil))
		if response.Code != http.StatusInternalServerError {
			t.Fatalf("%s status=%d body=%s, want 500（读故障不得伪装成空日志）", endpoint, response.Code, response.Body.String())
		}
	}
}
