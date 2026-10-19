package handlers

// 行缺失（初始化异常形态）时批量 cert-info 须与单规则端点同口径降级：
// GetCertExpiryThreshold error 留痕后取治理默认，照常 200 判到期状态。
// 修复前形态：原子查询 `(SELECT COALESCE(cert_expiry_days,30) ...)` 对缺行
// 无效（标量子查询零行恒 NULL，Scan 进 int 失败）→ 整批 500，与单规则端点
// （同一基准函数降级成功）口径分叉。

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/gin-gonic/gin"

	"lazy-balancer-v2/internal/db"
)

func TestGetRulesCertInfo_degrades_when_config_row_missing(t *testing.T) {
	// Given：manual 证书 20 天后过期；配置行在时基线 200 且判 expiring（30 天阈值内）
	h := newBackupTestHandlers(t)
	certPEM, _, err := generateTestCert("degrade-batch.test", time.Now().Add(-time.Hour), time.Now().Add(20*24*time.Hour))
	if err != nil {
		t.Fatalf("generate cert: %v", err)
	}
	if _, err := db.DB.Exec(`INSERT INTO lb_rules (caddy_id,name,domain,protocol,listen_port,enabled,enable_tls,tls_source,tls_cert)
		VALUES ('lb_r77degrade','degrade','degrade-batch.test','http',8080,1,1,'manual',?)`, certPEM); err != nil {
		t.Fatalf("seed rule: %v", err)
	}
	router := gin.New()
	router.POST("/rules/cert-info", h.GetRulesCertInfo)
	post := func() *httptest.ResponseRecorder {
		request := httptest.NewRequest(http.MethodPost, "/rules/cert-info", strings.NewReader(`{"caddy_ids":["lb_r77degrade"]}`))
		request.Header.Set("Content-Type", "application/json")
		response := httptest.NewRecorder()
		router.ServeHTTP(response, request)
		return response
	}
	if baseline := post(); baseline.Code != http.StatusOK {
		t.Fatalf("baseline status=%d body=%s, want 200", baseline.Code, baseline.Body.String())
	}

	// When：global_config 行被删（缺行=初始化异常形态）
	if _, err := db.DB.Exec(`DELETE FROM global_config WHERE id=1`); err != nil {
		t.Fatalf("delete global config: %v", err)
	}
	response := post()

	// Then：200 且按降级默认 30 天阈值判 expiring（与单规则端点同口径，不 500）
	if response.Code != http.StatusOK {
		t.Fatalf("status=%d body=%s, want 200（缺行降级默认阈值，与单规则端点同口径）", response.Code, response.Body.String())
	}
	var resp struct {
		Data map[string]*struct {
			Status string `json:"status"`
		} `json:"data"`
	}
	if err := json.Unmarshal(response.Body.Bytes(), &resp); err != nil {
		t.Fatalf("decode: %v body=%s", err, response.Body.String())
	}
	info := resp.Data["lb_r77degrade"]
	if info == nil {
		t.Fatalf("rule info missing: %s", response.Body.String())
	}
	if info.Status != "expiring" {
		t.Fatalf("status=%q, want expiring（降级默认 30 天阈值下 20 天后到期）", info.Status)
	}
}
