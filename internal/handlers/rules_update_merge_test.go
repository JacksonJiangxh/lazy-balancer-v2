package handlers

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"lazy-balancer-v2/internal/db"
	"lazy-balancer-v2/internal/services"

	"github.com/gin-gonic/gin"
)

// 历史修复1：部分载荷省略 listen_port 时不得把存量端口改写成 443。
// API/MCP 的 update_rule 明确允许只提交部分字段；此前 UpdateRule 在读到存量
// 之前就把省略的端口填成 443，导致 8443/8080 规则被静默迁移。
func TestUpdateRule_partialPayloadKeepsExistingListenPort(t *testing.T) {
	harness := newUpdateAuditRuleHandlers(t, "lb_port_keep", 0, false)
	restoreCertDir := services.SetCertDirForTest(t.TempDir())
	t.Cleanup(restoreCertDir)
	certPEM, keyPEM, err := generateTestCert("port-keep.example.test", time.Now().Add(-time.Hour), time.Now().Add(24*time.Hour))
	if err != nil {
		t.Fatalf("generate cert: %v", err)
	}
	if _, err := db.DB.Exec(`INSERT INTO lb_rules (caddy_id,name,description,protocol,domain,listen_port,strategy,health_check_path,enabled,enable_compress,tls_source,enable_tls,tls_cert,tls_key)
		VALUES ('lb_port_keep','port-keep','','http','port-keep.example.test',8443,'weighted_round_robin','',1,1,'manual',1,?,?)`, certPEM, keyPEM); err != nil {
		t.Fatalf("seed rule: %v", err)
	}
	seedAuditUpstream(t, "lb_port_keep")
	router := gin.New()
	router.PUT("/rules/:caddy_id", harness.handler.UpdateRule)

	// When：省略 listen_port 的部分更新（只开 TLS/改名，不带证书，沿用存量）
	response := httptest.NewRecorder()
	request := httptest.NewRequest(http.MethodPut, "/rules/lb_port_keep",
		strings.NewReader(`{"name":"port-keep-renamed","protocol":"http","enable_tls":true}`))
	request.Header.Set("Content-Type", "application/json")
	router.ServeHTTP(response, request)

	// Then
	if response.Code != http.StatusOK {
		t.Fatalf("update status=%d body=%s, want 200", response.Code, response.Body.String())
	}
	var port int
	if err := db.DB.QueryRow("SELECT listen_port FROM lb_rules WHERE caddy_id='lb_port_keep'").Scan(&port); err != nil {
		t.Fatalf("read listen_port: %v", err)
	}
	if port != 8443 {
		t.Fatalf("listen_port=%d, want 8443（省略 listen_port 时必须保留存量端口）", port)
	}
}

// 历史修复1 对照：显式提交的端口仍然生效（默认值只兜底缺省，不吞显式值）。
func TestUpdateRule_explicitListenPortStillApplied(t *testing.T) {
	harness := newUpdateAuditRuleHandlers(t, "lb_port_explicit", 0, false)
	restoreCertDir := services.SetCertDirForTest(t.TempDir())
	t.Cleanup(restoreCertDir)
	seedAuditRule(t, "lb_port_explicit", "port-explicit", "port-explicit.example.test", 8443, true, "manual", false)
	seedAuditUpstream(t, "lb_port_explicit")
	router := gin.New()
	router.PUT("/rules/:caddy_id", harness.handler.UpdateRule)

	response := httptest.NewRecorder()
	request := httptest.NewRequest(http.MethodPut, "/rules/lb_port_explicit",
		strings.NewReader(`{"name":"port-explicit","protocol":"http","listen_port":18080,"enable_tls":false}`))
	request.Header.Set("Content-Type", "application/json")
	router.ServeHTTP(response, request)

	if response.Code != http.StatusOK {
		t.Fatalf("update status=%d body=%s, want 200", response.Code, response.Body.String())
	}
	var port int
	if err := db.DB.QueryRow("SELECT listen_port FROM lb_rules WHERE caddy_id='lb_port_explicit'").Scan(&port); err != nil {
		t.Fatalf("read listen_port: %v", err)
	}
	if port != 18080 {
		t.Fatalf("listen_port=%d, want 18080（显式端口必须生效）", port)
	}
}

// 历史修复2：UpdateRule 主动放锁窗口后必须复核规则行仍存在——
// 已删除规则不得被更新失败补偿按快照复活。
func TestAbortIfRuleDeleted_rejectsDeletedRule(t *testing.T) {
	newUpdateAuditRuleHandlers(t, "lb_gone", 0, false)
	router := gin.New()
	router.PUT("/rules/:caddy_id", func(c *gin.Context) {
		if abortIfRuleDeleted(c, "lb_gone") {
			return
		}
		c.JSON(http.StatusOK, gin.H{"code": 0})
	})

	// When：规则不存在（模拟放锁窗口内被 DeleteRule 删除）
	response := httptest.NewRecorder()
	router.ServeHTTP(response, httptest.NewRequest(http.MethodPut, "/rules/lb_gone", nil))

	// Then
	if response.Code != http.StatusConflict {
		t.Fatalf("status=%d body=%s, want 409（已删除规则不得继续补偿）", response.Code, response.Body.String())
	}
	var body struct {
		Message string `json:"message"`
	}
	if err := json.Unmarshal(response.Body.Bytes(), &body); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if !strings.Contains(body.Message, "已被删除") {
		t.Fatalf("message=%q, want 含「已被删除」", body.Message)
	}
}

// 历史修复2 对照：规则仍存在时守卫放行。
func TestAbortIfRuleDeleted_allowsExistingRule(t *testing.T) {
	newUpdateAuditRuleHandlers(t, "lb_alive", 0, false)
	seedAuditRule(t, "lb_alive", "alive", "alive.example.test", 8080, true, "manual", false)
	router := gin.New()
	router.PUT("/rules/:caddy_id", func(c *gin.Context) {
		if abortIfRuleDeleted(c, "lb_alive") {
			return
		}
		c.JSON(http.StatusOK, gin.H{"code": 0})
	})

	response := httptest.NewRecorder()
	router.ServeHTTP(response, httptest.NewRequest(http.MethodPut, "/rules/lb_alive", nil))
	if response.Code != http.StatusOK {
		t.Fatalf("status=%d body=%s, want 200", response.Code, response.Body.String())
	}
}
