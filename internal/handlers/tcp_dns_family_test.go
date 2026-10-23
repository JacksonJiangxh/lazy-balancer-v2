package handlers

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/gin-gonic/gin"

	"lazy-balancer-v2/internal/db"
)

// dns_family 仅 HTTP 消费（dynamic_dns 上游族过滤），TCP 行归一为建库默认
// ipv4——同一 TCP 终态不得出现 ''/ipv4/ipv6 多形态（导出与快照 canonical
// 需要稳定值）。保存族（编辑/复制/创建）、单规则启用 SQL、启动迁移/导入
// SQL 三面同终态。

func TestTCPDeadFieldReset_normalizesDnsFamilyToIPv4(t *testing.T) {
	family := "ipv6"
	tcpDeadFieldReset("tcp", tcpDeadFields{DnsFamily: &family})
	if family != "ipv4" {
		t.Fatalf("tcp dns_family=%q, want ipv4", family)
	}

	// http 规则不得被归一（dynamic_dns 真实消费该列）。
	httpFamily := "ipv6"
	tcpDeadFieldReset("http", tcpDeadFields{DnsFamily: &httpFamily})
	if httpFamily != "ipv6" {
		t.Fatalf("http dns_family=%q, want 保持 ipv6", httpFamily)
	}
}

func TestRuleWrites_normalizeTCPDnsFamilyToIPv4(t *testing.T) {
	handler := newRuleFeatureTestHandlers(t)
	gin.SetMode(gin.TestMode)
	router := gin.New()
	router.PUT("/rules/:caddy_id", handler.UpdateRule)
	router.POST("/rules/:caddy_id/duplicate", handler.DuplicateRule)

	seed := func(id string, port int) {
		t.Helper()
		if _, err := db.DB.Exec(`INSERT INTO lb_rules (caddy_id,name,description,protocol,domain,listen_port,strategy,enabled,dns_family)
			VALUES (?,?,'','tcp','',?,'weighted_round_robin',1,'ipv6')`, id, id, port); err != nil {
			t.Fatalf("seed %s: %v", id, err)
		}
		if _, err := db.DB.Exec(`INSERT INTO upstreams (rule_id,host,port,weight,enabled,protocol) VALUES (?,'127.0.0.1',9000,1,1,'tcp')`, id); err != nil {
			t.Fatalf("seed upstream %s: %v", id, err)
		}
	}
	readFamily := func(id string) string {
		t.Helper()
		var family string
		if err := db.DB.QueryRow(`SELECT COALESCE(dns_family,'') FROM lb_rules WHERE caddy_id=?`, id).Scan(&family); err != nil {
			t.Fatalf("read %s: %v", id, err)
		}
		return family
	}

	t.Run("update", func(t *testing.T) {
		seed("lb_dnsfam_update", 18631)
		response := httptest.NewRecorder()
		router.ServeHTTP(response, httptest.NewRequest(http.MethodPut, "/rules/lb_dnsfam_update",
			strings.NewReader(`{"name":"dnsfam-updated","protocol":"tcp"}`)))
		if response.Code != http.StatusOK {
			t.Fatalf("update status=%d body=%s", response.Code, response.Body.String())
		}
		if got := readFamily("lb_dnsfam_update"); got != "ipv4" {
			t.Fatalf("update dns_family=%q, want ipv4", got)
		}
	})

	t.Run("duplicate", func(t *testing.T) {
		seed("lb_dnsfam_source", 18632)
		response := httptest.NewRecorder()
		router.ServeHTTP(response, httptest.NewRequest(http.MethodPost, "/rules/lb_dnsfam_source/duplicate", nil))
		if response.Code != http.StatusCreated {
			t.Fatalf("duplicate status=%d body=%s", response.Code, response.Body.String())
		}
		var copyID string
		if err := db.DB.QueryRow(`SELECT caddy_id FROM lb_rules WHERE name=?`, "lb_dnsfam_source（副本）").Scan(&copyID); err != nil {
			t.Fatalf("read copy: %v", err)
		}
		if got := readFamily(copyID); got != "ipv4" {
			t.Fatalf("copy dns_family=%q, want ipv4（源行 ipv6 不得放大到副本）", got)
		}
	})
}
