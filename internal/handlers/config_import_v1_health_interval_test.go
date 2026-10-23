package handlers

// v1 健康检查间隔归一：导入 INSERT 的 health_check_timeout 恒取
// db.DefaultHealthCheckTimeout，保存/启用侧要求超时小于间隔——间隔过短的
// v1 规则（fail_timeout 直接映射为间隔）落库后会变成下次保存即被拒的陷阱行，
// 因此按落库超时归一，且不再区分主动/被动（被动熔断窗口同样由间隔派生）。

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/gin-gonic/gin"

	"lazy-balancer-v2/internal/db"
)

func importV1SingleRule(t *testing.T, name string, httpCheck bool, failTimeout int) *httptest.ResponseRecorder {
	t.Helper()
	h := newBackupTestHandlers(t)
	gin.SetMode(gin.TestMode)
	backup := fmt.Sprintf(`{
		"proxy_config":{"config":[
			{"pk":1,"fields":{"proxy_name":%q,"protocol":true,"listen":8466,"server_name":"%s.example.test","status":true,"ssl":false,"http_check":%t,"fail_timeout":%d,"upstream_list":[1]}}
		]},
		"upstream_config":{"config":[
			{"pk":1,"fields":{"status":true,"address":"127.0.0.1","port":9466,"weight":100}}
		]}
	}`, name, name, httpCheck, failTimeout)
	router := gin.New()
	router.POST("/config/import/v1", h.ImportV1Config)
	request := httptest.NewRequest(http.MethodPost, "/config/import/v1", strings.NewReader(backup))
	request.Header.Set("Content-Type", "application/json")
	response := httptest.NewRecorder()
	router.ServeHTTP(response, request)
	return response
}

func TestImportV1Config_keeps_passive_rule_with_short_fail_timeout(t *testing.T) {
	response := importV1SingleRule(t, "hc-passive", false, 1)
	if response.Code != http.StatusOK {
		t.Fatalf("import status=%d body=%s, want 200（合法规则不得被整条丢弃）", response.Code, response.Body.String())
	}
	if strings.Contains(response.Body.String(), "跳过 1 条") {
		t.Fatalf("非主动探测规则被整条跳过: %s", response.Body.String())
	}
	var interval, timeout int
	if err := db.DB.QueryRow("SELECT health_check_interval, health_check_timeout FROM lb_rules WHERE name='hc-passive'").
		Scan(&interval, &timeout); err != nil {
		t.Fatalf("read imported rule: %v", err)
	}
	if interval != db.DefaultHealthCheckTimeout+1 || timeout != db.DefaultHealthCheckTimeout {
		t.Fatalf("health interval=%d timeout=%d, want %d/%d（须同时通过保存/启用不变式）",
			interval, timeout, db.DefaultHealthCheckTimeout+1, db.DefaultHealthCheckTimeout)
	}
	if !strings.Contains(response.Body.String(), "已提为") {
		t.Fatalf("归一须显性告知: %s", response.Body.String())
	}
}

func TestImportV1Config_keeps_active_interval_above_default_timeout(t *testing.T) {
	for _, failTimeout := range []int{db.DefaultHealthCheckTimeout + 1, db.DefaultHealthCheckTimeout + 3, 30} {
		t.Run(fmt.Sprintf("fail_timeout=%d", failTimeout), func(t *testing.T) {
			name := fmt.Sprintf("hc-active-%d", failTimeout)
			response := importV1SingleRule(t, name, true, failTimeout)
			if response.Code != http.StatusOK {
				t.Fatalf("import status=%d body=%s, want 200", response.Code, response.Body.String())
			}
			if strings.Contains(response.Body.String(), "已提为") {
				t.Fatalf("合法间隔被无谓归一: %s", response.Body.String())
			}
			var interval int
			if err := db.DB.QueryRow("SELECT health_check_interval FROM lb_rules WHERE name=?", name).Scan(&interval); err != nil {
				t.Fatalf("read imported rule: %v", err)
			}
			if interval != failTimeout {
				t.Fatalf("interval=%d, want 原值 %d", interval, failTimeout)
			}
		})
	}
}
