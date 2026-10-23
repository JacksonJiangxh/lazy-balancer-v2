package handlers

// 重试窗口值域（单源 validateTCPTryWindowBounds）：http 侧 [-1,60000]
//（-1=NTLM 接管哨兵）、tcp 侧 [0,60000]、duration>0 ⇒ interval≥1。本文件锁定
// 全部消费面：
//   ① 保存族三入口——保存门（validateRuleFeatures）；
//   ② UpdateRule 存量越界行的编辑自愈（镜像负值先例）；
//   ③ DuplicateRule 源行越界值不放大到副本；
//   ④ 存量两面——单规则启用门与启动/UpdateConfig 聚合门（同一值域表）。
// 存量为纯测试文件（唯一写点），不触碰既有钉测。

import (
	"context"
	"database/sql"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/gin-gonic/gin"

	"lazy-balancer-v2/internal/db"
)

// 保存门上界——两协议、两字段的 >60000 值一律拒绝；60000 边界与
// http 侧 td=-1（NTLM 接管态）仍放行。
func TestValidateRuleFeatures_rejectsOutOfRangeTryWindow(t *testing.T) {
	base := func(protocol string) ruleFeatureInput {
		input := ruleFeatureInput{
			Protocol:           protocol,
			Strategy:           "weighted_round_robin",
			ListenPort:         19099,
			TCPTryInterval:     250,
			TCPTryDuration:     3,
			TCPHealthCheckPort: 9123,
		}
		if protocol == "http" {
			input.ListenPort = 8080

			input.TCPHealthCheckPort = 0
		}
		return input
	}

	rejectCases := []struct {
		protocol string
		name     string
		mutate   func(*ruleFeatureInput)
	}{
		{"tcp", "tcp duration above max", func(i *ruleFeatureInput) { i.TCPTryDuration = 60001 }},
		{"tcp", "tcp interval above max", func(i *ruleFeatureInput) { i.TCPTryInterval = 60001 }},
		{"tcp", "tcp duration far above max", func(i *ruleFeatureInput) { i.TCPTryDuration = 1_000_000 }},
		{"http", "http interval above max", func(i *ruleFeatureInput) { i.TCPTryInterval = 60001 }},
		{"http", "http duration above max", func(i *ruleFeatureInput) { i.TCPTryDuration = 60001 }},
		// http 侧下界——修复前只判 >60000，负 interval 静默落库。
		{"http", "http interval below min", func(i *ruleFeatureInput) { i.TCPTryInterval = -1 }},
		{"http", "http interval far below min", func(i *ruleFeatureInput) { i.TCPTryInterval = -250 }},
		{"http", "http duration below min", func(i *ruleFeatureInput) { i.TCPTryDuration = -2 }},
	}
	for _, tc := range rejectCases {
		t.Run(tc.name, func(t *testing.T) {
			input := base(tc.protocol)
			tc.mutate(&input)
			if err := validateRuleFeatures(input); err == nil {
				t.Fatalf("%s must be rejected, got nil error", tc.name)
			}
		})
	}

	// 边界放行形状：60000 两协议、两字段均为合法上界；http interval 0 合法。
	validCases := []struct {
		protocol string
		name     string
		mutate   func(*ruleFeatureInput)
	}{
		{"tcp", "tcp at upper bound", func(i *ruleFeatureInput) { i.TCPTryDuration = 60000; i.TCPTryInterval = 60000 }},
		{"http", "http at upper bound", func(i *ruleFeatureInput) {
			i.TCPTryDuration = 60000
			i.TCPTryInterval = 60000
		}},
		{"http", "http ntlm sentinel -1", func(i *ruleFeatureInput) {
			i.TCPTryDuration = -1
			i.TCPTryInterval = 250
		}},
		// interval=0 仅在零窗口时合法——渲染层要求
		// duration>0 时 interval 必填（字段门已同源，见
		// TestTryWindow_requiresPositiveIntervalAtFieldGate）。
		{"http", "http zero interval with zero window", func(i *ruleFeatureInput) {
			i.TCPTryDuration = 0
			i.TCPTryInterval = 0
		}},
	}
	for _, tc := range validCases {
		t.Run(tc.name, func(t *testing.T) {
			input := base(tc.protocol)
			tc.mutate(&input)
			if err := validateRuleFeatures(input); err != nil {
				t.Fatalf("%s must pass, got %v", tc.name, err)
			}
		})
	}
}

// （TCP）：直改 DB 的越界 TCP 行随任意同协议编辑自愈归零（0=默认窗口），
// 修复前会命中新增上界门 400 死端（与负值自愈同格）。
func TestUpdateRule_tcpEditHealsOutOfRangeTryWindowResidue(t *testing.T) {
	handler := newRuleFeatureTestHandlers(t)
	gin.SetMode(gin.TestMode)
	router := gin.New()
	router.PUT("/rules/:caddy_id", handler.UpdateRule)

	// Given：直改 DB 的 TCP 行带 td=60001/ti=70000（越界存量）
	if _, err := db.DB.Exec(`INSERT INTO lb_rules (caddy_id,name,description,protocol,domain,listen_port,strategy,enabled,tcp_try_duration,tcp_try_interval)
		VALUES ('lb_tcptrymax','tcptrymax','','tcp','',18611,'weighted_round_robin',1,60001,70000)`); err != nil {
		t.Fatalf("seed rule: %v", err)
	}
	if _, err := db.DB.Exec(`INSERT INTO upstreams (rule_id,host,port,weight,enabled,protocol) VALUES ('lb_tcptrymax','up.test',9000,1,1,'tcp')`); err != nil {
		t.Fatalf("seed upstream: %v", err)
	}

	// When：同协议编辑（纯改名，不携带重试窗口字段）
	request := httptest.NewRequest(http.MethodPut, "/rules/lb_tcptrymax", strings.NewReader(`{"name":"tcptrymax-renamed","protocol":"tcp"}`))
	request.Header.Set("Content-Type", "application/json")
	response := httptest.NewRecorder()
	router.ServeHTTP(response, request)

	// Then：200（修复前 400 上界门死端）且越界值归零
	if response.Code != http.StatusOK {
		t.Fatalf("tcp edit: status=%d body=%s", response.Code, response.Body.String())
	}
	var tryDuration, tryInterval int
	if err := db.DB.QueryRow(`SELECT COALESCE(tcp_try_duration,0), COALESCE(tcp_try_interval,0) FROM lb_rules WHERE caddy_id='lb_tcptrymax'`).
		Scan(&tryDuration, &tryInterval); err != nil {
		t.Fatal(err)
	}
	if tryDuration != 0 || tryInterval != 0 {
		t.Fatalf("越界重试窗口未自愈: tcp_try_duration=%d tcp_try_interval=%d, want 0/0", tryDuration, tryInterval)
	}
}

// （http）：越界 tcp_try_interval 在 http 侧同样无自救路径（新增上界门
// 后任意编辑 400），编辑自愈归零；-1 合法哨兵不归零（本用例只带 ti 越界）。
func TestUpdateRule_httpEditHealsOutOfRangeTryIntervalResidue(t *testing.T) {
	handler := newRuleFeatureTestHandlers(t)
	gin.SetMode(gin.TestMode)
	router := gin.New()
	router.PUT("/rules/:caddy_id", handler.UpdateRule)

	// Given：直改 DB 的 http 行带 ti=70000（越界存量）
	if _, err := db.DB.Exec(`INSERT INTO lb_rules (caddy_id,name,description,protocol,domain,listen_port,strategy,enabled,tcp_try_duration,tcp_try_interval)
		VALUES ('lb_httptrymax','httptrymax','','http','httptrymax.test',18612,'weighted_round_robin',1,0,70000)`); err != nil {
		t.Fatalf("seed rule: %v", err)
	}
	if _, err := db.DB.Exec(`INSERT INTO upstreams (rule_id,host,port,weight,enabled,protocol) VALUES ('lb_httptrymax','up.test',80,1,1,'http')`); err != nil {
		t.Fatalf("seed upstream: %v", err)
	}

	// When：同协议编辑（纯改名）
	request := httptest.NewRequest(http.MethodPut, "/rules/lb_httptrymax", strings.NewReader(`{"name":"httptrymax-renamed"}`))
	request.Header.Set("Content-Type", "application/json")
	response := httptest.NewRecorder()
	router.ServeHTTP(response, request)

	// Then：200 且越界 interval 归零
	if response.Code != http.StatusOK {
		t.Fatalf("http edit: status=%d body=%s", response.Code, response.Body.String())
	}
	var tryInterval int
	if err := db.DB.QueryRow(`SELECT COALESCE(tcp_try_interval,0) FROM lb_rules WHERE caddy_id='lb_httptrymax'`).Scan(&tryInterval); err != nil {
		t.Fatal(err)
	}
	if tryInterval != 0 {
		t.Fatalf("越界重试间隔未自愈: tcp_try_interval=%d, want 0", tryInterval)
	}
}

// DuplicateRule 把源行越界窗口原样喂进 validateRuleFeatures——tcp 与
// http 源行复制均命中上界门 400 死端；越界值不放大到副本，非越界值原样复制。
func TestDuplicateRule_healsOutOfRangeTryWindowResidue(t *testing.T) {
	handler := newRuleFeatureTestHandlers(t)
	gin.SetMode(gin.TestMode)
	router := gin.New()
	router.POST("/rules/:caddy_id/duplicate", handler.DuplicateRule)

	// tcp 源行
	if _, err := db.DB.Exec(`INSERT INTO lb_rules (caddy_id,name,description,protocol,domain,listen_port,strategy,enabled,tcp_try_duration,tcp_try_interval)
		VALUES ('lb_tcpdupwin','tcpdupwin','','tcp','',18613,'weighted_round_robin',1,60001,70000)`); err != nil {
		t.Fatalf("seed tcp rule: %v", err)
	}
	if _, err := db.DB.Exec(`INSERT INTO upstreams (rule_id,host,port,weight,enabled,protocol) VALUES ('lb_tcpdupwin','up.test',9000,1,1,'tcp')`); err != nil {
		t.Fatalf("seed tcp upstream: %v", err)
	}
	// http 源行（越界 interval）
	if _, err := db.DB.Exec(`INSERT INTO lb_rules (caddy_id,name,description,protocol,domain,listen_port,strategy,enabled,tcp_try_duration,tcp_try_interval)
		VALUES ('lb_httpdupwin','httpdupwin','','http','httpdupwin.test',18614,'weighted_round_robin',1,0,65535)`); err != nil {
		t.Fatalf("seed http rule: %v", err)
	}
	if _, err := db.DB.Exec(`INSERT INTO upstreams (rule_id,host,port,weight,enabled,protocol) VALUES ('lb_httpdupwin','up.test',80,1,1,'http')`); err != nil {
		t.Fatalf("seed http upstream: %v", err)
	}

	cases := []struct {
		name       string
		sourceID   string
		copyName   string
		wantStatus int
	}{
		{"tcp source", "lb_tcpdupwin", "tcpdupwin（副本）", http.StatusCreated},
		{"http source", "lb_httpdupwin", "httpdupwin（副本）", http.StatusCreated},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			response := httptest.NewRecorder()
			router.ServeHTTP(response, httptest.NewRequest(http.MethodPost, "/rules/"+tc.sourceID+"/duplicate", nil))
			if response.Code != tc.wantStatus {
				t.Fatalf("duplicate %s: status=%d body=%s, want %d", tc.name, response.Code, response.Body.String(), tc.wantStatus)
			}
			var tryDuration, tryInterval sql.NullInt64
			if err := db.DB.QueryRow(`SELECT tcp_try_duration, tcp_try_interval FROM lb_rules WHERE name=?`, tc.copyName).
				Scan(&tryDuration, &tryInterval); err != nil {
				t.Fatalf("read copy %s: %v", tc.copyName, err)
			}
			if tryDuration.Int64 != 0 || tryInterval.Int64 != 0 {
				t.Fatalf("副本越界窗口未归零: tcp_try_duration=%d tcp_try_interval=%d, want 0/0", tryDuration.Int64, tryInterval.Int64)
			}
		})
	}
}

// 存量面：直改 DB / 导入 / 集群快照落库的越界重试窗口，必须在启用门与
// 启动（UpdateConfig）聚合门同样被拒——否则同一坏行「启用报错、重启静默降级」。
// 单源 validateTCPTryWindowBounds 是保存门与存量门的唯一值域表。
func TestStoredOutOfRangeTryWindowRejectedOnEnableAndAggregate(t *testing.T) {
	t.Run("enable gate", func(t *testing.T) {
		handler, _, _ := newAuditRuleHandlers(t, 0)
		seedTCPStoredRule(t, "lb_tcptry_store", "tcptry-store", 18621, false, "weighted_round_robin", false)
		if _, err := db.DB.Exec(`UPDATE lb_rules SET tcp_try_duration=60001, tcp_try_interval=250 WHERE caddy_id='lb_tcptry_store'`); err != nil {
			t.Fatal(err)
		}
		router := gin.New()
		router.POST("/rules/:caddy_id/enable", handler.EnableRule)

		response := httptest.NewRecorder()
		router.ServeHTTP(response, httptest.NewRequest(http.MethodPost, "/rules/lb_tcptry_store/enable", nil))

		if response.Code != http.StatusBadRequest {
			t.Fatalf("enable status=%d body=%s, want 400（越界重试窗口必须拒绝启用）", response.Code, response.Body.String())
		}
		if !strings.Contains(response.Body.String(), "60000") {
			t.Fatalf("enable body=%s, want 值域文案", response.Body.String())
		}
		var enabled bool
		if err := db.DB.QueryRow(`SELECT enabled FROM lb_rules WHERE caddy_id='lb_tcptry_store'`).Scan(&enabled); err != nil {
			t.Fatal(err)
		}
		if enabled {
			t.Fatal("越界重试窗口的规则不得被启用")
		}
	})

	t.Run("startup aggregate gate", func(t *testing.T) {
		initializeRuleFeatureTestDB(t)
		seedTCPStoredRule(t, "lb_tcptry_agg", "tcptry-agg", 18622, true, "weighted_round_robin", false)
		if _, err := db.DB.Exec(`UPDATE lb_rules SET tcp_try_interval=70000 WHERE caddy_id='lb_tcptry_agg'`); err != nil {
			t.Fatal(err)
		}

		err := validateEnabledStoredRuleConfigs(context.Background())
		if err == nil || !strings.Contains(err.Error(), "60000") {
			t.Fatalf("aggregate validation must reject out-of-range try window, got %v", err)
		}
	})

	t.Run("http ntlm sentinel still allowed", func(t *testing.T) {
		if err := validateTCPTryWindowBounds("http", -1, 250); err != nil {
			t.Fatalf("http duration=-1（NTLM 接管哨兵）必须放行, got %v", err)
		}
	})
}
