package handlers

// 规则族提交后补偿链的两条不变量（与设置族/逃生口同口径）：
//   - 补偿链的 restoreImportRuntime→ApplyConfig 会把「请求前运行配置」写进
//     LKG；该快照可能本身就是漂移形态（逃生口写入 / 外来 caddy api 改动），
//     补偿完成后必须把 LKG 钉回已提交库视图。
//   - 补偿/恢复失败 = 库态与运行态分叉：刷新页面后唯一可见信号是
//     caddy_apply_error 横幅；真实 /load 已发生，重载审计不得因随后失败缺席。

import (
	"io"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"sync"
	"testing"

	"github.com/gin-gonic/gin"

	"lazy-balancer-v2/internal/config"
	"lazy-balancer-v2/internal/db"
	"lazy-balancer-v2/internal/services"
)

// acmeCompensationRuleBody 命中 CreateRule 的 ACME 分支（测试环境 CA 队列
// 未初始化 → 提交后走 restoreCreatedRule 补偿）。
const acmeCompensationRuleBody = `{"name":"acme-comp","protocol":"http","listen_port":18099,"domain":"acme-comp.example.test","enabled":true,"enable_tls":true,"tls_source":"acme_dns","acme_config_id":1,"ca_provider_id":1,"health_check_interval":10,"health_check_timeout":2,"health_check_unhealthy_threshold":3,"health_check_healthy_threshold":2,"upstreams":[{"host":"127.0.0.1","port":9000,"weight":1,"enabled":true}]}`

// seedACMEForCompensation 建一条可用的 CA 提供商与 DNS 凭证配置（ACME 规则
// 的引用门），使 CreateRule 能走到提交后的队列分支。
func seedACMEForCompensation(t *testing.T) {
	t.Helper()
	if _, err := db.DB.Exec(`INSERT OR IGNORE INTO ca_providers (id,name,provider,directory_url,credentials,enabled)
		VALUES (1,'comp-ca','letsencrypt','https://acme-v02.api.letsencrypt.org/directory','{}',1)`); err != nil {
		t.Fatalf("seed ca provider: %v", err)
	}
	if _, err := db.DB.Exec(`INSERT OR IGNORE INTO certificate_configs (id,name,dns_provider,dns_credentials,enabled)
		VALUES (1,'comp-dns','dnspod','{"id":"1","token":"t"}',1)`); err != nil {
		t.Fatalf("seed certificate config: %v", err)
	}
}

// driftedRuntimeConfigSecond 是「请求前运行配置」的第二次读取形态：快照读取
// 之后运行配置又被带外改动（同 id 不同内容）——补偿回弹因此是一次真实
// /load，而不是同字节短路。
const driftedRuntimeConfigSecond = `{"apps":{"http":{"servers":{"s_80":{"routes":[{"@id":"foreign_extra_v2","handle":[]}]}}}}}`

// newCompensationLoadHandlers 桩 Caddy：GET /config 首次返回漂移形态（快照
// 来源，含外来路由），后续返回另一形态（保证补偿回弹不被同字节短路）；
// 候选 /load 恒成功；restoreLoadSucceeds 决定后续 /load 结果。
func newCompensationLoadHandlers(t *testing.T, restoreLoadSucceeds bool) (*Handlers, string) {
	t.Helper()
	initializeRuleFeatureTestDB(t)
	seedACMEForCompensation(t)
	var mu sync.Mutex
	loads, gets := 0, 0
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.Method == http.MethodGet && r.URL.Path == "/config/":
			w.Header().Set("Content-Type", "application/json")
			mu.Lock()
			gets++
			first := gets == 1
			mu.Unlock()
			if first {
				_, _ = w.Write([]byte(driftedRuntimeConfig))
				return
			}
			_, _ = w.Write([]byte(driftedRuntimeConfigSecond))
			return
		case r.Method == http.MethodPost && r.URL.Path == "/load":
			_, _ = io.ReadAll(r.Body)
			mu.Lock()
			loads++
			n := loads
			mu.Unlock()
			if n > 1 && !restoreLoadSucceeds {
				http.Error(w, "restore load rejected", http.StatusInternalServerError)
				return
			}
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{}`))
	}))
	t.Cleanup(server.Close)
	lkgPath := filepath.Join(t.TempDir(), "last_good.json")
	service := services.NewCaddyService(server.URL)
	service.SetLastGoodPath(lkgPath)
	return &Handlers{
		cfg:            &config.Config{CaddyAdminURL: server.URL},
		caddyService:   service,
		clusterService: services.NewClusterService(db.DB, ""),
	}, lkgPath
}

// Given：CreateRule 提交成功、证书任务入队失败（CA 队列未初始化）→ 补偿
// 回弹运行配置成功（LKG 因此被写成请求前漂移快照）。
// Then：补偿链末尾把 LKG 钉回已提交库视图——不得含外来路由。
func TestCreateRule_compensationPinsLastGoodToCommittedView(t *testing.T) {
	handler, lkgPath := newCompensationLoadHandlers(t, true)
	gin.SetMode(gin.TestMode)
	router := gin.New()
	router.POST("/rules", handler.CreateRule)

	request := httptest.NewRequest(http.MethodPost, "/rules", strings.NewReader(acmeCompensationRuleBody))
	request.Header.Set("Content-Type", "application/json")
	response := httptest.NewRecorder()
	router.ServeHTTP(response, request)
	if response.Code != http.StatusInternalServerError {
		t.Fatalf("status=%d body=%s, want 500（CA 队列未初始化触发补偿）", response.Code, response.Body.String())
	}
	// 补偿成功（恢复 /load 成功）时不得写失败横幅。
	var banner string
	if err := db.DB.QueryRow(`SELECT COALESCE(caddy_apply_error,'') FROM global_config WHERE id=1`).Scan(&banner); err != nil {
		t.Fatalf("read banner: %v", err)
	}
	if banner != "" {
		t.Fatalf("补偿成功不应留下失败横幅: %q", banner)
	}
	assertLastGoodIsCommittedView(t, lkgPath)
}

// Given：同一路径，但补偿回弹的 /load 也失败（库态/运行态分叉）。
// Then：横幅落「运行配置状态未知」口径 + 真实 /load 的「重载」审计在册。
func TestCreateRule_compensationRestoreFailureWritesBannerAndReloadAudit(t *testing.T) {
	handler, _ := newCompensationLoadHandlers(t, false)
	gin.SetMode(gin.TestMode)
	router := gin.New()
	router.POST("/rules", handler.CreateRule)

	request := httptest.NewRequest(http.MethodPost, "/rules", strings.NewReader(acmeCompensationRuleBody))
	request.Header.Set("Content-Type", "application/json")
	response := httptest.NewRecorder()
	router.ServeHTTP(response, request)
	if response.Code != http.StatusInternalServerError {
		t.Fatalf("status=%d body=%s, want 500", response.Code, response.Body.String())
	}

	var banner string
	if err := db.DB.QueryRow(`SELECT COALESCE(caddy_apply_error,'') FROM global_config WHERE id=1`).Scan(&banner); err != nil {
		t.Fatalf("read banner: %v", err)
	}
	if banner == "" {
		t.Fatal("补偿恢复失败必须落 caddy_apply_error 横幅（刷新后唯一可见信号）")
	}
	if !strings.Contains(banner, "运行配置状态未知") {
		t.Fatalf("横幅=%q, want 含「运行配置状态未知」（恢复失败不得断言旧配置已保留）", banner)
	}

	var reloadRows int
	if err := db.AuditDB.QueryRow(`SELECT COUNT(*) FROM audit_log WHERE action='重载' AND resource='Caddy服务'`).Scan(&reloadRows); err != nil {
		t.Fatalf("read reload audit: %v", err)
	}
	if reloadRows == 0 {
		t.Fatal("真实 /load 已发生，提交后失败分支不得吞掉「重载」审计")
	}
	// 回归形状：补偿成功后不得残留失败横幅（上方用例）与本用例的横幅互斥；
	// 并且补偿确实回滚了已提交的规则行。
	var rules int
	if err := db.DB.QueryRow(`SELECT COUNT(*) FROM lb_rules WHERE caddy_id LIKE 'lb_%'`).Scan(&rules); err != nil {
		t.Fatalf("read rules: %v", err)
	}
	if rules != 0 {
		t.Fatalf("补偿失败路径上已提交规则仍存在（count=%d）", rules)
	}
}
