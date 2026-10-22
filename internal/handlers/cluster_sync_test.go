package handlers

import (
	"context"
	"database/sql"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"

	"github.com/gin-gonic/gin"

	"lazy-balancer-v2/internal/config"
	"lazy-balancer-v2/internal/db"
	"lazy-balancer-v2/internal/services"
)

func TestAuthenticatedClusterToken_uses_bearer_token(t *testing.T) {
	// 收敛为只读 ctx 值——两处调用方均挂
	// clusterTokenAuth(成功恒 Set cluster_token),头部回退不可达且语义分叉。
	// Given:中间件已注入
	context, _ := gin.CreateTestContext(httptest.NewRecorder())
	context.Request = httptest.NewRequest("GET", "/api/v1/cluster/sync/snapshot", nil)
	context.Set("cluster_token", "bearer-token")

	// When
	token := authenticatedClusterToken(context)

	// Then
	if token != "bearer-token" {
		t.Fatalf("authenticated token=%q", token)
	}
}

func TestPullClusterSnapshot_persists_manual_sync_failure(t *testing.T) {
	// Given
	oldDB, oldMetricsDB, oldAuditDB := db.DB, db.MetricsDB, db.AuditDB
	if err := db.Initialize(t.TempDir()); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		_ = db.Close()
		db.DB, db.MetricsDB, db.AuditDB = oldDB, oldMetricsDB, oldAuditDB
		db.SetDB(oldDB)
	})
	if _, err := db.DB.Exec("UPDATE global_config SET is_master=0, master_url='', cluster_token='', last_sync_error='' WHERE id=1"); err != nil {
		t.Fatal(err)
	}
	syncService := services.NewSyncService(db.DB, &config.Config{DataDir: t.TempDir()}, nil)
	h := &Handlers{syncService: syncService, clusterService: services.NewClusterService(db.DB, "")}
	response := httptest.NewRecorder()
	request := httptest.NewRequest("POST", "/api/v1/cluster/sync/pull", nil).WithContext(context.Background())
	ginContext, _ := gin.CreateTestContext(response)
	ginContext.Request = request

	// When
	h.PullClusterSnapshot(ginContext)

	// Then
	var stored string
	if err := db.DB.QueryRow("SELECT COALESCE(last_sync_error,'') FROM global_config WHERE id=1").Scan(&stored); err != nil {
		t.Fatal(err)
	}
	if response.Code != http.StatusInternalServerError || stored == "" {
		t.Fatalf("status=%d stored=%q body=%q", response.Code, stored, response.Body.String())
	}
}

// 同步下发审计的节点名查询失败(节点已删除)不得落
// 尾部空名的「节点 」,回退「节点 #<id>」。
func TestGetClusterSnapshot_auditFallsBackToNodeID(t *testing.T) {
	// Given:主节点 + cluster_node_id 指向不存在的节点 999
	oldDB, oldMetricsDB, oldAuditDB := db.DB, db.MetricsDB, db.AuditDB
	if err := db.Initialize(t.TempDir()); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		_ = db.Close()
		db.DB, db.MetricsDB, db.AuditDB = oldDB, oldMetricsDB, oldAuditDB
		db.SetDB(oldDB)
	})
	h := &Handlers{clusterService: services.NewClusterService(db.DB, "")}
	gin.SetMode(gin.TestMode)
	router := gin.New()
	router.GET("/cluster/sync/snapshot", func(c *gin.Context) {
		c.Set("cluster_node_id", 999)
		h.GetClusterSnapshot(c)
	})

	// When
	response := httptest.NewRecorder()
	router.ServeHTTP(response, httptest.NewRequest(http.MethodGet, "/cluster/sync/snapshot", nil))

	// Then:快照下发成功 + 审计含「节点 #999」而非尾部空名的「节点 」
	if response.Code != http.StatusOK {
		t.Fatalf("status=%d body=%q, want 200", response.Code, response.Body.String())
	}
	var detail string
	if err := db.AuditDB.QueryRow("SELECT detail FROM audit_log WHERE action='同步下发' AND resource='集群节点' ORDER BY id DESC LIMIT 1").Scan(&detail); err != nil {
		t.Fatalf("query sync audit: %v", err)
	}
	if strings.Contains(detail, "节点 ；") {
		t.Fatalf("audit detail=%q, want 不含尾部空名的「节点 」", detail)
	}
	if !strings.Contains(detail, "节点 #999") {
		t.Fatalf("audit detail=%q, want 含「节点 #999」", detail)
	}
}

func TestPullClusterSnapshot_master_rejected_without_sync_error(t *testing.T) {
	// 回归：主节点调手动同步端点必须入口直接 400（不调 Pull），
	// 且 last_sync_error 保持为空——不得让节点页面显示无自愈路径的假错误。
	oldDB, oldMetricsDB, oldAuditDB := db.DB, db.MetricsDB, db.AuditDB
	if err := db.Initialize(t.TempDir()); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		_ = db.Close()
		db.DB, db.MetricsDB, db.AuditDB = oldDB, oldMetricsDB, oldAuditDB
		db.SetDB(oldDB)
	})
	if _, err := db.DB.Exec("UPDATE global_config SET is_master=1, last_sync_error='' WHERE id=1"); err != nil {
		t.Fatal(err)
	}
	syncService := services.NewSyncService(db.DB, &config.Config{DataDir: t.TempDir()}, nil)
	h := &Handlers{syncService: syncService, clusterService: services.NewClusterService(db.DB, "")}
	response := httptest.NewRecorder()
	request := httptest.NewRequest("POST", "/api/v1/cluster/sync/pull", nil).WithContext(context.Background())
	ginContext, _ := gin.CreateTestContext(response)
	ginContext.Request = request

	// When
	h.PullClusterSnapshot(ginContext)

	// Then
	if response.Code != http.StatusBadRequest {
		t.Fatalf("status=%d body=%q, want 400", response.Code, response.Body.String())
	}
	var stored string
	if err := db.DB.QueryRow("SELECT COALESCE(last_sync_error,'') FROM global_config WHERE id=1").Scan(&stored); err != nil {
		t.Fatal(err)
	}
	if stored != "" {
		t.Fatalf("last_sync_error=%q, want empty（主节点手动同步不得落库）", stored)
	}
}

func TestAuthenticatedClusterToken_prefers_middleware_context(t *testing.T) {
	// Given
	context, _ := gin.CreateTestContext(httptest.NewRecorder())
	context.Request = httptest.NewRequest("GET", "/api/v1/cluster/sync/snapshot", nil)
	context.Request.Header.Set("X-Cluster-Token", "header-token")
	context.Set("cluster_token", "authenticated-token")

	// When
	token := authenticatedClusterToken(context)

	// Then
	if token != "authenticated-token" {
		t.Fatalf("authenticated token=%q", token)
	}
}

// 降级主节点不得再拉取 WAF 数据包——快照端点有 requireMaster 设防，
// WAF 数据包端点必须对称，否则残留已审批的从节点令牌可继续拉取安全数据包。
func TestGetClusterWafFiles_demotedMasterForbidden(t *testing.T) {
	// Given
	oldDB, oldMetricsDB, oldAuditDB := db.DB, db.MetricsDB, db.AuditDB
	if err := db.Initialize(t.TempDir()); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		_ = db.Close()
		db.DB, db.MetricsDB, db.AuditDB = oldDB, oldMetricsDB, oldAuditDB
		db.SetDB(oldDB)
	})
	if _, err := db.DB.Exec("UPDATE global_config SET is_master=0 WHERE id=1"); err != nil {
		t.Fatal(err)
	}
	h := &Handlers{clusterService: services.NewClusterService(db.DB, "")}
	response := httptest.NewRecorder()
	request := httptest.NewRequest("GET", "/api/v1/cluster/waf/files", nil).WithContext(context.Background())
	ginContext, _ := gin.CreateTestContext(response)
	ginContext.Request = request

	// When
	h.GetClusterWafFiles(ginContext)

	// Then
	if response.Code != http.StatusForbidden {
		t.Fatalf("status=%d body=%q, want 403（与快照端点对称的 requireMaster 门）", response.Code, response.Body.String())
	}
}

// PullClusterSnapshot 曾直接调用
// h.syncService.Pull/Resume 而无 nil 判定——同族（SetClusterMode/Promote/
// ForgetClusterPins）均以 503「同步服务未初始化」前置。装配缺失或测试注入
// nil 时，从节点手动同步会 nil 指针 panic（Gin recovery → 500 空体），
// 与同族错误形状分叉。
func TestPullClusterSnapshot_missingSyncServiceReturnsUnavailable(t *testing.T) {
	h := newBackupTestHandlers(t)
	h.syncService = nil
	if _, err := db.DB.Exec(`UPDATE global_config SET is_master=0 WHERE id=1`); err != nil {
		t.Fatal(err)
	}
	gin.SetMode(gin.TestMode)
	router := gin.New()
	router.Use(gin.Recovery())
	router.POST("/cluster/sync/pull", h.PullClusterSnapshot)
	response := httptest.NewRecorder()
	router.ServeHTTP(response, httptest.NewRequest(http.MethodPost, "/cluster/sync/pull", nil))
	if response.Code != http.StatusServiceUnavailable {
		t.Fatalf("status=%d body=%s, want 503（nil syncService 不得 panic）", response.Code, response.Body.String())
	}
	if !strings.Contains(response.Body.String(), "同步服务未初始化") {
		t.Fatalf("body=%s, want 同步服务未初始化", response.Body.String())
	}
}

// 集群服务装配缺失时 ForgetClusterPins 必须 ——此前
// `if h.clusterService != nil` 包裹主节点守卫，nil 时直接放行清除本机全部
// TOFU 钉（主节点误清从节点钉的风险路径）。
func TestForgetClusterPins_missingClusterServiceFailsClosed(t *testing.T) {
	h := newBackupTestHandlers(t)
	h.clusterService = nil
	h.syncService = &services.SyncService{}
	gin.SetMode(gin.TestMode)
	router := gin.New()
	router.Use(gin.Recovery())
	router.POST("/cluster/sync/forget-pins", h.ForgetClusterPins)
	response := httptest.NewRecorder()
	router.ServeHTTP(response, httptest.NewRequest(http.MethodPost, "/cluster/sync/forget-pins", nil))
	if response.Code != http.StatusServiceUnavailable {
		t.Fatalf("status=%d body=%s, want 503（无法确认角色不得放行）", response.Code, response.Body.String())
	}
}

// 配置导入窗口内手动同步必须 409 ——Pull 会写
// global_config/lb_rules 等导入全量替代表，窗口内提交会被静默覆盖或阻塞至
// busy_timeout 后 500；后台 daemon 仍按「主节点为准」保留。
func TestPullClusterSnapshot_conflictsWhileImportInProgress(t *testing.T) {
	h := newBackupTestHandlers(t)
	h.syncService = &services.SyncService{}
	if _, err := db.DB.Exec(`UPDATE global_config SET is_master=0 WHERE id=1`); err != nil {
		t.Fatal(err)
	}
	configImportBeginMu.Lock()
	defer configImportBeginMu.Unlock()
	gin.SetMode(gin.TestMode)
	router := gin.New()
	router.Use(gin.Recovery())
	router.POST("/cluster/sync/pull", h.PullClusterSnapshot)
	response := httptest.NewRecorder()
	router.ServeHTTP(response, httptest.NewRequest(http.MethodPost, "/cluster/sync/pull", nil))
	if response.Code != http.StatusConflict {
		t.Fatalf("status=%d body=%s, want 409（导入窗口内手动同步）", response.Code, response.Body.String())
	}
}

// 快照下发审计的节点名必须取自 handler 注入的 clusterService 句柄（与其快照
// 读取同一库）；直读全局 db.DB 会在句柄与全局库不一致时（测试注入/多实例）
// 审计到另一库的同 ID 节点名，审计对象被错标。
func TestGetClusterSnapshot_auditNodeNameReadsServiceHandle(t *testing.T) {
	oldDB, oldMetricsDB, oldAuditDB := db.DB, db.MetricsDB, db.AuditDB
	if err := db.Initialize(t.TempDir()); err != nil {
		t.Fatal(err)
	}
	serviceDB := db.DB
	if err := db.Initialize(t.TempDir()); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		_ = db.Close()
		_ = serviceDB.Close()
		db.DB, db.MetricsDB, db.AuditDB = oldDB, oldMetricsDB, oldAuditDB
		db.SetDB(oldDB)
	})
	// 两个库各有节点 21，名字不同：审计必须取服务句柄库里的名字。
	if _, err := serviceDB.Exec(`INSERT INTO nodes (id,name,ip_address,port,status,is_approved) VALUES (21,'svc-named','10.0.0.21',8000,'online',1)`); err != nil {
		t.Fatal(err)
	}
	if _, err := db.DB.Exec(`INSERT INTO nodes (id,name,ip_address,port,status,is_approved) VALUES (21,'global-named','10.0.0.21',8000,'online',1)`); err != nil {
		t.Fatal(err)
	}
	h := &Handlers{clusterService: services.NewClusterService(serviceDB, "")}
	gin.SetMode(gin.TestMode)
	router := gin.New()
	router.GET("/cluster/sync/snapshot", func(c *gin.Context) {
		c.Set("cluster_node_id", 21)
		h.GetClusterSnapshot(c)
	})

	response := httptest.NewRecorder()
	router.ServeHTTP(response, httptest.NewRequest(http.MethodGet, "/cluster/sync/snapshot", nil))
	if response.Code != http.StatusOK {
		t.Fatalf("status=%d body=%q, want 200", response.Code, response.Body.String())
	}
	var detail string
	if err := db.AuditDB.QueryRow("SELECT detail FROM audit_log WHERE action='同步下发' AND resource='集群节点' ORDER BY id DESC LIMIT 1").Scan(&detail); err != nil {
		t.Fatalf("query sync audit: %v", err)
	}
	if !strings.Contains(detail, "节点 svc-named") {
		t.Fatalf("audit detail=%q, want 服务句柄库中的节点名 svc-named", detail)
	}
	if strings.Contains(detail, "global-named") {
		t.Fatalf("audit detail=%q, 不得读取全局 db.DB 库中的节点名", detail)
	}
}

// 手动同步角色读取必须走 h.clusterService 句柄（与 GetClusterSnapshot/
// ForgetClusterPins 同口径）：装配缺失 → 503，角色查询失败 → 500——瞬时 DB
// 故障不得伪装成「主节点无需手动同步」400 误导排障。
func TestPullClusterSnapshot_missingClusterServiceReturnsUnavailable(t *testing.T) {
	h := newBackupTestHandlers(t)
	h.clusterService = nil
	h.syncService = &services.SyncService{}
	gin.SetMode(gin.TestMode)
	router := gin.New()
	router.Use(gin.Recovery())
	router.POST("/cluster/sync/pull", h.PullClusterSnapshot)
	response := httptest.NewRecorder()
	router.ServeHTTP(response, httptest.NewRequest(http.MethodPost, "/cluster/sync/pull", nil))
	if response.Code != http.StatusServiceUnavailable {
		t.Fatalf("status=%d body=%s, want 503（装配缺失）", response.Code, response.Body.String())
	}
}

func TestPullClusterSnapshot_roleQueryFailureReturns500(t *testing.T) {
	h := newBackupTestHandlers(t)
	// 已关闭的库句柄：角色查询必然失败。
	closedDB, err := sql.Open("sqlite", filepath.Join(t.TempDir(), "closed.db"))
	if err != nil {
		t.Fatal(err)
	}
	if err := closedDB.Close(); err != nil {
		t.Fatal(err)
	}
	h.clusterService = services.NewClusterService(closedDB, "")
	h.syncService = &services.SyncService{}
	gin.SetMode(gin.TestMode)
	router := gin.New()
	router.Use(gin.Recovery())
	router.POST("/cluster/sync/pull", h.PullClusterSnapshot)
	response := httptest.NewRecorder()
	router.ServeHTTP(response, httptest.NewRequest(http.MethodPost, "/cluster/sync/pull", nil))
	if response.Code != http.StatusInternalServerError {
		t.Fatalf("status=%d body=%s, want 500（角色查询失败不得误映射 400 主节点语义）", response.Code, response.Body.String())
	}
}
