package middleware

// 登录/MFA 验证步的「触发器不可用即 500」fail-closed
// 仅主节点语义——users 触发器 WHEN COALESCE(is_master,1)=1，从节点锁写入
// （login_locked_until 置锁/清零）本就不会 bump cluster_version，fail-closed
// 在从端零保护收益、只截断登录可用性（与票据登录的排除口径一致）。

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/gin-gonic/gin"

	"lazy-balancer-v2/internal/db"
	"lazy-balancer-v2/internal/models"
)

// usersTableWriteRoutes 写 users 表同步列的 POST 路由（单源分类的 6 条 POST
// + GET /auth/oidc/callback）——分类与 fail-closed 分流共用同一清单。
var usersTableWriteRoutes = []string{
	"/api/v1/auth/login",
	"/api/v1/auth/mfa/verify",
	"/api/v1/auth/setup",
	"/api/v1/auth/mfa/activate",
	"/api/v1/auth/mfa/disable",
	"/api/v1/auth/mfa/recovery-codes",
}

// usersTableWriteTargets 上述 POST 路由 + GET 形态的 OIDC 回调（并发请求面）。
var usersTableWriteTargets = append(append([]string{}, usersTableWriteRoutes...), "/api/v1/auth/oidc/callback")

// newLoginFailClosedTestRouter 构造「触发器安装失败但 DB 本体可用」的中间件
// 形态：DROP TABLE users 使 CREATE TRIGGER ... ON users 报错（installErr
// 非空），global_config 完好（RoleOf 可读）。返回 router 与 database。
func newLoginFailClosedTestRouter(t *testing.T) (*gin.Engine, func()) {
	t.Helper()
	oldDB, oldMetricsDB, oldAuditDB := db.DB, db.MetricsDB, db.AuditDB
	if err := db.Initialize(t.TempDir()); err != nil {
		t.Fatalf("initialize database: %v", err)
	}
	database := db.DB
	cleanup := func() {
		_ = db.Close()
		restoreTestDBHandles(oldDB, oldMetricsDB, oldAuditDB)
	}
	if _, err := database.Exec("DROP TABLE users"); err != nil {
		cleanup()
		t.Fatalf("drop users to break trigger install: %v", err)
	}
	gin.SetMode(gin.TestMode)
	router := gin.New()
	router.Use(clusterVersionMiddleware(database))
	noContent := func(c *gin.Context) { c.Status(http.StatusNoContent) }
	for _, route := range usersTableWriteRoutes {
		router.POST(route, noContent)
	}
	router.GET("/api/v1/auth/oidc/callback", noContent)
	router.POST("/api/v1/auth/mfa/setup", noContent)
	router.POST("/api/v1/auth/mfa/verify-step", noContent)
	router.POST("/api/v1/rules", noContent)
	return router, cleanup
}

func serveStatus(router *gin.Engine, method, path string) (int, string) {
	recorder := httptest.NewRecorder()
	router.ServeHTTP(recorder, httptest.NewRequest(method, path, nil))
	return recorder.Code, recorder.Body.String()
}

// 目标形状：触发器降级态下从节点登录/MFA 验证步放行；主节点同请求仍 500；
// 从端其他同步写（rules）仍 500。
func TestClusterVersionMiddleware_loginFailClosedIsMasterOnly(t *testing.T) {
	router, cleanup := newLoginFailClosedTestRouter(t)
	defer cleanup()
	database := db.DB

	// Given 从节点
	if _, err := database.Exec("UPDATE global_config SET is_master=0 WHERE id=1"); err != nil {
		t.Fatal(err)
	}
	// When/Then：从端 users 表写路径全部放行（登录/开户/改 MFA 可用性保留）
	for _, path := range usersTableWriteTargets {
		method := http.MethodPost
		if path == "/api/v1/auth/oidc/callback" {
			method = http.MethodGet
		}
		if code, body := serveStatus(router, method, path); code != http.StatusNoContent {
			t.Fatalf("从节点 %s status=%d body=%q, want 204（从端 fail-closed 无保护收益）", path, code, body)
		}
	}
	// 回归：从端其他同步写仍 fail-closed 500（触发器降级保护面不缩）
	if code, body := serveStatus(router, http.MethodPost, "/api/v1/rules"); code != http.StatusInternalServerError {
		t.Fatalf("从节点 rules 同步写 status=%d body=%q, want fail-closed 500", code, body)
	}

	// Given 主节点
	if _, err := database.Exec("UPDATE global_config SET is_master=1 WHERE id=1"); err != nil {
		t.Fatal(err)
	}
	// 回归：主端 users 表写路径仍 fail-closed 500（锁传播/用户集保护语义不变）
	for _, path := range usersTableWriteTargets {
		method := http.MethodPost
		if path == "/api/v1/auth/oidc/callback" {
			method = http.MethodGet
		}
		code, body := serveStatus(router, method, path)
		if code != http.StatusInternalServerError {
			t.Fatalf("主节点 %s status=%d body=%q, want fail-closed 500", path, code, body)
		}
		var resp models.APIResponse
		if err := json.Unmarshal([]byte(body), &resp); err != nil || resp.Code != 500 || resp.Message != "集群版本触发器不可用" {
			t.Fatalf("主节点 %s body=%q, want APIResponse{500,集群版本触发器不可用}", path, body)
		}
	}
}

// 分类表：users 表写路径 7 条全部命中；两条反例（只写记账/pending 列）不得
// 被前缀捕获（否则降级态误伤 MFA 登录/step-up）。
func TestIsUsersTableWritePath_classification(t *testing.T) {
	for _, path := range usersTableWriteRoutes {
		if !isUsersTableWritePath(http.MethodPost, path) {
			t.Fatalf("POST %s 必须归类为 users 表写路径", path)
		}
	}
	if !isUsersTableWritePath(http.MethodGet, "/api/v1/auth/oidc/callback") {
		t.Fatal("GET /api/v1/auth/oidc/callback 必须归类为 users 表写路径（JIT 开户）")
	}
	for _, path := range []string{"/api/v1/auth/mfa/setup", "/api/v1/auth/mfa/verify-step"} {
		if isUsersTableWritePath(http.MethodPost, path) {
			t.Fatalf("POST %s 只写记账/pending 列，不得归类为 users 表写路径", path)
		}
	}
}

// 畸形形状：角色读失败（DB 已关闭）时 users 表写路径按写闸同语义 fail-closed
// 500——不得因「可能从节点」猜测放行。
func TestClusterVersionMiddleware_loginFailClosedOnRoleReadError(t *testing.T) {
	router, cleanup := newLoginFailClosedTestRouter(t)
	defer cleanup()
	if err := db.Close(); err != nil {
		t.Fatalf("close database to break role read: %v", err)
	}
	if code, body := serveStatus(router, http.MethodPost, "/api/v1/auth/login"); code != http.StatusInternalServerError {
		t.Fatalf("角色读失败时登录 status=%d body=%q, want fail-closed 500", code, body)
	}
}
