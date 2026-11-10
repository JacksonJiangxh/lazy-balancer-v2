package middleware

// fail-closed 与降级分支的最小覆盖：守卫/降级路径此前零用例（实现分支存在
// 但删除后测试仍绿）。每条都钉「删除该分支即复现失败方向」。

import (
	"database/sql"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/gin-gonic/gin"

	"lazy-balancer-v2/internal/db"
)

// Given 节点角色不可读（独立库句柄已关闭，半可用 DB 形态）。
// Then readOnlyGuard 必须 500「节点角色查询失败」——不得猜测角色放行或 403。
func TestReadOnlyGuard_roleReadFailureIsInternalError(t *testing.T) {
	database, err := sql.Open("sqlite", t.TempDir()+"/closed.db")
	if err != nil {
		t.Fatalf("open db: %v", err)
	}
	if err := database.Close(); err != nil {
		t.Fatalf("close db: %v", err)
	}
	gin.SetMode(gin.TestMode)
	router := gin.New()
	router.Use(readOnlyGuard(database))
	router.POST("/api/v1/rules", func(c *gin.Context) { c.Status(http.StatusNoContent) })

	response := httptest.NewRecorder()
	router.ServeHTTP(response, httptest.NewRequest(http.MethodPost, "/api/v1/rules", nil))

	if response.Code != http.StatusInternalServerError {
		t.Fatalf("status=%d body=%s, want 500（角色读失败必须 fail-closed）", response.Code, response.Body.String())
	}
	if !strings.Contains(response.Body.String(), "节点角色查询失败") {
		t.Fatalf("body=%s, want 含「节点角色查询失败」", response.Body.String())
	}
}

// Given 半可用 DB：MFA 开关可读（global_config 存在）但角色列不可读
// （is_master 列被改名）。
// Then mfaStepUpGuard 必须 500——不得把基建读失败当成「无从节点限制」放行。
func TestMFAStepUpGuard_roleReadFailureIsInternalError(t *testing.T) {
	oldDB, oldMetricsDB, oldAuditDB := db.DB, db.MetricsDB, db.AuditDB
	if err := db.Initialize(t.TempDir()); err != nil {
		t.Fatalf("initialize database: %v", err)
	}
	t.Cleanup(func() {
		_ = db.Close()
		restoreTestDBHandles(oldDB, oldMetricsDB, oldAuditDB)
	})
	database := db.DB
	if _, err := database.Exec(`INSERT INTO users (id,username,password_hash,role,is_enabled,mfa_enabled) VALUES (77,'stepup','x','admin',1,1)`); err != nil {
		t.Fatalf("seed mfa user: %v", err)
	}
	if _, err := database.Exec(`UPDATE global_config SET mfa_write_guard=1 WHERE id=1`); err != nil {
		t.Fatalf("enable mfa write guard: %v", err)
	}
	if _, err := database.Exec(`ALTER TABLE global_config RENAME COLUMN is_master TO is_master_gone`); err != nil {
		t.Fatalf("rename is_master to break role read: %v", err)
	}
	t.Cleanup(func() {
		if _, err := database.Exec(`ALTER TABLE global_config RENAME COLUMN is_master_gone TO is_master`); err != nil {
			t.Errorf("restore is_master column: %v", err)
		}
	})

	gin.SetMode(gin.TestMode)
	router := gin.New()
	router.Use(func(c *gin.Context) {
		c.Set("auth_type", "jwt")
		c.Set("auth_method", "password")
		c.Set("user_id", 77)
		c.Set("role", "admin")
		c.Next()
	})
	router.Use(mfaStepUpGuard(database))
	router.POST("/api/v1/rules", func(c *gin.Context) { c.Status(http.StatusNoContent) })

	response := httptest.NewRecorder()
	router.ServeHTTP(response, httptest.NewRequest(http.MethodPost, "/api/v1/rules", nil))

	if response.Code != http.StatusInternalServerError {
		t.Fatalf("status=%d body=%s, want 500（角色读失败必须 fail-closed）", response.Code, response.Body.String())
	}
	if !strings.Contains(response.Body.String(), "节点角色查询失败") {
		t.Fatalf("body=%s, want 含「节点角色查询失败」", response.Body.String())
	}
}

// Given 全表 1024 桶都是受保护桶（login/register 交替），无凭证桶/匿名桶可淘汰。
// When 新匿名来源首次请求。
// Then tier-3 淘汰仍建桶（不得因「只剩余受保护桶」而跳过建桶 = 该来源本分钟
// 零限流 fail-open），且桶表保持容量上限。
func TestRateLimitBucketEviction_tier3StillCreatesBucket(t *testing.T) {
	withIsolatedRateLimitBuckets(t)
	now := time.Now()
	loginRateBuckets.Lock()
	for index := range rateLimitBucketCapacity {
		scope := "login"
		if index%2 == 1 {
			scope = "register"
		}
		bucket := &loginRateBucket{until: now.Add(time.Minute), count: 1}
		bucket.lastUsed.Store(now.Add(time.Duration(index) * time.Millisecond).UnixNano())
		loginRateBuckets.entries[fmt.Sprintf("198.51.100.%d|%s", index, scope)] = bucket
	}
	if got := len(loginRateBuckets.entries); got != rateLimitBucketCapacity {
		loginRateBuckets.Unlock()
		t.Fatalf("fixture size=%d, want %d", got, rateLimitBucketCapacity)
	}
	loginRateBuckets.Unlock()

	bucket := acquireRateLimitBucket("203.0.113.201", "oidc-callback", now)

	if bucket == nil {
		t.Fatal("tier-3 淘汰后必须返回计数桶（返回 nil/跳过建桶 = 新来源零限流）")
	}
	loginRateBuckets.Lock()
	_, bucketed := loginRateBuckets.entries["203.0.113.201|oidc-callback"]
	size := len(loginRateBuckets.entries)
	loginRateBuckets.Unlock()
	if !bucketed {
		t.Fatal("新键必须真实入表（否则本分钟限流 fail-open）")
	}
	if size != rateLimitBucketCapacity {
		t.Fatalf("桶表 size=%d, want %d（淘汰腾位后严格有界）", size, rateLimitBucketCapacity)
	}
}

// Given 本节点已降级为从节点（is_master=0），残留 nodes 行与旧令牌仍可用。
// When 该节点上报 detached。
// Then 403 master-only（X-LB-Error-Code=MASTER_REQUIRED）且节点行保留——
// 降级主节点不得替旧集群删节点。
func TestReportClusterNode_detachedDeniedOnSlave(t *testing.T) {
	router := newMiddlewareTestRouter(t)
	const token = "detach-slave-token"
	nodeID := seedDetachedNode(t, token)
	if _, err := db.DB.Exec(`UPDATE global_config SET is_master=0 WHERE id=1`); err != nil {
		t.Fatalf("demote node: %v", err)
	}

	response := httptest.NewRecorder()
	request := httptest.NewRequest(http.MethodPost, "/api/v1/cluster/nodes/report", strings.NewReader(`{"applied_version":0,"service_status":"ok","detached":true}`))
	request.Header.Set("Content-Type", "application/json")
	request.Header.Set("X-Cluster-Token", token)
	router.ServeHTTP(response, request)

	if response.Code != http.StatusForbidden {
		t.Fatalf("status=%d body=%s, want 403", response.Code, response.Body.String())
	}
	if got := response.Header().Get("X-LB-Error-Code"); got != "master_required" {
		t.Fatalf("X-LB-Error-Code=%q, want master_required", got)
	}
	if !detachNodeExists(t, nodeID) {
		t.Fatal("降级主节点不得删除节点行")
	}
}

// Given 未审批节点（is_approved=0）持正确令牌。
// When 机器端点认证。
// Then 401（审批是独立前置条件，令牌正确不等于可用）。
func TestClusterTokenAuth_unapprovedNodeRejected(t *testing.T) {
	database, token := newClusterAuthContractDatabase(t)
	router := newClusterAuthContractRouter(database)
	if _, err := database.Exec(`UPDATE nodes SET is_approved=0`); err != nil {
		t.Fatalf("unapprove node: %v", err)
	}

	request := httptest.NewRequest(http.MethodGet, "/cluster", nil)
	request.Header.Set("X-Cluster-Token", token)
	response := httptest.NewRecorder()
	router.ServeHTTP(response, request)

	if response.Code != http.StatusUnauthorized {
		t.Fatalf("status=%d body=%q, want 401", response.Code, response.Body.String())
	}
}

// Given 装配期注入句柄（从节点库）与进程级原子句柄（主节点库）指向不同库。
// When 启用 MFA 的用户发起需 step-up 的写请求。
// Then 从节点短路必须读注入句柄（与 readOnlyGuard/clusterVersionMiddleware
// 同源）→ 403；旧实现读包级 db.GetDB()（主节点）→ 428，同一请求上两守卫
// 结论相反。句柄来源第三态（注入与进程句柄不同库）是本用例钉住的唯一形态。
func TestMFAStepUpGuard_roleReadsInjectedHandle(t *testing.T) {
	oldDB, oldMetricsDB, oldAuditDB := db.DB, db.MetricsDB, db.AuditDB
	if err := db.Initialize(t.TempDir()); err != nil {
		t.Fatalf("initialize database: %v", err)
	}
	t.Cleanup(func() {
		_ = db.Close()
		restoreTestDBHandles(oldDB, oldMetricsDB, oldAuditDB)
	})
	database := db.DB
	if _, err := database.Exec(`INSERT INTO users (id,username,password_hash,role,is_enabled,mfa_enabled) VALUES (91,'injected','x','admin',1,1)`); err != nil {
		t.Fatalf("seed mfa user: %v", err)
	}
	if _, err := database.Exec(`UPDATE global_config SET mfa_write_guard=1, is_master=1 WHERE id=1`); err != nil {
		t.Fatalf("enable mfa write guard: %v", err)
	}

	// 独立从节点库：守卫的三处读取（开关/用户 MFA 状态/节点角色）全走它。
	slaveDB, err := sql.Open("sqlite", t.TempDir()+"/injected-slave.db")
	if err != nil {
		t.Fatalf("open injected db: %v", err)
	}
	t.Cleanup(func() { _ = slaveDB.Close() })
	if _, err := slaveDB.Exec(`CREATE TABLE global_config (id INTEGER PRIMARY KEY, is_master INTEGER, mfa_write_guard INTEGER);
		INSERT INTO global_config (id,is_master,mfa_write_guard) VALUES (1,0,1);
		CREATE TABLE users (id INTEGER PRIMARY KEY, mfa_enabled INTEGER);
		INSERT INTO users (id,mfa_enabled) VALUES (91,1)`); err != nil {
		t.Fatalf("seed injected slave db: %v", err)
	}

	gin.SetMode(gin.TestMode)
	router := gin.New()
	router.Use(func(c *gin.Context) {
		c.Set("auth_type", "jwt")
		c.Set("auth_method", "password")
		c.Set("user_id", 91)
		c.Set("role", "admin")
		c.Next()
	})
	router.Use(mfaStepUpGuard(slaveDB))
	router.POST("/api/v1/rules", func(c *gin.Context) { c.Status(http.StatusNoContent) })

	response := httptest.NewRecorder()
	router.ServeHTTP(response, httptest.NewRequest(http.MethodPost, "/api/v1/rules", nil))

	if response.Code != http.StatusForbidden {
		t.Fatalf("status=%d body=%s, want 403（角色必须读装配期注入句柄，进程级句柄是主节点）", response.Code, response.Body.String())
	}
	if !strings.Contains(response.Body.String(), "从节点只读") {
		t.Fatalf("body=%s, want 含「从节点只读」", response.Body.String())
	}
}

// 守卫链上的 MFA 读取（全局开关 + 用户启用态）必须与角色读取共用装配期注入
// 的句柄：任一读取回落到进程库，嵌入/测试形态下就会拼出「按 A 库判从节点
// 403、按 B 库判已启用 428」这类自相矛盾判定，且测试绿掩盖生产形状分叉。
func TestMFAStepUpGuard_stateReadsInjectedHandle(t *testing.T) {
	oldDB, oldMetricsDB, oldAuditDB := db.DB, db.MetricsDB, db.AuditDB
	if err := db.Initialize(t.TempDir()); err != nil {
		t.Fatalf("initialize database: %v", err)
	}
	t.Cleanup(func() {
		_ = db.Close()
		restoreTestDBHandles(oldDB, oldMetricsDB, oldAuditDB)
	})
	// 进程库：守卫开启 + 用户 92 已启用 MFA——任何回落到 db.DB 的读取都会 428。
	if _, err := db.DB.Exec(`INSERT INTO users (id,username,password_hash,role,is_enabled,mfa_enabled) VALUES (92,'injected-state','x','admin',1,1)`); err != nil {
		t.Fatalf("seed mfa user: %v", err)
	}
	if _, err := db.DB.Exec(`UPDATE global_config SET mfa_write_guard=1 WHERE id=1`); err != nil {
		t.Fatalf("enable mfa write guard: %v", err)
	}

	cases := []struct {
		name string
		seed string
	}{
		{
			name: "写守卫开关按注入句柄关闭",
			seed: `CREATE TABLE global_config (id INTEGER PRIMARY KEY, is_master INTEGER, mfa_write_guard INTEGER);
				INSERT INTO global_config (id,is_master,mfa_write_guard) VALUES (1,1,0)`,
		},
		{
			name: "MFA 启用态按注入句柄为未启用",
			seed: `CREATE TABLE global_config (id INTEGER PRIMARY KEY, is_master INTEGER, mfa_write_guard INTEGER);
				INSERT INTO global_config (id,is_master,mfa_write_guard) VALUES (1,1,1);
				CREATE TABLE users (id INTEGER PRIMARY KEY, mfa_enabled INTEGER);
				INSERT INTO users (id,mfa_enabled) VALUES (92,0)`,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			injected, err := sql.Open("sqlite", t.TempDir()+"/injected-mfa-state.db")
			if err != nil {
				t.Fatalf("open injected db: %v", err)
			}
			t.Cleanup(func() { _ = injected.Close() })
			if _, err := injected.Exec(tc.seed); err != nil {
				t.Fatalf("seed injected db: %v", err)
			}

			gin.SetMode(gin.TestMode)
			router := gin.New()
			router.Use(func(c *gin.Context) {
				c.Set("auth_type", "jwt")
				c.Set("auth_method", "password")
				c.Set("user_id", 92)
				c.Set("role", "admin")
				c.Next()
			})
			router.Use(mfaStepUpGuard(injected))
			router.POST("/api/v1/rules", func(c *gin.Context) { c.Status(http.StatusNoContent) })

			response := httptest.NewRecorder()
			router.ServeHTTP(response, httptest.NewRequest(http.MethodPost, "/api/v1/rules", nil))

			if response.Code != http.StatusNoContent {
				t.Fatalf("status=%d body=%s, want 204（状态读取必须用注入句柄；回落到进程库会 428）",
					response.Code, response.Body.String())
			}
		})
	}
}
