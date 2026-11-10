package handlers

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/gin-gonic/gin"

	"lazy-balancer-v2/internal/config"
	"lazy-balancer-v2/internal/db"
)

// 的 users 表由主端同步下发——同步未收敛的瞬态空表会让 GetSetupStatus 报
// needs_setup=true 并允许 SetupAdmin 建号,建号随即被同步覆盖,且与主端
// 首个管理员语义冲突。从节点:SetupAdmin 403,GetSetupStatus needs_setup=false。
// 主节点(is_master=1)与 global_config 不可读(老库形态)的行为不变(既有
// TestSetupAdmin_first_run_flow 钉住)。
func TestSetupAdmin_slaveNodeGate(t *testing.T) {
	// Given:从节点(is_master=0)+ users 空表
	setupAuthTestDB(t)
	if _, err := db.DB.Exec(`CREATE TABLE global_config (id INTEGER PRIMARY KEY, is_master BOOLEAN); INSERT INTO global_config VALUES (1,0)`); err != nil {
		t.Fatalf("create global config: %v", err)
	}
	gin.SetMode(gin.TestMode)
	h := &Handlers{cfg: &config.Config{JWTSecret: "test-secret"}}
	router := gin.New()
	router.GET("/auth/setup", h.GetSetupStatus)
	router.POST("/auth/setup", h.SetupAdmin)

	// When / Then 1:GetSetupStatus 不得引导初始化
	response := httptest.NewRecorder()
	router.ServeHTTP(response, httptest.NewRequest(http.MethodGet, "/auth/setup", nil))
	// 先断言状态码与业务码：500（角色读失败）或错误信封解码出的
	// needs_setup=false 零值同样满足「不引导初始化」，必须排除。
	if response.Code != http.StatusOK {
		t.Fatalf("setup status=%d body=%s, want 200", response.Code, response.Body.String())
	}
	var statusBody struct {
		Code int `json:"code"`
		Data struct {
			NeedsSetup bool `json:"needs_setup"`
		} `json:"data"`
	}
	if err := json.Unmarshal(response.Body.Bytes(), &statusBody); err != nil {
		t.Fatalf("decode setup status: %v body=%s", err, response.Body.String())
	}
	if statusBody.Code != 0 {
		t.Fatalf("setup status code=%d body=%s, want 0", statusBody.Code, response.Body.String())
	}
	if statusBody.Data.NeedsSetup {
		t.Fatalf("slave node must not report needs_setup, body=%s", response.Body.String())
	}

	// When / Then 2:SetupAdmin 必须 403 且不落用户
	response = httptest.NewRecorder()
	request := httptest.NewRequest(http.MethodPost, "/auth/setup", strings.NewReader(`{"username":"root","password":"Secret123!"}`))
	request.Header.Set("Content-Type", "application/json")
	router.ServeHTTP(response, request)
	if response.Code != http.StatusForbidden {
		t.Fatalf("slave setup status=%d body=%s, want 403", response.Code, response.Body.String())
	}
	var count int
	if err := db.DB.QueryRow(`SELECT COUNT(*) FROM users`).Scan(&count); err != nil || count != 0 {
		t.Fatalf("slave setup must not create user: count=%d err=%v", count, err)
	}
}

// 角色读取失败（DB 瞬断/脏行）在公开初始化端点必须 fail-closed 500——不得落回
// 「主节点语义」放行初始化建号（与 readOnlyGuard/clusterVersionMiddleware 同口径）。
func TestSetupEndpoints_failClosedOnRoleReadError(t *testing.T) {
	setupAuthTestDB(t)
	if _, err := db.DB.Exec(`CREATE TABLE global_config (id INTEGER PRIMARY KEY, is_master TEXT); INSERT INTO global_config VALUES (1,'corrupt')`); err != nil {
		t.Fatalf("create global config: %v", err)
	}
	gin.SetMode(gin.TestMode)
	h := &Handlers{cfg: &config.Config{JWTSecret: "test-secret"}}
	router := gin.New()
	router.GET("/auth/setup", h.GetSetupStatus)
	router.POST("/auth/setup", h.SetupAdmin)

	rec := httptest.NewRecorder()
	router.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/auth/setup", nil))
	if rec.Code != http.StatusInternalServerError {
		t.Fatalf("GetSetupStatus status=%d body=%s, want 500（角色读失败 fail-closed）", rec.Code, rec.Body.String())
	}

	req := httptest.NewRequest(http.MethodPost, "/auth/setup", strings.NewReader(`{"username":"root","password":"Secret123!"}`))
	req.Header.Set("Content-Type", "application/json")
	rec = httptest.NewRecorder()
	router.ServeHTTP(rec, req)
	if rec.Code != http.StatusInternalServerError {
		t.Fatalf("SetupAdmin status=%d body=%s, want 500（角色读失败 fail-closed）", rec.Code, rec.Body.String())
	}
	var count int
	if err := db.DB.QueryRow(`SELECT COUNT(*) FROM users`).Scan(&count); err != nil || count != 0 {
		t.Fatalf("角色读失败不得建号: count=%d err=%v", count, err)
	}
}

// 鉴权层与 handler 之间用户被并发删除：GET/PATCH /users/me 返回 401（与 jwtAuth
// 同文案），不得折叠为 500 诱导客户端重试。
func TestCurrentUserEndpoints_deletedUserReturns401(t *testing.T) {
	setupAuthTestDB(t)
	gin.SetMode(gin.TestMode)
	h := &Handlers{}
	router := gin.New()
	inject := func(c *gin.Context) {
		c.Set("user_id", 999) // 行不存在（模拟并发删除窗口）
		c.Set("username", "ghost")
		c.Set("auth_type", "jwt")
	}
	router.GET("/users/me", inject, h.GetCurrentUser)
	router.PATCH("/users/me", inject, h.UpdateCurrentUser)

	rec := httptest.NewRecorder()
	router.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/users/me", nil))
	if rec.Code != http.StatusUnauthorized || !strings.Contains(rec.Body.String(), "用户不存在或已禁用") {
		t.Fatalf("GET status=%d body=%s, want 401 用户不存在或已禁用", rec.Code, rec.Body.String())
	}

	req := httptest.NewRequest(http.MethodPatch, "/users/me", strings.NewReader(`{"display_name":"newname"}`))
	req.Header.Set("Content-Type", "application/json")
	rec = httptest.NewRecorder()
	router.ServeHTTP(rec, req)
	if rec.Code != http.StatusUnauthorized || !strings.Contains(rec.Body.String(), "用户不存在或已禁用") {
		t.Fatalf("PATCH status=%d body=%s, want 401 用户不存在或已禁用", rec.Code, rec.Body.String())
	}
}
