package handlers

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/gin-gonic/gin"

	"lazy-balancer-v2/internal/db"
)

// 密码策略 8-32 可打印 ASCII(2026-09-28 用户裁定)，超限密码在绑定层以 400 拒绝，
// 不能先落库再让用户以被截断的密码登录失败。
func TestUserPasswordEndpoints_reject_passwords_over_32_chars(t *testing.T) {
	longPassword := strings.Repeat("a", 33)
	tests := []struct {
		name   string
		method string
		path   string
		body   string
		mount  func(*gin.Engine, *Handlers)
	}{
		{name: "create user", method: http.MethodPost, path: "/users", body: `{"username":"long-create","password":"` + longPassword + `","role":"user"}`, mount: func(r *gin.Engine, h *Handlers) { r.POST("/users", h.CreateUser) }},
		{name: "update user", method: http.MethodPut, path: "/users/1", body: `{"password":"` + longPassword + `"}`, mount: func(r *gin.Engine, h *Handlers) { r.PUT("/users/:id", h.UpdateUser) }},
		{name: "reset password", method: http.MethodPost, path: "/users/1/password", body: `{"new_password":"` + longPassword + `"}`, mount: func(r *gin.Engine, h *Handlers) { r.POST("/users/:id/password", h.ResetUserPassword) }},
		{name: "update current user", method: http.MethodPut, path: "/me", body: `{"password":"` + longPassword + `"}`, mount: func(r *gin.Engine, h *Handlers) {
			r.PUT("/me", func(c *gin.Context) { c.Set("user_id", 1); h.UpdateCurrentUser(c) })
		}},
		{name: "setup admin", method: http.MethodPost, path: "/setup", body: `{"username":"long-setup","password":"` + longPassword + `"}`, mount: func(r *gin.Engine, h *Handlers) {
			r.POST("/setup", h.SetupAdmin)
		}},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			// Given（setup admin 依赖空用户表，其余用例需要一个已存在用户）
			h := newBackupTestHandlers(t)
			if test.name != "setup admin" {
				if _, err := db.DB.Exec("INSERT INTO users (id,username,password_hash,role,display_name) VALUES (1,'existing','old-hash','admin','Before')"); err != nil {
					t.Fatalf("seed user: %v", err)
				}
			}
			router := gin.New()
			test.mount(router, h)
			request := httptest.NewRequest(test.method, test.path, strings.NewReader(test.body))
			request.Header.Set("Content-Type", "application/json")
			response := httptest.NewRecorder()

			// When
			router.ServeHTTP(response, request)

			// Then
			if response.Code != http.StatusBadRequest {
				t.Fatalf("status=%d body=%s, want 400", response.Code, response.Body.String())
			}
			if test.name != "setup admin" {
				var passwordHash string
				if err := db.DB.QueryRow("SELECT password_hash FROM users WHERE id=1").Scan(&passwordHash); err != nil {
					t.Fatalf("read password hash: %v", err)
				}
				if passwordHash != "old-hash" {
					t.Fatalf("password hash=%q, want unchanged", passwordHash)
				}
			}
		})
	}
}
