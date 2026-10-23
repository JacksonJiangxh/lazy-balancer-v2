package handlers

import (
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"

	"github.com/gin-gonic/gin"

	"lazy-balancer-v2/internal/db"
)

// passwordPolicyMaxMessage 是策略层长度上限的友好文案（validatePasswordPolicy 单源）。
const passwordPolicyMaxMessage = "密码长度不能超过 24 位"

// 密码策略 8-24 可打印 ASCII（2026-09-28 用户裁定）：超限/非 ASCII 一律在
// 策略层以 400 + 友好文案拒绝，绝不落库（bcrypt 之前）。
//
// 真实边界分两层：24 < 长度 ≤ 72 由策略层拦（CreateUser 的绑定层上限也是 72，
// 此区间绑定层放行→策略层文案）；>72 才轮到 CreateUser 绑定层兜底（泛化
// 「请求格式错误」，任何路径都不得让 bcrypt 超长密码落库）。
func TestUserPasswordEndpoints_reject_passwords_beyond_policy(t *testing.T) {
	// 8 个汉字 = 24 字节：字节长度恰好等于上限（len 判定通过），只有 rune/ASCII
	// 校验能拒绝它——同时钉住「长度按字节」与「非 ASCII 拒绝」两条语义。
	multibyte := strings.Repeat("密", 8)
	tests := []struct {
		name        string
		password    string
		wantMessage string
	}{
		{"33 ascii (24<len<=72) rejected by policy", strings.Repeat("a", 33), passwordPolicyMaxMessage},
		{"72 ascii (binding upper bound) rejected by policy", strings.Repeat("a", 72), passwordPolicyMaxMessage},
		{"24 bytes of multibyte rejected as non-ascii", multibyte, "不允许汉字或其他非 ASCII 字符"},
	}
	endpoints := []struct {
		name   string
		method string
		path   string
		body   func(password string) string
		mount  func(*gin.Engine, *Handlers)
	}{
		{name: "create user", method: http.MethodPost, path: "/users", body: func(p string) string {
			return `{"username":"mbcreate","password":"` + p + `","role":"user"}`
		}, mount: func(r *gin.Engine, h *Handlers) { r.POST("/users", h.CreateUser) }},
		{name: "update user", method: http.MethodPut, path: "/users/1", body: func(p string) string {
			return `{"password":"` + p + `"}`
		}, mount: func(r *gin.Engine, h *Handlers) { r.PUT("/users/:id", h.UpdateUser) }},
		{name: "reset password", method: http.MethodPost, path: "/users/1/reset-password", body: func(p string) string {
			return `{"new_password":"` + p + `"}`
		}, mount: func(r *gin.Engine, h *Handlers) { r.POST("/users/:id/reset-password", h.ResetUserPassword) }},
		{name: "update current user", method: http.MethodPatch, path: "/users/me", body: func(p string) string {
			return `{"password":"` + p + `"}`
		}, mount: func(r *gin.Engine, h *Handlers) {
			r.PATCH("/users/me", func(c *gin.Context) { c.Set("user_id", 1); h.UpdateCurrentUser(c) })
		}},
		{name: "setup admin", method: http.MethodPost, path: "/auth/setup", body: func(p string) string {
			return `{"username":"mbsetup","password":"` + p + `"}`
		}, mount: func(r *gin.Engine, h *Handlers) { r.POST("/auth/setup", h.SetupAdmin) }},
	}
	for _, test := range tests {
		for _, endpoint := range endpoints {
			t.Run(test.name+"/"+endpoint.name, func(t *testing.T) {
				h := newBackupTestHandlers(t)
				if endpoint.name != "setup admin" {
					if _, err := db.DB.Exec("INSERT INTO users (id,username,password_hash,role,display_name) VALUES (1,'existing','old-hash','admin','Before')"); err != nil {
						t.Fatalf("seed user: %v", err)
					}
				}
				router := gin.New()
				endpoint.mount(router, h)
				request := httptest.NewRequest(endpoint.method, endpoint.path, strings.NewReader(endpoint.body(test.password)))
				request.Header.Set("Content-Type", "application/json")
				response := httptest.NewRecorder()

				router.ServeHTTP(response, request)

				// Then：400 + 策略层友好文案（不是绑定层泛化文案）
				if response.Code != http.StatusBadRequest {
					t.Fatalf("status=%d body=%s, want 400", response.Code, response.Body.String())
				}
				if !strings.Contains(response.Body.String(), test.wantMessage) {
					t.Fatalf("body=%s, want 策略文案「%s」", response.Body.String(), test.wantMessage)
				}
				if endpoint.name != "setup admin" {
					var passwordHash string
					if err := db.DB.QueryRow("SELECT password_hash FROM users WHERE id=1").Scan(&passwordHash); err != nil {
						t.Fatalf("read user: %v", err)
					}
					if passwordHash != "old-hash" {
						t.Fatalf("password hash=%q, want unchanged", passwordHash)
					}
				}
			})
		}
	}
}

// CreateUser 绑定层与策略层的真实边界：24 恰为上界（201）、25/72 交策略层
// 友好文案、73（>bcrypt 72）才由绑定层 max=72 兜底为泛化 400。
func TestCreateUser_passwordLengthBoundaries(t *testing.T) {
	tests := []struct {
		name        string
		length      int
		wantStatus  int
		wantMessage string
	}{
		{"24 accepted", 24, http.StatusCreated, ""},
		{"25 rejected by policy", 25, http.StatusBadRequest, passwordPolicyMaxMessage},
		{"72 rejected by policy", 72, http.StatusBadRequest, passwordPolicyMaxMessage},
		{"73 rejected by binding max=72", 73, http.StatusBadRequest, "请求格式错误"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			h := newBackupTestHandlers(t)
			router := gin.New()
			router.POST("/users", h.CreateUser)
			body := `{"username":"edge` + strconv.Itoa(test.length) + `","password":"` + strings.Repeat("a", test.length) + `","role":"user"}`
			request := httptest.NewRequest(http.MethodPost, "/users", strings.NewReader(body))
			request.Header.Set("Content-Type", "application/json")
			response := httptest.NewRecorder()

			router.ServeHTTP(response, request)

			if response.Code != test.wantStatus {
				t.Fatalf("status=%d body=%s, want %d", response.Code, response.Body.String(), test.wantStatus)
			}
			if test.wantMessage != "" && !strings.Contains(response.Body.String(), test.wantMessage) {
				t.Fatalf("body=%s, want 包含「%s」", response.Body.String(), test.wantMessage)
			}
		})
	}
}

// （收口 UpdateUser）：25 位密码的边界交 validatePasswordPolicy，
// 修复前走绑定层 max=24 泛化 400「请求格式错误」，拿不到友好文案。
func TestUpdateUser_passwordLengthRejectedByPolicyWithFriendlyMessage(t *testing.T) {
	h := newBackupTestHandlers(t)
	if _, err := db.DB.Exec("INSERT INTO users (id,username,password_hash,role,display_name) VALUES (1,'pw-len','old-hash','admin','A')"); err != nil {
		t.Fatalf("seed user: %v", err)
	}
	router := gin.New()
	adminAuthForTest(router)
	router.PUT("/users/:id", h.UpdateUser)
	request := httptest.NewRequest(http.MethodPut, "/users/1", strings.NewReader(`{"password":"`+strings.Repeat("a", 25)+`"}`))
	request.Header.Set("Content-Type", "application/json")
	response := httptest.NewRecorder()
	router.ServeHTTP(response, request)

	if response.Code != http.StatusBadRequest {
		t.Fatalf("status=%d body=%s, want 400", response.Code, response.Body.String())
	}
	if !strings.Contains(response.Body.String(), passwordPolicyMaxMessage) {
		t.Fatalf("须由密码策略校验器给出友好文案: %s", response.Body.String())
	}
	var passwordHash string
	if err := db.DB.QueryRow("SELECT password_hash FROM users WHERE id=1").Scan(&passwordHash); err != nil {
		t.Fatalf("read password hash: %v", err)
	}
	if passwordHash != "old-hash" {
		t.Fatalf("password hash=%q, want unchanged", passwordHash)
	}
}
