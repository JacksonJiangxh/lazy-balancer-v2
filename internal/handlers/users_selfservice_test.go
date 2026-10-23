package handlers

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/gin-gonic/gin"
	"golang.org/x/crypto/bcrypt"

	"lazy-balancer-v2/internal/db"
)

func serveUserMutationAs(h *Handlers, method, path, body string, actorID int, role string, handler gin.HandlerFunc) *httptest.ResponseRecorder {
	response := httptest.NewRecorder()
	context, _ := gin.CreateTestContext(response)
	context.Request = httptest.NewRequest(method, path, strings.NewReader(body))
	context.Request.Header.Set("Content-Type", "application/json")
	context.Params = gin.Params{{Key: "id", Value: strings.TrimSuffix(strings.TrimPrefix(path, "/users/"), "/reset-password")}}
	context.Set("user_id", actorID)
	context.Set("role", role)
	handler(context)
	return response
}

func TestUpdateUser_selfServiceEditsDisplayNameOnly(t *testing.T) {
	h := newBackupTestHandlers(t)
	seedUserAuditTest(t, 1, "admin", "admin", true)
	seedUserAuditTest(t, 5, "self", "user", true)

	rec := serveUserMutationAs(h, http.MethodPut, "/users/5", `{"display_name":"新昵称"}`, 5, "user", h.UpdateUser)
	if rec.Code != http.StatusOK {
		t.Fatalf("status=%d body=%s", rec.Code, rec.Body.String())
	}
	var name string
	if err := db.DB.QueryRow(`SELECT COALESCE(display_name,'') FROM users WHERE id=5`).Scan(&name); err != nil {
		t.Fatal(err)
	}
	if name != "新昵称" {
		t.Fatalf("display_name=%q, want 新昵称", name)
	}
}

func TestUpdateUser_selfServiceCannotChangeRoleOrUsername(t *testing.T) {
	h := newBackupTestHandlers(t)
	seedUserAuditTest(t, 1, "admin", "admin", true)
	seedUserAuditTest(t, 5, "self", "user", true)

	for _, tc := range []struct{ name, body string }{
		{"role", `{"role":"admin"}`},
		{"username", `{"username":"renamed"}`},
	} {
		rec := serveUserMutationAs(h, http.MethodPut, "/users/5", tc.body, 5, "user", h.UpdateUser)
		if rec.Code != http.StatusForbidden {
			t.Fatalf("%s: status=%d body=%s, want 403", tc.name, rec.Code, rec.Body.String())
		}
	}
	var role, username string
	if err := db.DB.QueryRow(`SELECT role, username FROM users WHERE id=5`).Scan(&role, &username); err != nil {
		t.Fatal(err)
	}
	if role != "user" || username != "self" {
		t.Fatalf("role=%q username=%q, want user/self", role, username)
	}
}

func TestResetUserPassword_selfServiceWithoutCurrentPassword(t *testing.T) {
	h := newBackupTestHandlers(t)
	seedUserAuditTest(t, 1, "admin", "admin", true)
	seedUserAuditTest(t, 5, "self", "user", true)
	if _, err := db.DB.Exec(`INSERT INTO mfa_challenges (token,user_id,expires_at,password_version) VALUES ('tok-self',5,datetime('now','+5 minutes'),0)`); err != nil {
		t.Fatal(err)
	}
	var before int
	if err := db.DB.QueryRow(`SELECT password_version FROM users WHERE id=5`).Scan(&before); err != nil {
		t.Fatal(err)
	}

	rec := serveUserMutationAs(h, http.MethodPost, "/users/5/reset-password", `{"new_password":"Abc12345"}`, 5, "user", h.ResetUserPassword)
	if rec.Code != http.StatusOK {
		t.Fatalf("status=%d body=%s", rec.Code, rec.Body.String())
	}
	var after int
	if err := db.DB.QueryRow(`SELECT password_version FROM users WHERE id=5`).Scan(&after); err != nil {
		t.Fatal(err)
	}
	if after != before+1 {
		t.Fatalf("password_version=%d, want %d", after, before+1)
	}
	var challenges int
	if err := db.DB.QueryRow(`SELECT COUNT(*) FROM mfa_challenges WHERE user_id=5`).Scan(&challenges); err != nil {
		t.Fatal(err)
	}
	if challenges != 0 {
		t.Fatalf("mfa_challenges=%d, want 0", challenges)
	}
}

// 自助重置＝重置语义（用户裁定：维持现状，不补当前密码门）：非管理员对本人
// 调用 POST /users/:id/reset-password 只提交 new_password 即成功，且新密码真实
// 生效。该路径从不读取 current_password——与 PATCH /users/me 的当前密码确认门
// 是两套语义，改动本契约须先改裁定与 API 文档。
func TestResetUserPassword_selfServiceContractResetSemantics(t *testing.T) {
	h := newBackupTestHandlers(t)
	seedUserAuditTest(t, 1, "admin", "admin", true)
	seedUserAuditTest(t, 6, "self-reset", "user", true)

	rec := serveUserMutationAs(h, http.MethodPost, "/users/6/reset-password", `{"new_password":"Abc12345"}`, 6, "user", h.ResetUserPassword)
	if rec.Code != http.StatusOK {
		t.Fatalf("status=%d body=%s（自助重置不得要求 current_password）", rec.Code, rec.Body.String())
	}
	var hash string
	if err := db.DB.QueryRow(`SELECT password_hash FROM users WHERE id=6`).Scan(&hash); err != nil {
		t.Fatal(err)
	}
	if err := bcrypt.CompareHashAndPassword([]byte(hash), []byte("Abc12345")); err != nil {
		t.Fatalf("自助重置后新密码必须生效: %v", err)
	}
}
