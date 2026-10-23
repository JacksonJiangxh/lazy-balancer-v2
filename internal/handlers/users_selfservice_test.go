package handlers

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/gin-gonic/gin"

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
