package handlers

// break-glass 管理入口的持久标记：保护判定读 users.is_setup_admin（不再是
// 「id==1」常量），跨实例还原时按「最低 id 的启用管理员」重建标记；标记缺失
// （升级窗口/手工编辑备份）时回落到历史恒等 id。

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/gin-gonic/gin"

	"lazy-balancer-v2/internal/config"
	"lazy-balancer-v2/internal/db"
)

func TestSetupAdminProtection_followsPersistedFlag(t *testing.T) {
	h := newBackupTestHandlers(t)
	seedUserAuditTest(t, 1, "plain-admin", "admin", true)
	seedUserAuditTest(t, 2, "setup-admin", "admin", true)
	if _, err := db.DB.Exec(`UPDATE users SET is_setup_admin=1 WHERE id=2`); err != nil {
		t.Fatalf("mark setup admin: %v", err)
	}

	cases := []struct {
		name    string
		method  string
		path    string
		body    string
		actorID int
		handler gin.HandlerFunc
		wantMsg string
	}{
		{"删除", http.MethodDelete, "/users/2", "", 1, h.DeleteUser, "初始管理员不可删除"},
		{"禁用", http.MethodPut, "/users/2", `{"is_enabled":false}`, 1, h.ToggleUserStatus, "初始管理员不可禁用"},
		{"降级", http.MethodPut, "/users/2", `{"role":"user"}`, 1, h.UpdateUser, "初始管理员不可降级"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			response := serveUserMutation(h, tc.method, tc.path, tc.body, tc.actorID, tc.handler)
			if response.Code != http.StatusBadRequest || !strings.Contains(response.Body.String(), tc.wantMsg) {
				t.Fatalf("status=%d body=%s, want 400 %s", response.Code, response.Body.String(), tc.wantMsg)
			}
		})
	}

	// 未标记的启用管理员可正常删除（保护只跟随标记，不再恒等 id=1）。
	response := serveUserMutation(h, http.MethodDelete, "/users/1", "", 2, h.DeleteUser)
	if response.Code != http.StatusOK {
		t.Fatalf("delete unmarked admin status=%d body=%s, want 200", response.Code, response.Body.String())
	}
}

func TestSetupAdminProtection_markedUserNeedNotBeLowestID(t *testing.T) {
	h := newBackupTestHandlers(t)
	seedUserAuditTest(t, 1, "admin-one", "admin", true)
	seedUserAuditTest(t, 6, "restored-admin", "admin", true)
	if _, err := db.DB.Exec(`UPDATE users SET is_setup_admin=1 WHERE id=6`); err != nil {
		t.Fatalf("mark setup admin: %v", err)
	}
	// 标记行不是最低 id 时保护跟随标记（跨实例还原后的真实形状）。
	if response := serveUserMutation(h, http.MethodDelete, "/users/6", "", 1, h.DeleteUser); response.Code != http.StatusBadRequest {
		t.Fatalf("delete marked admin status=%d body=%s, want 400", response.Code, response.Body.String())
	}
	if response := serveUserMutation(h, http.MethodDelete, "/users/1", "", 6, h.DeleteUser); response.Code != http.StatusOK {
		t.Fatalf("delete unmarked admin status=%d body=%s, want 200", response.Code, response.Body.String())
	}
}

// 旧备份（无 is_setup_admin 键）导入后按「最低 id 的启用管理员」重建标记：
// 导入前本地标记不得残留到替换后的账号集合上。
func TestImportConfigBackup_rebuildsSetupAdminFlagWhenBackupLacksIt(t *testing.T) {
	h := newBackupTestHandlers(t)
	h.cfg.DataDir = t.TempDir()
	if _, err := db.DB.Exec(`INSERT INTO users (id,username,password_hash,role,is_enabled,is_setup_admin) VALUES
		(1,'local-admin','hash','admin',1,1)`); err != nil {
		t.Fatalf("seed local admin: %v", err)
	}
	body := buildBackup(t, backupFixtureOptions{Sections: []string{"users"}, Tables: map[string][]map[string]any{
		"users": {
			{"id": 3, "username": "restored-user", "password_hash": "hash", "role": "user", "is_enabled": 1},
			{"id": 4, "username": "restored-admin", "password_hash": "hash", "role": "admin", "is_enabled": 1},
		},
	}, Config: map[string]any{}})
	router := gin.New()
	router.POST("/config/import", func(c *gin.Context) {
		c.Set("username", "local-admin")
		c.Set("user_id", 1)
		c.Set("role", "admin")
		h.ImportConfigBackup(c)
	})
	request := httptest.NewRequest(http.MethodPost, "/config/import", strings.NewReader(body))
	request.Header.Set("Content-Type", "application/json")
	response := httptest.NewRecorder()
	router.ServeHTTP(response, request)
	if response.Code != http.StatusOK {
		t.Fatalf("import status=%d body=%s, want 200", response.Code, response.Body.String())
	}
	var flagged int
	if err := db.DB.QueryRow(`SELECT id FROM users WHERE COALESCE(is_setup_admin,0)=1`).Scan(&flagged); err != nil {
		t.Fatalf("read setup admin flag: %v", err)
	}
	if flagged != 4 {
		t.Fatalf("flagged id=%d, want 4（最低 id 的启用管理员）", flagged)
	}
}

// 初始化建号必须落标记：首个管理员是 break-glass 入口，标记是保护判定的
// 唯一依据（首次启动不经过迁移回填路径）。
func TestSetupAdmin_marksCreatedUserAsSetupAdmin(t *testing.T) {
	database := setupAuthTestDB(t)
	if _, err := database.Exec(`CREATE TABLE global_config (id INTEGER PRIMARY KEY, is_master BOOLEAN, jwt_expire_minutes INTEGER, mfa_lockout_enabled BOOLEAN);
		INSERT INTO global_config VALUES (1,1,20,1)`); err != nil {
		t.Fatalf("seed global config: %v", err)
	}
	gin.SetMode(gin.TestMode)
	h := &Handlers{cfg: &config.Config{JWTSecret: "test-secret"}}
	router := gin.New()
	router.POST("/auth/setup", h.SetupAdmin)

	response := httptest.NewRecorder()
	request := httptest.NewRequest(http.MethodPost, "/auth/setup",
		strings.NewReader(`{"username":"root","password":"Secret123!","display_name":"管理员"}`))
	request.Header.Set("Content-Type", "application/json")
	router.ServeHTTP(response, request)
	if response.Code != http.StatusOK {
		t.Fatalf("setup status=%d body=%s", response.Code, response.Body.String())
	}

	var flagged int
	if err := db.DB.QueryRow(`SELECT COALESCE(is_setup_admin,0) FROM users WHERE username='root'`).Scan(&flagged); err != nil {
		t.Fatalf("read setup admin flag: %v", err)
	}
	if flagged != 1 {
		t.Fatalf("is_setup_admin=%d, want 1", flagged)
	}
}
