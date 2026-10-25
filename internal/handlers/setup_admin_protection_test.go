package handlers

// break-glass 管理入口的持久标记：保护判定读 users.is_setup_admin（不再是
// 「id==1」常量），跨实例还原时按「最低 id 的启用管理员」重建标记；标记缺失
// （升级窗口/手工编辑备份）时回落到历史恒等 id。

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/pquerna/otp"
	"github.com/pquerna/otp/totp"
	"golang.org/x/crypto/bcrypt"

	"lazy-balancer-v2/internal/config"
	"lazy-balancer-v2/internal/db"
	"lazy-balancer-v2/internal/models"
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

// —— is_setup_admin 在全部 UserResponse 产出路径的一致性 ——

// userResponseSetupAdmin 按响应中的对象路径取出 is_setup_admin：键必须存在
// （字段无 omitempty，任何 UserResponse 载荷都必须下发），值必须是布尔。
func userResponseSetupAdmin(t *testing.T, body []byte, path ...string) bool {
	t.Helper()
	var root map[string]any
	if err := json.Unmarshal(body, &root); err != nil {
		t.Fatalf("解析响应体失败: %v body=%s", err, body)
	}
	var node any = root
	for _, key := range path {
		obj, ok := node.(map[string]any)
		if !ok {
			t.Fatalf("响应路径 %v 在 %q 处不是对象: %s", path, key, body)
		}
		node = obj[key]
	}
	obj, ok := node.(map[string]any)
	if !ok {
		t.Fatalf("响应路径 %v 不是对象: %s", path, body)
	}
	flag, ok := obj["is_setup_admin"].(bool)
	if !ok {
		t.Fatalf("响应缺少 is_setup_admin 布尔键（无 omitempty，必须下发真实值）: %s", body)
	}
	return flag
}

// 七条 UserResponse 产出路径必须下发真实的 is_setup_admin：该字段曾只在
// 列表查询载入，登录/MFA 两步/step-up//users/me(GET/PATCH)/PUT users/:id/
// 票据登录响应恒 false——前端与脚本据 /users/me 判定 break-glass 身份会与
// GET /users 得到相反答案，进而继续尝试删除/禁用/降级（随后 400）。
// 表驱动逐生产点断言；未标记用户的 false 对照证明该值来自列读取而非常量。
func TestSetupAdminFlag_deliveredOnEveryUserResponsePath(t *testing.T) {
	t.Run("密码登录", func(t *testing.T) {
		database := setupAuthTestDB(t)
		if _, err := database.Exec(`CREATE TABLE global_config (id INTEGER PRIMARY KEY, is_master BOOLEAN, jwt_expire_minutes INTEGER, mfa_lockout_enabled BOOLEAN); INSERT INTO global_config VALUES (1,1,20,1)`); err != nil {
			t.Fatalf("seed global config: %v", err)
		}
		hash, err := bcrypt.GenerateFromPassword([]byte("Secret123!"), bcrypt.MinCost)
		if err != nil {
			t.Fatalf("hash password: %v", err)
		}
		if _, err := database.Exec(`INSERT INTO users (username,password_hash,role,is_enabled,is_setup_admin) VALUES ('root',?,'admin',1,1)`, string(hash)); err != nil {
			t.Fatalf("seed setup admin: %v", err)
		}
		h := &Handlers{cfg: &config.Config{JWTSecret: "test-secret"}}
		router := gin.New()
		router.POST("/auth/login", h.Login)
		request := httptest.NewRequest(http.MethodPost, "/auth/login", strings.NewReader(`{"username":"root","password":"Secret123!"}`))
		request.Header.Set("Content-Type", "application/json")
		response := httptest.NewRecorder()
		router.ServeHTTP(response, request)
		if response.Code != http.StatusOK {
			t.Fatalf("login status=%d body=%s", response.Code, response.Body.String())
		}
		if !userResponseSetupAdmin(t, response.Body.Bytes(), "user") {
			t.Fatalf("登录响应 user.is_setup_admin=false，want true（body=%s）", response.Body.String())
		}
	})

	t.Run("MFA 登录第二步", func(t *testing.T) {
		secret, _ := seedMFAChallengeLoginFixture(t, "setup-admin-challenge", 0)
		if _, err := db.DB.Exec(`UPDATE users SET is_setup_admin=1 WHERE username='mfa-root'`); err != nil {
			t.Fatalf("mark setup admin: %v", err)
		}
		h := &Handlers{cfg: &config.Config{JWTSecret: "test-secret"}}
		router := gin.New()
		router.POST("/auth/mfa/verify", h.MFAVerifyLogin)
		response := postMFAVerify(t, router, "setup-admin-challenge", currentTOTPCode(t, secret))
		if response.Code != http.StatusOK {
			t.Fatalf("mfa verify status=%d body=%s", response.Code, response.Body.String())
		}
		if !userResponseSetupAdmin(t, response.Body.Bytes(), "user") {
			t.Fatalf("MFA 登录响应 user.is_setup_admin=false，want true（body=%s）", response.Body.String())
		}
	})

	t.Run("MFA step-up", func(t *testing.T) {
		h := newBackupTestHandlers(t)
		h.cfg.JWTSecret = "test-secret"
		secret := seedMfaVerifyStepUser(t)
		if _, err := db.DB.Exec(`UPDATE users SET is_setup_admin=1 WHERE id=1`); err != nil {
			t.Fatalf("mark setup admin: %v", err)
		}
		code, err := totp.GenerateCodeCustom(secret, time.Now(), totp.ValidateOpts{Period: 30, Skew: 0, Digits: otp.DigitsSix, Algorithm: otp.AlgorithmSHA1})
		if err != nil {
			t.Fatalf("generate totp: %v", err)
		}
		response := postMfaVerifyStep(mfaVerifyStepRouter(h, "jwt"), fmt.Sprintf(`{"code":%q}`, code))
		if response.Code != http.StatusOK {
			t.Fatalf("step-up status=%d body=%s", response.Code, response.Body.String())
		}
		if !userResponseSetupAdmin(t, response.Body.Bytes(), "user") {
			t.Fatalf("step-up 响应 user.is_setup_admin=false，want true（body=%s）", response.Body.String())
		}
	})

	// 余下三条上下文型端点：同一初始化管理员分别经读取/自助更新/管理员更新
	// 取回，响应必须一致；未标记用户作为 false 对照。
	for _, tc := range []struct {
		name   string
		marked bool
	}{
		{"标记用户", true},
		{"未标记用户", false},
	} {
		t.Run("GET /users/me "+tc.name, func(t *testing.T) {
			h := newBackupTestHandlers(t)
			seedUserAuditTest(t, 5, "self", "admin", true)
			if tc.marked {
				if _, err := db.DB.Exec(`UPDATE users SET is_setup_admin=1 WHERE id=5`); err != nil {
					t.Fatalf("mark setup admin: %v", err)
				}
			}
			recorder := httptest.NewRecorder()
			context, _ := gin.CreateTestContext(recorder)
			context.Set("user_id", 5)
			h.GetCurrentUser(context)
			if recorder.Code != http.StatusOK {
				t.Fatalf("status=%d body=%s", recorder.Code, recorder.Body.String())
			}
			if got := userResponseSetupAdmin(t, recorder.Body.Bytes(), "data"); got != tc.marked {
				t.Fatalf("GET /users/me is_setup_admin=%t, want %t（body=%s）", got, tc.marked, recorder.Body.String())
			}
		})

		t.Run("PATCH /users/me "+tc.name, func(t *testing.T) {
			h := newBackupTestHandlers(t)
			seedUserAuditTest(t, 5, "self", "admin", true)
			if tc.marked {
				if _, err := db.DB.Exec(`UPDATE users SET is_setup_admin=1 WHERE id=5`); err != nil {
					t.Fatalf("mark setup admin: %v", err)
				}
			}
			recorder := httptest.NewRecorder()
			context, _ := gin.CreateTestContext(recorder)
			context.Request = httptest.NewRequest(http.MethodPatch, "/users/me", strings.NewReader(`{"display_name":"新昵称"}`))
			context.Request.Header.Set("Content-Type", "application/json")
			context.Set("user_id", 5)
			context.Set("username", "self")
			context.Set("role", "admin")
			h.UpdateCurrentUser(context)
			if recorder.Code != http.StatusOK {
				t.Fatalf("status=%d body=%s", recorder.Code, recorder.Body.String())
			}
			if got := userResponseSetupAdmin(t, recorder.Body.Bytes(), "data"); got != tc.marked {
				t.Fatalf("PATCH /users/me is_setup_admin=%t, want %t（body=%s）", got, tc.marked, recorder.Body.String())
			}
		})

		t.Run("PUT /users/:id "+tc.name, func(t *testing.T) {
			h := newBackupTestHandlers(t)
			seedUserAuditTest(t, 1, "operator", "admin", true)
			seedUserAuditTest(t, 2, "target", "admin", true)
			if tc.marked {
				if _, err := db.DB.Exec(`UPDATE users SET is_setup_admin=1 WHERE id=2`); err != nil {
					t.Fatalf("mark setup admin: %v", err)
				}
			}
			response := serveUserMutation(h, http.MethodPut, "/users/2", `{"display_name":"观察员"}`, 1, h.UpdateUser)
			if response.Code != http.StatusOK {
				t.Fatalf("status=%d body=%s", response.Code, response.Body.String())
			}
			if got := userResponseSetupAdmin(t, response.Body.Bytes(), "data"); got != tc.marked {
				t.Fatalf("PUT /users/:id is_setup_admin=%t, want %t（body=%s）", got, tc.marked, response.Body.String())
			}
		})
	}

	t.Run("从节点票据登录", func(t *testing.T) {
		h := newBackupTestHandlers(t)
		h.cfg.JWTSecret = "test-secret"
		seedUserAuditTest(t, 3, "alice", "admin", true)
		if _, err := db.DB.Exec(`UPDATE users SET is_setup_admin=1 WHERE id=3`); err != nil {
			t.Fatalf("mark setup admin: %v", err)
		}
		clusterToken := "lb_cluster_setup-admin-ticket"
		key := sha256.Sum256([]byte(clusterToken))
		if _, err := db.DB.Exec(`INSERT INTO nodes (id,name,ip_address,port,status,is_approved,cluster_token_hash,last_seen) VALUES (7,'slave','10.0.0.7',8000,'online',1,?,datetime('now'))`, hex.EncodeToString(key[:])); err != nil {
			t.Fatalf("seed node: %v", err)
		}
		// 主节点签发（签发侧要求主节点角色），随后翻为从节点形态校验票据。
		response, err := h.clusterService.GenerateLoginTicket(context.Background(), models.ClusterLoginTicketClaims{UserID: 3, Username: "alice", NodeID: 7}, time.Now())
		if err != nil {
			t.Fatalf("generate login ticket: %v", err)
		}
		if _, err := db.DB.Exec(`UPDATE global_config SET is_master=0, cluster_token=?, registration_id=7 WHERE id=1`, clusterToken); err != nil {
			t.Fatalf("switch to slave: %v", err)
		}
		router := gin.New()
		router.POST("/auth/ticket-login", h.TicketLogin)
		request := httptest.NewRequest(http.MethodPost, "/auth/ticket-login", strings.NewReader(`{"ticket":"`+response.Ticket+`"}`))
		request.Header.Set("Content-Type", "application/json")
		recorder := httptest.NewRecorder()
		router.ServeHTTP(recorder, request)
		if recorder.Code != http.StatusOK {
			t.Fatalf("ticket login status=%d body=%s", recorder.Code, recorder.Body.String())
		}
		if !userResponseSetupAdmin(t, recorder.Body.Bytes(), "user") {
			t.Fatalf("票据登录响应 user.is_setup_admin=false，want true（body=%s）", recorder.Body.String())
		}
	})
}

// setupAdminProtected 的读库失败必须 fail-closed：无法判定目标是否受保护时
// 三条写路径一律 500，且目标行不得被删除/禁用/降级。此前该分支无回归网——
// 把错误分支改成「放行」或让写路径忽略 ok，全部既有测试仍绿。
func TestSetupAdminProtection_readFailureFailsClosed(t *testing.T) {
	t.Run("删除", func(t *testing.T) {
		h := newBackupTestHandlers(t)
		seedUserAuditTest(t, 1, "operator", "admin", true)
		seedUserAuditTest(t, 2, "protected", "admin", true)
		if _, err := db.DB.Exec(`UPDATE users SET is_setup_admin=1 WHERE id=2`); err != nil {
			t.Fatalf("mark setup admin: %v", err)
		}
		if _, err := db.DB.Exec(`ALTER TABLE users RENAME COLUMN is_setup_admin TO is_setup_admin_unreadable`); err != nil {
			t.Fatalf("break is_setup_admin column: %v", err)
		}
		response := serveUserMutation(h, http.MethodDelete, "/users/2", "", 1, h.DeleteUser)
		if response.Code != http.StatusInternalServerError || !strings.Contains(response.Body.String(), "读取用户保护状态失败") {
			t.Fatalf("status=%d body=%s, want 500 读取用户保护状态失败", response.Code, response.Body.String())
		}
		var exists int
		if err := db.DB.QueryRow(`SELECT COUNT(*) FROM users WHERE id=2`).Scan(&exists); err != nil {
			t.Fatalf("count target: %v", err)
		}
		if exists != 1 {
			t.Fatalf("目标用户已被删除（exists=%d）——读失败必须拒绝写", exists)
		}
	})

	t.Run("禁用", func(t *testing.T) {
		h := newBackupTestHandlers(t)
		seedUserAuditTest(t, 1, "operator", "admin", true)
		seedUserAuditTest(t, 2, "protected", "admin", true)
		if _, err := db.DB.Exec(`UPDATE users SET is_setup_admin=1 WHERE id=2`); err != nil {
			t.Fatalf("mark setup admin: %v", err)
		}
		if _, err := db.DB.Exec(`ALTER TABLE users RENAME COLUMN is_setup_admin TO is_setup_admin_unreadable`); err != nil {
			t.Fatalf("break is_setup_admin column: %v", err)
		}
		response := serveUserMutation(h, http.MethodPut, "/users/2", `{"is_enabled":false}`, 1, h.ToggleUserStatus)
		if response.Code != http.StatusInternalServerError || !strings.Contains(response.Body.String(), "读取用户保护状态失败") {
			t.Fatalf("status=%d body=%s, want 500 读取用户保护状态失败", response.Code, response.Body.String())
		}
		var enabled bool
		if err := db.DB.QueryRow(`SELECT is_enabled FROM users WHERE id=2`).Scan(&enabled); err != nil {
			t.Fatalf("read target state: %v", err)
		}
		if !enabled {
			t.Fatal("目标用户已被禁用——读失败必须拒绝写")
		}
	})

	t.Run("降级", func(t *testing.T) {
		h := newBackupTestHandlers(t)
		seedUserAuditTest(t, 1, "operator", "admin", true)
		seedUserAuditTest(t, 2, "protected", "admin", true)
		if _, err := db.DB.Exec(`UPDATE users SET is_setup_admin=1 WHERE id=2`); err != nil {
			t.Fatalf("mark setup admin: %v", err)
		}
		if _, err := db.DB.Exec(`ALTER TABLE users RENAME COLUMN is_setup_admin TO is_setup_admin_unreadable`); err != nil {
			t.Fatalf("break is_setup_admin column: %v", err)
		}
		response := serveUserMutation(h, http.MethodPut, "/users/2", `{"role":"user"}`, 1, h.UpdateUser)
		if response.Code != http.StatusInternalServerError || !strings.Contains(response.Body.String(), "读取用户保护状态失败") {
			t.Fatalf("status=%d body=%s, want 500 读取用户保护状态失败", response.Code, response.Body.String())
		}
		var role string
		if err := db.DB.QueryRow(`SELECT role FROM users WHERE id=2`).Scan(&role); err != nil {
			t.Fatalf("read target role: %v", err)
		}
		if role != "admin" {
			t.Fatalf("目标用户已被降级为 %q——读失败必须拒绝写", role)
		}
	})
}
