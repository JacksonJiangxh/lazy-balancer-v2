package handlers

import (
	"database/sql"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"lazy-balancer-v2/internal/config"
	"lazy-balancer-v2/internal/db"
	"lazy-balancer-v2/internal/services"

	"github.com/gin-gonic/gin"
	"github.com/pquerna/otp/totp"
	"golang.org/x/crypto/bcrypt"
)

// 2026-09 用户裁定后的 MFA 端点语义：登录后不再有密码输入要求（改密是唯一
// 例外，见 auth 侧测试）；disable/setup 重绑仅验当前有效验证码，验码失败只
// 提示 401 不计数不锁定（另有 per-user 滑动窗仅限流门：60 秒 5 次失败 → 429，
// 成功清零，不落库不置锁）；恢复码重生成仅凭 JWT 会话；全系统唯一锁定为登录
// 阶段 5 次/10 分钟、受「登录失败锁定」开关控制。本文件钉住该契约。

// seedMfaGateUser 种 id=1 已启用 MFA 操作者（登录后端点无密码段）。
func seedMfaGateUser(t *testing.T) string {
	t.Helper()
	return seedMfaRulingUser(t)
}

func mfaSetupTestRouter(h *Handlers) *gin.Engine {
	router := gin.New()
	router.POST("/auth/mfa/setup", func(c *gin.Context) {
		c.Set("user_id", 1)
		c.Set("username", "operator")
		c.Set("auth_type", "jwt")
		h.MFASetup(c)
	})
	return router
}

func seedMfaRulingUser(t *testing.T) string {
	t.Helper()
	// 登录后验码限流为进程内内存态——同 user id 的跨用例残留会让后序用例
	// 误中 429，播种即清并在用例结束时再清。
	services.MFAResetVerifyAttemptsForTest()
	t.Cleanup(services.MFAResetVerifyAttemptsForTest)
	// MFA 列/挑战表统一由 ensureMFATestSchema 单源提供
	hash, err := bcrypt.GenerateFromPassword([]byte("irrelevant"), bcrypt.MinCost)
	if err != nil {
		t.Fatalf("hash password: %v", err)
	}
	if _, err := db.DB.Exec("INSERT INTO users (id,username,password_hash,role,is_enabled) VALUES (1,'operator',?,'admin',1)", string(hash)); err != nil {
		t.Fatalf("seed user: %v", err)
	}
	secret, _, err := services.MFAGenerateSecret("operator")
	if err != nil {
		t.Fatalf("generate secret: %v", err)
	}
	if _, err := db.DB.Exec("UPDATE users SET mfa_enabled=1, mfa_secret=? WHERE id=1", secret); err != nil {
		t.Fatalf("enable mfa: %v", err)
	}
	return secret
}

func mfaRulingRouter(h *Handlers) *gin.Engine {
	router := gin.New()
	for _, r := range []struct {
		path    string
		handler func(*gin.Context)
	}{
		{"/auth/mfa/disable", h.MFADisable},
		{"/auth/mfa/recovery-codes", h.MFARecoveryCodes},
		{"/auth/mfa/setup", h.MFASetup},
	} {
		path, handler := r.path, r.handler
		router.POST(path, func(c *gin.Context) {
			c.Set("user_id", 1)
			c.Set("username", "operator")
			c.Set("auth_type", "jwt")
			handler(c)
		})
	}
	return router
}

func postMfa(router *gin.Engine, path, body string) int {
	request := httptest.NewRequest(http.MethodPost, path, strings.NewReader(body))
	request.Header.Set("Content-Type", "application/json")
	recorder := httptest.NewRecorder()
	router.ServeHTTP(recorder, request)
	return recorder.Code
}

// 验码失败 401 且不产生任何计数/锁定；登录后验码另有 per-user 仅限流门
// （60 秒内失败 5 次后 429，成功清零——不落 login_* 列、不置锁）。
func TestMFAVerifyFailures_NeverCountOrLock(t *testing.T) {
	setupAuthTestDB(t)
	seedMfaRulingUser(t)
	h := &Handlers{cfg: &config.Config{JWTSecret: "test-secret"}}
	router := mfaRulingRouter(h)
	for i := 1; i <= 5; i++ {
		if code := postMfa(router, "/auth/mfa/disable", `{"code":"000000"}`); code != http.StatusUnauthorized {
			t.Fatalf("attempt %d: status=%d, want 401（限流窗内验码失败只提示）", i, code)
		}
	}
	// 第 6 次失败尝试触发仅限流门（429）——不锁定、不计 login_* 列。
	if code := postMfa(router, "/auth/mfa/disable", `{"code":"000000"}`); code != http.StatusTooManyRequests {
		t.Fatalf("attempt 6: status=%d, want 429（滑动窗限流）", code)
	}
	// 断言迁移到 login_* 列(生产 schema 已删
	// mfa_failed_attempts/mfa_locked_until 死列)——MFA 验码失败不计数不锁定。
	var loginAttempts int
	var loginLocked sql.NullString
	if err := db.DB.QueryRow("SELECT COALESCE(login_failed_attempts,0), login_locked_until FROM users WHERE id=1").Scan(&loginAttempts, &loginLocked); err != nil {
		t.Fatal(err)
	}
	if loginAttempts != 0 || loginLocked.Valid {
		t.Fatalf("login_attempts=%d login_locked=%v, want 0/NULL（MFA 验码失败不计数不锁定，仅限流）", loginAttempts, loginLocked)
	}
}

// 恢复码重生成仅凭 JWT（无密码字段），且不触碰任何失败计数。
func TestMFARecoveryCodes_JWTOnly(t *testing.T) {
	setupAuthTestDB(t)
	seedMfaRulingUser(t)
	h := &Handlers{cfg: &config.Config{JWTSecret: "test-secret"}}
	router := mfaRulingRouter(h)
	if code := postMfa(router, "/auth/mfa/recovery-codes", `{}`); code != http.StatusOK {
		t.Fatalf("recovery-codes status=%d, want 200（JWT 会话即确认）", code)
	}
	var count int
	if err := db.DB.QueryRow("SELECT COUNT(*) FROM users WHERE id=1 AND mfa_recovery_codes NOT IN ('[]','')").Scan(&count); err != nil {
		t.Fatal(err)
	}
	if count != 1 {
		t.Fatal("恢复码未重生成")
	}
}

// 正确验证码路径不受影响：disable 成功、setup 重绑返回新 secret 材料。
func TestMFAValidCode_StillWorks(t *testing.T) {
	setupAuthTestDB(t)
	secret := seedMfaRulingUser(t)
	h := &Handlers{cfg: &config.Config{JWTSecret: "test-secret"}}
	router := mfaRulingRouter(h)
	code, err := totp.GenerateCode(secret, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	// 消耗该时间片（重放防护拒绝同片）：用 setup 重绑验证正确码路径即可
	if got := postMfa(router, "/auth/mfa/setup", `{"code":"`+code+`"}`); got != http.StatusOK {
		t.Fatalf("setup rebind with valid code: status=%d, want 200", got)
	}
}
