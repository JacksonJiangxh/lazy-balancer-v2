package handlers

// 登录失败锁定的共享语义：密码步与 MFA 验证步共用同一账户级计数与同一
// 冷却窗；开关关闭时只累计不锁定，重新开启后计数立即参与判定（关闭期
// 不清零——失败计数是事实，清零等于给免费重置窗口）。

import (
	"database/sql"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/gin-gonic/gin"
	"golang.org/x/crypto/bcrypt"

	"lazy-balancer-v2/internal/config"
	"lazy-balancer-v2/internal/db"
)

func TestMFAVerifyLogin_sharesAccountLockoutWithPasswordStep(t *testing.T) {
	secret, userID := seedMFAChallengeLoginFixture(t, "lock-tok", 0)
	if _, err := db.DB.Exec(`UPDATE global_config SET mfa_lockout_enabled=1 WHERE id=1`); err != nil {
		t.Fatalf("enable lockout: %v", err)
	}
	h := &Handlers{cfg: &config.Config{JWTSecret: "test-secret"}}
	router := gin.New()
	router.POST("/auth/mfa/verify", h.MFAVerifyLogin)

	wrong := wrongTOTPCode(t, secret)
	for i := range loginLockMaxAttempts {
		rec := postMFAVerify(t, router, "lock-tok", wrong)
		if rec.Code != http.StatusUnauthorized {
			t.Fatalf("attempt %d status=%d body=%s, want 401", i+1, rec.Code, rec.Body.String())
		}
	}
	assertLockedFor(t, userID, 0)

	// 第 6 次（登录流程会重新签发挑战）直接 429，不再消耗挑战。
	if _, err := db.DB.Exec(`INSERT INTO mfa_challenges (token,user_id,expires_at,consumed)
		VALUES ('lock-tok-2', ?, datetime('now','+5 minutes'), 0)`, userID); err != nil {
		t.Fatalf("seed second challenge: %v", err)
	}
	rec := postMFAVerify(t, router, "lock-tok-2", wrong)
	if rec.Code != http.StatusTooManyRequests {
		t.Fatalf("locked attempt status=%d body=%s, want 429", rec.Code, rec.Body.String())
	}
	var consumed int
	if err := db.DB.QueryRow(`SELECT consumed FROM mfa_challenges WHERE token='lock-tok-2'`).Scan(&consumed); err != nil {
		t.Fatalf("read challenge: %v", err)
	}
	if consumed != 0 {
		t.Fatal("锁定期间不得消费挑战")
	}
}

func TestMFAVerifyLogin_lockoutSwitchOffCountsWithoutLocking(t *testing.T) {
	secret, userID := seedMFAChallengeLoginFixture(t, "nolk-tok", 0)
	// 开关默认关闭（fixture 建表为 0）。
	h := &Handlers{cfg: &config.Config{JWTSecret: "test-secret"}}
	router := gin.New()
	router.POST("/auth/mfa/verify", h.MFAVerifyLogin)

	wrong := wrongTOTPCode(t, secret)
	attempts := loginLockMaxAttempts + 1
	for i := range attempts {
		if rec := postMFAVerify(t, router, "nolk-tok", wrong); rec.Code != http.StatusUnauthorized {
			t.Fatalf("attempt %d status=%d body=%s, want 401", i+1, rec.Code, rec.Body.String())
		}
	}
	var gotAttempts int
	var locked sql.NullString
	if err := db.DB.QueryRow(`SELECT login_failed_attempts, login_locked_until FROM users WHERE id=?`, userID).
		Scan(&gotAttempts, &locked); err != nil {
		t.Fatalf("read user lockout state: %v", err)
	}
	if gotAttempts != attempts {
		t.Fatalf("attempts=%d, want %d（开关关闭只累计）", gotAttempts, attempts)
	}
	if locked.Valid {
		t.Fatalf("开关关闭时不得置锁: %q", locked.String)
	}

	// 重新开启：关闭期累计的计数不清零，一次失败即置锁。
	if _, err := db.DB.Exec(`UPDATE global_config SET mfa_lockout_enabled=1 WHERE id=1`); err != nil {
		t.Fatalf("enable lockout: %v", err)
	}
	if rec := postMFAVerify(t, router, "nolk-tok", wrong); rec.Code != http.StatusUnauthorized {
		t.Fatalf("status=%d body=%s, want 401", rec.Code, rec.Body.String())
	}
	assertLockedFor(t, userID, loginLockCooldown)
}

func TestLogin_lockCooldownMatchesConfiguredWindow(t *testing.T) {
	database := setupAuthTestDB(t)
	if _, err := database.Exec(`CREATE TABLE global_config (id INTEGER PRIMARY KEY, is_master BOOLEAN, jwt_expire_minutes INTEGER, mfa_lockout_enabled BOOLEAN);
		INSERT INTO global_config VALUES (1,1,20,1)`); err != nil {
		t.Fatalf("seed global config: %v", err)
	}
	hash, err := bcrypt.GenerateFromPassword([]byte("Secret123!"), bcrypt.MinCost)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := database.Exec(`INSERT INTO users (username,password_hash,role,is_enabled) VALUES ('root',?,'admin',1)`, string(hash)); err != nil {
		t.Fatalf("seed user: %v", err)
	}
	var userID int64
	if err := database.QueryRow(`SELECT id FROM users WHERE username='root'`).Scan(&userID); err != nil {
		t.Fatalf("read user id: %v", err)
	}
	h := &Handlers{cfg: &config.Config{JWTSecret: "test-secret"}}
	router := gin.New()
	router.POST("/auth/login", h.Login)

	for i := range loginLockMaxAttempts {
		rec := httptest.NewRecorder()
		router.ServeHTTP(rec, httptest.NewRequest(http.MethodPost, "/auth/login",
			strings.NewReader(`{"username":"root","password":"WrongPass1!"}`)))
		if rec.Code != http.StatusUnauthorized {
			t.Fatalf("attempt %d status=%d body=%s, want 401", i+1, rec.Code, rec.Body.String())
		}
	}
	assertLockedFor(t, userID, loginLockCooldown)

	// 锁定期间正确密码也 429（等时占位后拒绝）。
	rec := httptest.NewRecorder()
	router.ServeHTTP(rec, httptest.NewRequest(http.MethodPost, "/auth/login",
		strings.NewReader(`{"username":"root","password":"Secret123!"}`)))
	if rec.Code != http.StatusTooManyRequests {
		t.Fatalf("locked login status=%d body=%s, want 429", rec.Code, rec.Body.String())
	}
}

// assertLockedFor 断言用户处于锁定且剩余时间落在期望值 ±1 分钟窗口内
// （计数同时被清零——锁满后重新累计，避免延长冷却）。
func assertLockedFor(t *testing.T, userID int64, want time.Duration) {
	t.Helper()
	var attempts int
	var locked sql.NullString
	if err := db.DB.QueryRow(`SELECT login_failed_attempts, login_locked_until FROM users WHERE id=?`, userID).
		Scan(&attempts, &locked); err != nil {
		t.Fatalf("read user lockout state: %v", err)
	}
	if !locked.Valid {
		t.Fatalf("用户未置锁（attempts=%d）", attempts)
	}
	if attempts != 0 {
		t.Fatalf("attempts=%d, want 0（置锁同时清零计数）", attempts)
	}
	lockedAt, ok := parseLoginLockedUntil(locked.String)
	if !ok {
		t.Fatalf("锁定时间无法解析: %q", locked.String)
	}
	remaining := time.Until(lockedAt)
	if want == 0 {
		if remaining <= 0 {
			t.Fatalf("锁已过期: remaining=%v", remaining)
		}
		return
	}
	if remaining < want-time.Minute || remaining > want+time.Minute {
		t.Fatalf("锁剩余 %v, want ≈%v（±1 分钟）", remaining, want)
	}
}
