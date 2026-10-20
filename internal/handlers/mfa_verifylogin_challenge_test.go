package handlers

// 历史问题（历史）：MFAVerifyLogin 必须先消费挑战、后验码。
// 旧顺序（先 MFAVerifyCode 后 MFAConsumeChallenge）下「挑战已被使用」401
// 发生在验码之后——恢复码「提交即消费」，挑战作废场景（并发登录/过期窗口）
// 白烧一枚恢复码却换不到登录。新契约：
//   - 挑战已消费 → 401「MFA 挑战已被使用」且验码不执行（恢复码不减少）；
//   - 验证码错误 → 挑战不被消费（同 token 重试仍可成功）。

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"log"
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
)

// seedMFAChallengeLoginFixture 建 MFA 登录二步的最小夹具：启用 MFA 的用户 +
// 一条挑战；返回 (secret, 用户 ID)。schema 由 setupAuthTestDB →
// ensureMFATestSchema 单源提供。
func seedMFAChallengeLoginFixture(t *testing.T, challengeToken string, consumed int) (string, int64) {
	t.Helper()
	database := setupAuthTestDB(t) // 已含 MFA 列/挑战表（ensureMFATestSchema 单源）
	if _, err := database.Exec(`CREATE TABLE global_config (id INTEGER PRIMARY KEY, mfa_lockout_enabled INTEGER NOT NULL DEFAULT 0);
		INSERT INTO global_config (id) VALUES (1)`); err != nil {
		t.Fatalf("seed global config: %v", err)
	}
	key, err := totp.Generate(totp.GenerateOpts{
		Issuer: "LazyBalancer", AccountName: "mfa-user",
		Period: 30, Digits: otp.DigitsSix, Algorithm: otp.AlgorithmSHA1,
	})
	if err != nil {
		t.Fatal(err)
	}
	hash, err := bcrypt.GenerateFromPassword([]byte("Secret123!"), bcrypt.MinCost)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := database.Exec(`INSERT INTO users (username,password_hash,role,is_enabled,mfa_enabled,mfa_secret) VALUES ('mfa-root',?,'admin',1,1,?)`, string(hash), key.Secret()); err != nil {
		t.Fatalf("seed mfa user: %v", err)
	}
	if _, err := database.Exec(`INSERT INTO mfa_challenges (token,user_id,expires_at,consumed) VALUES (?, (SELECT id FROM users WHERE username='mfa-root'), datetime('now','+5 minutes'), ?)`, challengeToken, consumed); err != nil {
		t.Fatalf("seed challenge: %v", err)
	}
	var userID int64
	if err := database.QueryRow(`SELECT id FROM users WHERE username='mfa-root'`).Scan(&userID); err != nil {
		t.Fatalf("read user id: %v", err)
	}
	return key.Secret(), userID
}

func postMFAVerify(t *testing.T, router *gin.Engine, token, code string) *httptest.ResponseRecorder {
	t.Helper()
	recorder := httptest.NewRecorder()
	router.ServeHTTP(recorder, httptest.NewRequest(http.MethodPost, "/auth/mfa/verify",
		strings.NewReader(`{"mfa_token":"`+token+`","code":"`+code+`"}`)))
	return recorder
}

func currentTOTPCode(t *testing.T, secret string) string {
	t.Helper()
	code, err := totp.GenerateCodeCustom(secret, time.Now(), totp.ValidateOpts{Period: 30, Skew: 0, Digits: otp.DigitsSix, Algorithm: otp.AlgorithmSHA1})
	if err != nil {
		t.Fatal(err)
	}
	return code
}

func TestMFAVerifyLogin_consumedChallengeDoesNotBurnRecoveryCode(t *testing.T) {
	// Given：启用 MFA 的用户持两枚恢复码；挑战已被消费（并发登录胜出方/作阈值作废后重放）
	_, userID := seedMFAChallengeLoginFixture(t, "consumed-tok", 1)
	recoveryCode := "RECOVERYCODE1234" // 16 字符，走恢复码分支
	sum := sha256.Sum256([]byte(recoveryCode))
	hashes, _ := json.Marshal([]string{hex.EncodeToString(sum[:]), "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"})
	if _, err := db.DB.Exec(`UPDATE users SET mfa_recovery_codes=? WHERE id=?`, string(hashes), userID); err != nil {
		t.Fatalf("seed recovery codes: %v", err)
	}
	h := &Handlers{cfg: &config.Config{JWTSecret: "test-secret"}}
	router := gin.New()
	router.POST("/auth/mfa/verify", h.MFAVerifyLogin)

	// When：持已消费挑战 + 有效恢复码提交
	recorder := postMFAVerify(t, router, "consumed-tok", recoveryCode)

	// Then 1：401 且为「挑战已被使用」语义（消费判定是挑战状态的唯一权威）
	if recorder.Code != http.StatusUnauthorized {
		t.Fatalf("status=%d body=%s, want 401", recorder.Code, recorder.Body.String())
	}
	if !strings.Contains(recorder.Body.String(), "MFA 挑战已被使用") {
		t.Fatalf("message=%s, want 「MFA 挑战已被使用」", recorder.Body.String())
	}
	// Then 2：验码不得执行——恢复码一枚不少（修复前旧顺序先验码，恢复码被白烧）
	var raw string
	if err := db.DB.QueryRow(`SELECT COALESCE(mfa_recovery_codes,'[]') FROM users WHERE id=?`, userID).Scan(&raw); err != nil {
		t.Fatalf("read recovery codes: %v", err)
	}
	var remaining []string
	if err := json.Unmarshal([]byte(raw), &remaining); err != nil {
		t.Fatalf("decode recovery codes: %v", err)
	}
	if len(remaining) != 2 {
		t.Fatalf("恢复码被白烧：剩余 %d 枚（应 2 枚），raw=%s", len(remaining), raw)
	}
}

func TestMFAVerifyLogin_wrongCodeKeepsChallengeRetryable(t *testing.T) {
	// Given：有效挑战 + 启用 MFA 的用户
	secret, _ := seedMFAChallengeLoginFixture(t, "retry-tok", 0)
	h := &Handlers{cfg: &config.Config{JWTSecret: "test-secret"}}
	router := gin.New()
	router.POST("/auth/mfa/verify", h.MFAVerifyLogin)

	// When 1：提交错误验证码
	correct := currentTOTPCode(t, secret)
	wrong := "000000"
	if correct == wrong {
		wrong = "000001"
	}
	first := postMFAVerify(t, router, "retry-tok", wrong)
	if first.Code != http.StatusUnauthorized {
		t.Fatalf("wrong code status=%d body=%s, want 401", first.Code, first.Body.String())
	}

	// Then 1：挑战不被消费（验码失败不烧挑战）
	var consumed int
	if err := db.DB.QueryRow(`SELECT consumed FROM mfa_challenges WHERE token='retry-tok'`).Scan(&consumed); err != nil {
		t.Fatalf("read challenge: %v", err)
	}
	if consumed != 0 {
		t.Fatalf("验码失败烧掉了挑战：consumed=%d（同 token 应可重试）", consumed)
	}

	// When 2/Then 2：同 token 重试正确验证码 → 登录成功
	second := postMFAVerify(t, router, "retry-tok", correct)
	if second.Code != http.StatusOK {
		t.Fatalf("retry status=%d body=%s, want 200", second.Code, second.Body.String())
	}
}

func TestMFAVerifyLogin_resetFailureIsLoggedWithoutRevokingJWT(t *testing.T) {
	// Given 有效第二因子与旧失败计数；仅清零 login_* 两列的 UPDATE 被真实
	// SQLite 触发器拒绝，其他登录读写保持正常。
	secret, userID := seedMFAChallengeLoginFixture(t, "reset-log-tok", 0)
	if _, err := db.DB.Exec(`UPDATE users SET login_failed_attempts=4 WHERE id=?`, userID); err != nil {
		t.Fatal(err)
	}
	if _, err := db.DB.Exec(`CREATE TRIGGER fail_login_reset
		BEFORE UPDATE OF login_failed_attempts, login_locked_until ON users
		BEGIN SELECT RAISE(FAIL, 'login reset blocked'); END`); err != nil {
		t.Fatalf("create reset fault trigger: %v", err)
	}
	var logs strings.Builder
	oldWriter := log.Writer()
	log.SetOutput(&logs)
	t.Cleanup(func() { log.SetOutput(oldWriter) })
	h := &Handlers{cfg: &config.Config{JWTSecret: "test-secret"}}
	router := gin.New()
	router.POST("/auth/mfa/verify", h.MFAVerifyLogin)

	// When 第二因子登录成功，但收尾清零失败。
	response := postMFAVerify(t, router, "reset-log-tok", currentTOTPCode(t, secret))

	// Then 已验证的登录仍返回 JWT，旧计数未被静默当作清零，运行日志包含
	// 明确 warn 与底层错误，便于排障。
	if response.Code != http.StatusOK || !strings.Contains(response.Body.String(), `"token"`) {
		t.Fatalf("verified login status=%d body=%s, want 200 with token", response.Code, response.Body.String())
	}
	var attempts int
	if err := db.DB.QueryRow(`SELECT login_failed_attempts FROM users WHERE id=?`, userID).Scan(&attempts); err != nil {
		t.Fatal(err)
	}
	if attempts != 4 {
		t.Fatalf("fault injection did not preserve old attempts: got %d, want 4", attempts)
	}
	if !strings.Contains(logs.String(), "MFA 登录成功清零登录失败计数与锁定失败") || !strings.Contains(logs.String(), "login reset blocked") {
		t.Fatalf("missing reset failure warning, logs=%q", logs.String())
	}
}

// 历史修复（历史）：挑战查询的 DB 故障（非 ErrNoRows）不得与「无效
// 挑战」混同 401——基础设施错误必须显式 500，无效挑战（ErrNoRows）仍 401
// 且不泄露具体原因。
func TestMFAVerifyLogin_dbFailureReturns500Not401(t *testing.T) {
	// Given：有效夹具后破坏挑战表——查询报「no such table」而非 ErrNoRows
	seedMFAChallengeLoginFixture(t, "db-err-tok", 0)
	if _, err := db.DB.Exec(`DROP TABLE mfa_challenges`); err != nil {
		t.Fatalf("drop challenges table: %v", err)
	}
	h := &Handlers{cfg: &config.Config{JWTSecret: "test-secret"}}
	router := gin.New()
	router.POST("/auth/mfa/verify", h.MFAVerifyLogin)

	// When
	recorder := postMFAVerify(t, router, "db-err-tok", "123456")

	// Then：DB 故障=500（修复前与无效挑战混同为 401）
	if recorder.Code != http.StatusInternalServerError {
		t.Fatalf("status=%d body=%s, want 500", recorder.Code, recorder.Body.String())
	}
}

// 历史修复-历史问题：消费挑战的 DB 故障不得折叠成 401「已消费」；挑战保持未消费，
// 并留下服务故障审计，客户端可重试。
func TestMFAVerifyLogin_consumeDBFailureReturns500AndKeepsChallenge(t *testing.T) {
	seedMFAChallengeLoginFixture(t, "consume-db-err", 0)
	oldAudit := db.AuditDB
	if err := db.InitializeAuditDB(t.TempDir()); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { db.AuditDB = oldAudit })
	if _, err := db.DB.Exec(`ALTER TABLE mfa_challenges RENAME COLUMN consumed TO consumed_unreadable`); err != nil {
		t.Fatalf("break consume update: %v", err)
	}
	h := &Handlers{cfg: &config.Config{JWTSecret: "test-secret"}}
	router := gin.New()
	router.POST("/auth/mfa/verify", h.MFAVerifyLogin)

	response := postMFAVerify(t, router, "consume-db-err", "123456")
	if response.Code != http.StatusInternalServerError {
		t.Fatalf("status=%d body=%s, want 500", response.Code, response.Body.String())
	}
	var consumed int
	if err := db.DB.QueryRow(`SELECT consumed_unreadable FROM mfa_challenges WHERE token='consume-db-err'`).Scan(&consumed); err != nil {
		t.Fatal(err)
	}
	if consumed != 0 {
		t.Fatalf("challenge consumed=%d, want unchanged 0", consumed)
	}
	var events int
	if err := db.AuditDB.QueryRow(`SELECT COUNT(*) FROM audit_log WHERE action='认证拒绝' AND detail LIKE '%挑战消费服务故障%'`).Scan(&events); err != nil {
		t.Fatalf("query audit: %v", err)
	}
	if events != 1 {
		t.Fatalf("consume failure audit events=%d, want 1", events)
	}
}

// 挑战已被使用（并发登录落败/阈值作废后重放）是观测面，必须留痕，
// 与同函数其余拒绝分支同密度。
func TestMFAVerifyLogin_consumedChallengeIsAudited(t *testing.T) {
	newBackupTestHandlers(t)
	if _, err := db.DB.Exec(`INSERT INTO users (username,password_hash,role,is_enabled,mfa_enabled,mfa_secret)
		VALUES ('audit-root','x','admin',1,1,'JBSWY3DPEHPK3PXP')`); err != nil {
		t.Fatalf("seed user: %v", err)
	}
	if _, err := db.DB.Exec(`INSERT INTO mfa_challenges (token,user_id,expires_at,consumed,password_version)
		VALUES ('consumed-audit-tok',(SELECT id FROM users WHERE username='audit-root'),datetime('now','+5 minutes'),1,0)`); err != nil {
		t.Fatalf("seed consumed challenge: %v", err)
	}
	h := &Handlers{cfg: &config.Config{JWTSecret: "test-secret"}}
	router := gin.New()
	router.POST("/auth/mfa/verify", h.MFAVerifyLogin)

	recorder := postMFAVerify(t, router, "consumed-audit-tok", "000000")
	if recorder.Code != http.StatusUnauthorized {
		t.Fatalf("status=%d body=%s, want 401", recorder.Code, recorder.Body.String())
	}
	var audits int
	if err := db.AuditDB.QueryRow(`SELECT COUNT(*) FROM audit_log WHERE action='认证拒绝' AND detail LIKE '%挑战已被使用%'`).Scan(&audits); err != nil {
		t.Fatalf("count audits: %v", err)
	}
	if audits != 1 {
		t.Fatalf("audit rows=%d, want 1（「挑战已被使用」拒绝必须留痕）", audits)
	}
}
