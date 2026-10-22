package handlers

// +:密码登录与 MFA 挑战两步的登录响应必须携带 auth_provider
// ('local'/'oidc')——前端据此隐藏本地显示名/密码编辑;SELECT 漏列使本地
// 用户得到空串,OIDC 会话的 auth_method 声明也随之丢失。

import (
	"encoding/json"
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
)

func TestLogin_responseCarriesAuthProvider(t *testing.T) {
	database := setupAuthTestDB(t)
	if _, err := database.Exec(`CREATE TABLE global_config (id INTEGER PRIMARY KEY, is_master BOOLEAN, jwt_expire_minutes INTEGER, mfa_lockout_enabled BOOLEAN); INSERT INTO global_config VALUES (1,1,20,1)`); err != nil {
		t.Fatalf("create global config: %v", err)
	}
	hash, err := bcrypt.GenerateFromPassword([]byte("Secret123!"), bcrypt.MinCost)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := database.Exec(`INSERT INTO users (username,password_hash,role,is_enabled) VALUES ('root',?,'admin',1)`, string(hash)); err != nil {
		t.Fatalf("seed user: %v", err)
	}
	h := &Handlers{cfg: &config.Config{JWTSecret: "test-secret"}}
	router := gin.New()
	router.POST("/auth/login", h.Login)

	rec := httptest.NewRecorder()
	router.ServeHTTP(rec, httptest.NewRequest(http.MethodPost, "/auth/login", strings.NewReader(`{"username":"root","password":"Secret123!"}`)))
	if rec.Code != http.StatusOK {
		t.Fatalf("login: status=%d body=%s", rec.Code, rec.Body.String())
	}
	var resp struct {
		User struct {
			AuthProvider string `json:"auth_provider"`
		} `json:"user"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatal(err)
	}
	if resp.User.AuthProvider != "local" {
		t.Fatalf("local login must carry auth_provider=local, got %q", resp.User.AuthProvider)
	}
}

func TestMFAVerifyLogin_responseCarriesAuthProvider(t *testing.T) {
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
	if _, err := database.Exec(`INSERT INTO mfa_challenges (token,user_id,expires_at,consumed) VALUES ('challenge-tok', (SELECT id FROM users WHERE username='mfa-root'), datetime('now','+5 minutes'), 0)`); err != nil {
		t.Fatalf("seed challenge: %v", err)
	}
	code, err := totp.GenerateCodeCustom(key.Secret(), time.Now(), totp.ValidateOpts{Period: 30, Skew: 0, Digits: otp.DigitsSix, Algorithm: otp.AlgorithmSHA1})
	if err != nil {
		t.Fatal(err)
	}
	h := &Handlers{cfg: &config.Config{JWTSecret: "test-secret"}}
	router := gin.New()
	router.POST("/auth/mfa/verify", h.MFAVerifyLogin)

	rec := httptest.NewRecorder()
	router.ServeHTTP(rec, httptest.NewRequest(http.MethodPost, "/auth/mfa/verify", strings.NewReader(`{"mfa_token":"challenge-tok","code":"`+code+`"}`)))
	if rec.Code != http.StatusOK {
		t.Fatalf("mfa verify: status=%d body=%s", rec.Code, rec.Body.String())
	}
	var resp struct {
		User struct {
			AuthProvider string `json:"auth_provider"`
		} `json:"user"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatal(err)
	}
	if resp.User.AuthProvider != "local" {
		t.Fatalf("mfa verify must carry auth_provider=local, got %q", resp.User.AuthProvider)
	}
}
