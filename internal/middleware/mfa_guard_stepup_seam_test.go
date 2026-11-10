package middleware

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	jwt "github.com/golang-jwt/jwt/v5"
	"github.com/pquerna/otp"
	"github.com/pquerna/otp/totp"

	"lazy-balancer-v2/internal/db"
	"lazy-balancer-v2/internal/services"
)

// step-up 接缝端到端钉：守卫验码置标记 → handler 免码消费的完整链路——
// 全程穿真实路由（jwtAuth → business 组 mfaStepUpGuard → handler），标记由
// 守卫放行路径自置，测试不自行注入 mfa_stepup_verified。
// 链路：旧 JWT（无 mfa_ts）→ verify-step 验码 → 新 JWT（新鲜 mfa_ts）→
// disable 空码体 → 守卫宽限窗置标记放行 → handler 见标记跳过本层验码 → 200。
// 无此接缝时 handler 对空码必 401。
// totpCodeAwayFromBoundary 生成 TOTP 码并避开时间片边界：距边界 ≤2s 时等到
// 下一片再生码——「片尾生成、请求跨片到达」会让验证落到下一片，造成与实现
// 无关的偶发假红。
func totpCodeAwayFromBoundary(t *testing.T, secret string) string {
	t.Helper()
	const periodSeconds = 30
	now := time.Now()
	if remaining := periodSeconds - now.Unix()%periodSeconds; remaining <= 2 {
		time.Sleep(time.Duration(remaining) * time.Second)
		now = time.Now()
	}
	code, err := totp.GenerateCodeCustom(secret, now, totp.ValidateOpts{Period: periodSeconds, Skew: 0, Digits: otp.DigitsSix, Algorithm: otp.AlgorithmSHA1})
	if err != nil {
		t.Fatalf("generate totp code: %v", err)
	}
	return code
}

func TestMFAStepUpSeam_guardMarkerFlowDisablesWithoutCode(t *testing.T) {
	router := newMiddlewareTestRouter(t)
	const jwtSecret = "test-secret" // 与 newMiddlewareTestRouterAtPort 相同

	// Given：启用 MFA 的用户（真实 TOTP 密钥）+ 守卫开启。
	res, err := db.DB.Exec("INSERT INTO users (username,password_hash,role,is_enabled,password_version) VALUES ('seam-op','x','admin',1,0)")
	if err != nil {
		t.Fatal(err)
	}
	userID, _ := res.LastInsertId()
	secret, _, err := services.MFAGenerateSecret("seam-op")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := db.DB.Exec("UPDATE users SET mfa_enabled=1, mfa_secret=? WHERE id=?", secret, userID); err != nil {
		t.Fatal(err)
	}
	if _, err := db.DB.Exec("UPDATE global_config SET mfa_write_guard=1 WHERE id=1"); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _, _ = db.DB.Exec("UPDATE global_config SET mfa_write_guard=0 WHERE id=1") })

	issueJWT := func(mfaTs int64) string {
		claims := jwt.MapClaims{
			"user_id": float64(userID), "username": "seam-op", "pwd_ver": float64(0),
			"jti": fmt.Sprintf("j%d", time.Now().UnixNano()), "exp": time.Now().Add(time.Hour).Unix(),
		}
		if mfaTs > 0 {
			claims["mfa_ts"] = float64(mfaTs)
		}
		token, err := jwt.NewWithClaims(jwt.SigningMethodHS256, claims).SignedString([]byte(jwtSecret))
		if err != nil {
			t.Fatal(err)
		}
		return token
	}
	do := func(method, path, body, token string) *httptest.ResponseRecorder {
		req := httptest.NewRequest(method, path, strings.NewReader(body))
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("Authorization", "Bearer "+token)
		rec := httptest.NewRecorder()
		router.ServeHTTP(rec, req)
		return rec
	}

	oldToken := issueJWT(0)

	// 对照：无 mfa_ts 直接 disable → 守卫 428（接缝前置条件成立）。
	if rec := do(http.MethodPost, "/api/v1/auth/mfa/disable", `{}`, oldToken); rec.Code != http.StatusPreconditionRequired {
		t.Fatalf("stale-token disable: status=%d body=%s, want 428", rec.Code, rec.Body.String())
	}

	// When①：verify-step 验码 → 新 JWT 携新鲜 mfa_ts。
	code := totpCodeAwayFromBoundary(t, secret)
	rec := do(http.MethodPost, "/api/v1/auth/mfa/verify-step", fmt.Sprintf(`{"code":%q}`, code), oldToken)
	if rec.Code != http.StatusOK {
		t.Fatalf("verify-step: status=%d body=%s, want 200", rec.Code, rec.Body.String())
	}
	var loginResp struct {
		Token string `json:"token"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &loginResp); err != nil || loginResp.Token == "" {
		t.Fatalf("verify-step response must carry token: err=%v body=%s", err, rec.Body.String())
	}

	// When②：携新 JWT 空码 disable——守卫宽限窗置标记，handler 免码消费。
	// （不经测试注入 mfa_stepup_verified；无标记时本路径恒 401。）
	rec = do(http.MethodPost, "/api/v1/auth/mfa/disable", `{}`, loginResp.Token)
	if rec.Code != http.StatusOK {
		t.Fatalf("disable with fresh step-up JWT and empty code: status=%d body=%s, want 200（守卫标记须贯通 handler）", rec.Code, rec.Body.String())
	}

	// Then：MFA 确已禁用（handler 真实执行，非守卫旁路假象）。
	var enabled int
	if err := db.DB.QueryRow("SELECT COALESCE(mfa_enabled,0) FROM users WHERE id=?", userID).Scan(&enabled); err != nil {
		t.Fatal(err)
	}
	if enabled != 0 {
		t.Fatalf("mfa_enabled=%d, want 0（disable 未真实执行）", enabled)
	}
}
