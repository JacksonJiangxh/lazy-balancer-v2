package handlers

// U7a-P5-1（第 67 轮审计）：MFARecoveryCodes 缺 rejectOIDCUserMFAOperation 门——
// 五个 OIDC MFA 写入口（setup/activate/disable/recovery-codes/admin reset）
// 仅此一处缺席（mfa.go:127/:186/:224/:340 有门）。OIDC 用户与本地 MFA 体系完全
// 解耦（v2.3.0 用户裁定，身份保证在 IdP 侧），恢复码重生成对 OIDC 用户必须 403。
// 测试以 mfa_enabled=1 的 OIDC 行构造「未来新路径写上」形态——无门时端点真实
// 执行重生成并 200（旧码作废+明文下发登录可用凭证），钉住纵深防御缺口。

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/gin-gonic/gin"

	"lazy-balancer-v2/internal/db"
)

// Given：auth_provider=oidc 且 mfa_enabled=1 的用户（恢复码已在库）。
// When：调用 POST /auth/mfa/recovery-codes（自助端点，JWT 会话）。
// Then：403「OIDC 用户不支持本地 MFA」——与其余四个 MFA 写入口同门。
func TestMFARecoveryCodes_rejectsOIDCUser(t *testing.T) {
	h := newBackupTestHandlers(t)
	if _, err := db.DB.Exec("INSERT INTO users (id,username,password_hash,role,is_enabled,auth_provider,oidc_subject,oidc_issuer,mfa_enabled,mfa_recovery_codes) VALUES (9,'oidcu','','user',1,'oidc','sub9','https://x',1,'[\"old-hash\"]')"); err != nil {
		t.Fatalf("seed oidc user: %v", err)
	}
	gin.SetMode(gin.TestMode)

	recorder := httptest.NewRecorder()
	ctx, _ := gin.CreateTestContext(recorder)
	req := httptest.NewRequest(http.MethodPost, "/auth/mfa/recovery-codes", strings.NewReader(`{}`))
	req.Header.Set("Content-Type", "application/json")
	ctx.Request = req
	ctx.Set("user_id", 9)
	ctx.Set("auth_type", "jwt")
	ctx.Set("auth_method", "oidc")
	h.MFARecoveryCodes(ctx)

	if recorder.Code != http.StatusForbidden || !strings.Contains(recorder.Body.String(), "不支持本地 MFA") {
		t.Fatalf("OIDC 用户重生成恢复码必须 403, got %d %s", recorder.Code, recorder.Body.String())
	}
	// 旧码不得被作废（重生成未发生）。
	var codes string
	if err := db.DB.QueryRow("SELECT COALESCE(mfa_recovery_codes,'') FROM users WHERE id=9").Scan(&codes); err != nil {
		t.Fatal(err)
	}
	if codes != `["old-hash"]` {
		t.Fatalf("OIDC 用户恢复码不得被重生成, got %q", codes)
	}
}

// 回归形状：本地用户（auth_provider 缺省 local）重生成恢复码正常 200 且旧码作废。
func TestMFARecoveryCodes_allowsLocalUser(t *testing.T) {
	h := newBackupTestHandlers(t)
	if _, err := db.DB.Exec("INSERT INTO users (id,username,password_hash,role,is_enabled,mfa_enabled,mfa_recovery_codes) VALUES (1,'localu','x','user',1,1,'[\"old-hash\"]')"); err != nil {
		t.Fatalf("seed local user: %v", err)
	}
	gin.SetMode(gin.TestMode)

	recorder := httptest.NewRecorder()
	ctx, _ := gin.CreateTestContext(recorder)
	req := httptest.NewRequest(http.MethodPost, "/auth/mfa/recovery-codes", strings.NewReader(`{}`))
	req.Header.Set("Content-Type", "application/json")
	ctx.Request = req
	ctx.Set("user_id", 1)
	ctx.Set("auth_type", "jwt")
	h.MFARecoveryCodes(ctx)

	if recorder.Code != http.StatusOK || !strings.Contains(recorder.Body.String(), "recovery_codes") {
		t.Fatalf("本地用户重生成恢复码应 200 且下发新码, got %d %s", recorder.Code, recorder.Body.String())
	}
}
