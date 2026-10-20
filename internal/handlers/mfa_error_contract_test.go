package handlers

import (
	"context"
	"database/sql"
	"database/sql/driver"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"lazy-balancer-v2/internal/db"
	"lazy-balancer-v2/internal/services"

	"github.com/gin-gonic/gin"
)

// 管理员重置 MFA 对不存在用户必须 404「用户不存在」。
// 修复前 rejectOIDCUserMFAOperation 把身份查询的 sql.ErrNoRows 折叠成
// 500「读取用户身份失败」，下方 404 分支在常态输入下不可达。
func TestMFAResetByAdmin_missingTargetUser_returns404(t *testing.T) {
	h := newBackupTestHandlers(t)
	seedMfaResetUsers(t, false)
	setMfaWriteGuard(t, false)
	router := mfaResetRouter(h, "jwt")

	req := postMfaResetPath(router, "/users/99/mfa/reset", `{}`)

	if req.Code != http.StatusNotFound {
		t.Fatalf("status=%d body=%s, want 404（目标用户不存在应为输入错误，不是基础设施故障）", req.Code, req.Body.String())
	}
	if !strings.Contains(req.Body.String(), "用户不存在") {
		t.Fatalf("body=%s, want 包含「用户不存在」", req.Body.String())
	}
	if strings.Contains(req.Body.String(), "读取用户身份失败") {
		t.Fatalf("body=%s, 不得把不存在的用户报成身份读取失败", req.Body.String())
	}
}

// mfaActivateFailingConnector 假 db.DB：pending 读成功、激活写注入带表名/列名
// 的底层错误——用于断言 500 响应不泄露 SQL 错误文本。
type mfaActivateFailingConnector struct{ secret string }

func (c mfaActivateFailingConnector) Connect(context.Context) (driver.Conn, error) {
	return mfaActivateFailingConn{c.secret}, nil
}

func (c mfaActivateFailingConnector) Driver() driver.Driver { return mfaActivateFailingDriver{} }

type mfaActivateFailingDriver struct{}

func (mfaActivateFailingDriver) Open(string) (driver.Conn, error) { return nil, errors.New("not used") }

type mfaActivateFailingConn struct{ secret string }

func (mfaActivateFailingConn) Prepare(string) (driver.Stmt, error) {
	return nil, errors.New("unexpected prepare")
}

func (mfaActivateFailingConn) Close() error { return nil }

func (mfaActivateFailingConn) Begin() (driver.Tx, error) { return nil, errors.New("no tx") }

func (c mfaActivateFailingConn) QueryContext(_ context.Context, query string, _ []driver.NamedValue) (driver.Rows, error) {
	switch {
	case strings.Contains(query, "auth_provider"):
		return &fakeQueryRows{values: [][]driver.Value{{"local"}}}, nil
	case strings.Contains(query, "mfa_pending_secret"):
		return &fakeQueryRows{values: [][]driver.Value{{c.secret}}}, nil
	}
	return &fakeQueryRows{}, nil
}

func (c mfaActivateFailingConn) ExecContext(_ context.Context, query string, _ []driver.NamedValue) (driver.Result, error) {
	if strings.Contains(query, "mfa_enabled=1") {
		return nil, errors.New("SQLITE_ERROR: no such column: users.mfa_secret_internal")
	}
	return nil, errors.New("unexpected exec: " + query)
}

// MFA 写端点 500 必须固定文案 + 服务端留痕，不得回显底层 SQL 错误
// （与 mfaVerifyFailureResponse / Login 的三态口径一致）。
func TestMFAActivate_dbFailure_hidesUnderlyingError(t *testing.T) {
	h := newBackupTestHandlers(t)
	seedMfaSetupUser(t)
	secret := "JBSWY3DPEHPK3PXP"
	code := mfaResetCurrentCode(t, secret, time.Now())

	fake := sql.OpenDB(mfaActivateFailingConnector{secret: secret})
	t.Cleanup(func() { _ = fake.Close() })
	orig := db.DB
	db.DB = fake
	t.Cleanup(func() { db.DB = orig })

	router := gin.New()
	router.POST("/auth/mfa/activate", func(c *gin.Context) {
		c.Set("user_id", 1)
		c.Set("username", "operator")
		c.Set("auth_type", "jwt")
		h.MFAActivate(c)
	})

	rec := postRaw(router, "/auth/mfa/activate", `{"code":"`+code+`"}`)

	if rec.Code != http.StatusInternalServerError {
		t.Fatalf("status=%d body=%s, want 500", rec.Code, rec.Body.String())
	}
	if strings.Contains(rec.Body.String(), "no such column") || strings.Contains(rec.Body.String(), "SQLITE") {
		t.Fatalf("body=%s, 不得回显底层 SQL 错误文本", rec.Body.String())
	}
	if !strings.Contains(rec.Body.String(), "MFA 操作失败") {
		t.Fatalf("body=%s, want 固定文案「MFA 操作失败」", rec.Body.String())
	}
}

// 历史修复 配套：MFA 业务态错误（无 pending 密钥/并发变更）仍以 400 + 业务文案
// 返回，不被固定 500 文案吞掉。
func TestMFAInternalFailure_businessErrorsStayTyped(t *testing.T) {
	if !errors.Is(services.ErrMFANoPendingSecret, services.ErrMFANoPendingSecret) {
		t.Fatal("sentinel must be comparable")
	}
	if services.ErrMFANoPendingSecret.Error() == "" || services.ErrMFASecretChanged.Error() == "" {
		t.Fatal("sentinel errors must carry user-facing text")
	}
}

func postMfaResetPath(router *gin.Engine, path, body string) *httptest.ResponseRecorder {
	req := httptest.NewRequest(http.MethodPost, path, strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	router.ServeHTTP(rec, req)
	return rec
}
