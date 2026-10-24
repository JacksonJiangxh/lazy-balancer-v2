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

// mfaActivateFailingConnector 假 db.DB：pending 读成功，激活写的终态由
// activateErr / rowsAffected 指定——分别用于断言 500 不泄露 SQL 错误文本
// （基础设施故障）与业务态哨兵不被固定 500 吞掉（0 行=CAS 未命中）。
type mfaActivateFailingConnector struct {
	secret       string
	activateErr  error
	rowsAffected int64
}

func (c mfaActivateFailingConnector) Connect(context.Context) (driver.Conn, error) {
	return mfaActivateFailingConn{
		secret:       c.secret,
		activateErr:  c.activateErr,
		rowsAffected: c.rowsAffected,
	}, nil
}

func (c mfaActivateFailingConnector) Driver() driver.Driver { return mfaActivateFailingDriver{} }

type mfaActivateFailingDriver struct{}

func (mfaActivateFailingDriver) Open(string) (driver.Conn, error) { return nil, errors.New("not used") }

type mfaActivateFailingConn struct {
	secret       string
	activateErr  error
	rowsAffected int64
}

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
		if c.activateErr != nil {
			return nil, c.activateErr
		}
		return driver.RowsAffected(c.rowsAffected), nil
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

	fake := sql.OpenDB(mfaActivateFailingConnector{secret: secret, activateErr: errors.New("SQLITE_ERROR: no such column: users.mfa_secret_internal")})
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

// MFA 业务态错误（并发变更：激活 CAS 未命中）必须仍是 400 + 业务文案，
// 不被固定 500 文案吞掉、也不泄露底层错误。pending 读成功且验证码有效，
// 激活 UPDATE 的 RowsAffected=0 即 ErrMFASecretChanged 的生产触发形态。
func TestMFAActivate_businessErrorStaysTyped(t *testing.T) {
	h := newBackupTestHandlers(t)
	seedMfaSetupUser(t)
	secret := "JBSWY3DPEHPK3PXP"
	code := mfaResetCurrentCode(t, secret, time.Now())

	fake := sql.OpenDB(mfaActivateFailingConnector{secret: secret}) // rowsAffected=0 → CAS 未命中
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

	if rec.Code != http.StatusBadRequest {
		t.Fatalf("status=%d body=%s, want 400（业务态错误不是基础设施故障）", rec.Code, rec.Body.String())
	}
	if !strings.Contains(rec.Body.String(), services.ErrMFASecretChanged.Error()) {
		t.Fatalf("body=%s, want 业务文案「%s」", rec.Body.String(), services.ErrMFASecretChanged.Error())
	}
	if strings.Contains(rec.Body.String(), "MFA 操作失败") {
		t.Fatalf("body=%s, 业务态错误被固定 500 文案吞掉", rec.Body.String())
	}
}

func postMfaResetPath(router *gin.Engine, path, body string) *httptest.ResponseRecorder {
	req := httptest.NewRequest(http.MethodPost, path, strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	router.ServeHTTP(rec, req)
	return rec
}

// seedNoMfaUser 种一个未启用 MFA 的用户（id=1，auth_provider=local）。
func seedNoMfaUser(t *testing.T) {
	t.Helper()
	if _, err := db.DB.Exec(`INSERT INTO users (id,username,password_hash,role,is_enabled,mfa_enabled,mfa_secret)
		VALUES (1,'nomfa','x','admin',1,0,'')`); err != nil {
		t.Fatalf("seed user: %v", err)
	}
}

func assertMFANotEnabled400(t *testing.T, rec *httptest.ResponseRecorder) {
	t.Helper()
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("status=%d body=%s, want 400（业务态未启用）", rec.Code, rec.Body.String())
	}
	if !strings.Contains(rec.Body.String(), "MFA 未启用") {
		t.Fatalf("body=%s, want 业务文案「MFA 未启用」", rec.Body.String())
	}
	if strings.Contains(rec.Body.String(), "验证码错误") {
		t.Fatalf("body=%s, 未启用不得报成验证码错误", rec.Body.String())
	}
}

// 未启用 MFA 的验码入口必须 400 业务文案：与 MFAActivate 已确立的三态口径
// （业务哨兵→400 / 真码错→401 / 基础设施故障→500）一致，既不误报验证码错误，
// 也不把业务态折叠成 500。
func TestMFAVerifyEntries_notEnabledReturns400(t *testing.T) {
	t.Run("禁用 MFA", func(t *testing.T) {
		setupAuthTestDB(t)
		seedNoMfaUser(t)
		h := &Handlers{}
		router := gin.New()
		router.POST("/auth/mfa/disable", func(c *gin.Context) {
			c.Set("user_id", 1)
			c.Set("auth_type", "jwt")
			h.MFADisable(c)
		})
		assertMFANotEnabled400(t, postMfaSelfService(router, "/auth/mfa/disable", `{"code":"123456"}`))
	})

	t.Run("verify-step", func(t *testing.T) {
		setupAuthTestDB(t)
		seedNoMfaUser(t)
		h := &Handlers{}
		assertMFANotEnabled400(t, postMfaVerifyStep(mfaVerifyStepRouter(h, "jwt"), `{"code":"123456"}`))
	})

	t.Run("登录第二步", func(t *testing.T) {
		setupAuthTestDB(t)
		seedNoMfaUser(t)
		// 登录失败锁定开关读取是验证步的前置（缺 global_config 行会被判成
		// 基础设施故障 500，与本次语义无关）。
		if _, err := db.DB.Exec(`CREATE TABLE global_config (id INTEGER PRIMARY KEY, mfa_lockout_enabled BOOLEAN);
			INSERT INTO global_config VALUES (1,0)`); err != nil {
			t.Fatalf("seed global config: %v", err)
		}
		if _, err := db.DB.Exec(`INSERT INTO mfa_challenges (token,user_id,expires_at,consumed,password_version)
			VALUES ('nomfa-tok', 1, datetime('now','+5 minutes'), 0, 0)`); err != nil {
			t.Fatalf("seed challenge: %v", err)
		}
		h := &Handlers{}
		router := gin.New()
		router.POST("/auth/mfa/verify", h.MFAVerifyLogin)
		assertMFANotEnabled400(t, postMFAVerify(t, router, "nomfa-tok", "123456"))

		// 业务态不是验证码错误：挑战必须已归还（同 token 仍可重试/重登）。
		var consumed bool
		if err := db.DB.QueryRow("SELECT COALESCE(consumed,0) FROM mfa_challenges WHERE token='nomfa-tok'").Scan(&consumed); err != nil {
			t.Fatalf("read challenge: %v", err)
		}
		if consumed {
			t.Fatal("未启用 MFA 的验码失败不得烧掉挑战")
		}
	})
}

// 自助 MFA 端点的错误分类：用户行缺失（jwtAuth 与本 handler 之间的并发删除
// 窗口）按全仓 401 约定处理，不得折叠成 500 诱导客户端重试；基础设施故障
// 500 + 固定文案 + 服务端留痕（不得零日志，也不得回显底层 SQL）。
func TestMFAStatus_errorClasses(t *testing.T) {
	h := newBackupTestHandlers(t)
	call := func(userID int) *httptest.ResponseRecorder {
		rec := httptest.NewRecorder()
		c, _ := gin.CreateTestContext(rec)
		c.Request = httptest.NewRequest(http.MethodGet, "/auth/mfa/status", nil)
		c.Set("user_id", userID)
		h.MFAStatus(c)
		return rec
	}

	if rec := call(424242); rec.Code != http.StatusUnauthorized || !strings.Contains(rec.Body.String(), "用户不存在或已禁用") {
		t.Fatalf("missing user status=%d body=%s, want 401 用户不存在或已禁用", rec.Code, rec.Body.String())
	}

	if _, err := db.DB.Exec(`DROP TABLE users`); err != nil {
		t.Fatalf("drop users: %v", err)
	}
	rec := call(1)
	if rec.Code != http.StatusInternalServerError || !strings.Contains(rec.Body.String(), "MFA 操作失败") {
		t.Fatalf("infra failure status=%d body=%s, want 500 固定文案", rec.Code, rec.Body.String())
	}
	if strings.Contains(rec.Body.String(), "no such table") {
		t.Fatalf("响应泄漏底层 SQL: %s", rec.Body.String())
	}
}
