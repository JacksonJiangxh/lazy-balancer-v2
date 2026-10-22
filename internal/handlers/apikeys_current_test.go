package handlers

import (
	"database/sql"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/gin-gonic/gin"

	"lazy-balancer-v2/internal/db"
)

func setupAPIKeyTestDB(t *testing.T) *sql.DB {
	t.Helper()
	oldDB, oldAuditDB := db.DB, db.AuditDB
	database, err := sql.Open("sqlite", t.TempDir()+"/test.db")
	if err != nil {
		t.Fatal(err)
	}
	auditDB, err := sql.Open("sqlite", t.TempDir()+"/audit.db")
	if err != nil {
		t.Fatal(err)
	}
	db.DB = database
	db.SetDB(database)
	db.AuditDB = auditDB
	t.Cleanup(func() {
		db.DB = oldDB
		db.SetDB(oldDB)
		db.AuditDB = oldAuditDB
		database.Close()
		auditDB.Close()
	})
	_, err = database.Exec(`CREATE TABLE users (
		id INTEGER PRIMARY KEY AUTOINCREMENT,
		username VARCHAR(50) UNIQUE NOT NULL,
		password_hash VARCHAR(255) NOT NULL,
		role VARCHAR(20) NOT NULL DEFAULT 'user',
		display_name VARCHAR(100),
		is_enabled BOOLEAN DEFAULT TRUE,
		last_login DATETIME
	);
	CREATE TABLE api_keys (
		id INTEGER PRIMARY KEY AUTOINCREMENT,
		name VARCHAR(100) NOT NULL,
		key_hash VARCHAR(255) NOT NULL,
		key_prefix VARCHAR(20) NOT NULL,
		created_by INTEGER NOT NULL,
		last_used DATETIME,
		expires_at DATETIME,
		is_enabled BOOLEAN DEFAULT TRUE,
		mcp_enabled INTEGER DEFAULT 0,
		read_only INTEGER DEFAULT 0,
		mcp_ip_whitelist TEXT DEFAULT '',
		created_at DATETIME DEFAULT CURRENT_TIMESTAMP
	);
	INSERT INTO users (id, username, password_hash, role) VALUES (1, 'alice', 'x', 'user'), (2, 'bob', 'x', 'user');
	INSERT INTO api_keys (id, name, key_hash, key_prefix, created_by, is_enabled) VALUES (10, 'alice-key', 'h1', 'prefix1', 1, 1), (20, 'bob-key', 'h2', 'prefix2', 2, 1);`)
	if err != nil {
		t.Fatal(err)
	}
	// 密码确认门已于 2026-09 裁定删除——
	// 特权 Key(非只读或 MCP)创建不验密码,可选防线为 mfa_write_guard 的
	// MFA step-up(428,见 apikeys.go createAPIKeyForUser);本文件用例未开
	// guard,不再种子真实密码哈希、不再携带 password 载荷。
	return database
}

func TestListCurrentUserAPIKeysOnlyOwn(t *testing.T) {
	setupAPIKeyTestDB(t)
	gin.SetMode(gin.TestMode)
	recorder := httptest.NewRecorder()
	ctx, _ := gin.CreateTestContext(recorder)
	ctx.Request = httptest.NewRequest(http.MethodGet, "/api/v1/users/me/api-keys", nil)
	ctx.Set("user_id", 1)

	h := &Handlers{}
	h.ListCurrentUserAPIKeys(ctx)

	if recorder.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", recorder.Code)
	}
	var body struct {
		Data []struct {
			ID       int    `json:"id"`
			Name     string `json:"name"`
			Username string `json:"username"`
		} `json:"data"`
	}
	if err := json.Unmarshal(recorder.Body.Bytes(), &body); err != nil {
		t.Fatal(err)
	}
	if len(body.Data) != 1 || body.Data[0].ID != 10 || body.Data[0].Username != "alice" {
		t.Fatalf("unexpected keys: %#v", body.Data)
	}
}

func TestListAPIKeysIncludesUsernameOwnership(t *testing.T) {
	setupAPIKeyTestDB(t)
	recorder := httptest.NewRecorder()
	ctx, _ := gin.CreateTestContext(recorder)
	ctx.Request = httptest.NewRequest(http.MethodGet, "/api/v1/api-keys", nil)

	(&Handlers{}).ListAPIKeys(ctx)

	if recorder.Code != http.StatusOK {
		t.Fatalf("status=%d body=%s", recorder.Code, recorder.Body.String())
	}
	var body struct {
		Data []struct {
			ID       int    `json:"id"`
			Username string `json:"username"`
		} `json:"data"`
	}
	if err := json.Unmarshal(recorder.Body.Bytes(), &body); err != nil {
		t.Fatal(err)
	}
	if len(body.Data) != 2 || body.Data[0].ID != 10 || body.Data[0].Username != "alice" || body.Data[1].ID != 20 || body.Data[1].Username != "bob" {
		t.Fatalf("unexpected key ownership: %#v", body.Data)
	}
}

func TestListCurrentUserAPIKeys_serializes_nullable_times_as_strings_or_null(t *testing.T) {
	// Given
	database := setupAPIKeyTestDB(t)
	if _, err := database.Exec("UPDATE api_keys SET last_used=?, expires_at=? WHERE id=10", time.Date(2026, time.July, 30, 1, 2, 3, 0, time.UTC), nil); err != nil {
		t.Fatalf("seed API key times: %v", err)
	}
	recorder := httptest.NewRecorder()
	ctx, _ := gin.CreateTestContext(recorder)
	ctx.Request = httptest.NewRequest(http.MethodGet, "/api/v1/users/me/api-keys", nil)
	ctx.Set("user_id", 1)

	// When
	(&Handlers{}).ListCurrentUserAPIKeys(ctx)

	// Then
	if recorder.Code != http.StatusOK {
		t.Fatalf("status=%d body=%s", recorder.Code, recorder.Body.String())
	}
	body := recorder.Body.String()
	if !strings.Contains(body, `"last_used":"2026-07-30T01:02:03Z"`) || !strings.Contains(body, `"expires_at":null`) {
		t.Fatalf("unexpected nullable time JSON: %s", body)
	}
	if strings.Contains(body, `"Time"`) || strings.Contains(body, `"Valid"`) {
		t.Fatalf("response leaked sql.NullTime representation: %s", body)
	}
}

func TestListAPIKeys_serializes_nullable_times_as_strings_or_null(t *testing.T) {
	// Given
	database := setupAPIKeyTestDB(t)
	if _, err := database.Exec("UPDATE api_keys SET expires_at=? WHERE id=20", time.Date(2026, time.August, 1, 2, 3, 4, 0, time.UTC)); err != nil {
		t.Fatalf("seed API key expiry: %v", err)
	}
	recorder := httptest.NewRecorder()
	ctx, _ := gin.CreateTestContext(recorder)
	ctx.Request = httptest.NewRequest(http.MethodGet, "/api/v1/api-keys", nil)

	// When
	(&Handlers{}).ListAPIKeys(ctx)

	// Then
	if recorder.Code != http.StatusOK {
		t.Fatalf("status=%d body=%s", recorder.Code, recorder.Body.String())
	}
	body := recorder.Body.String()
	if !strings.Contains(body, `"expires_at":"2026-08-01T02:03:04Z"`) || !strings.Contains(body, `"last_used":null`) {
		t.Fatalf("unexpected nullable time JSON: %s", body)
	}
	if strings.Contains(body, `"Time"`) || strings.Contains(body, `"Valid"`) {
		t.Fatalf("response leaked sql.NullTime representation: %s", body)
	}
}

func TestDeleteCurrentUserAPIKeyRejectsOtherUsersKey(t *testing.T) {
	setupAPIKeyTestDB(t)
	gin.SetMode(gin.TestMode)
	recorder := httptest.NewRecorder()
	ctx, _ := gin.CreateTestContext(recorder)
	ctx.Request = httptest.NewRequest(http.MethodDelete, "/api/v1/users/me/api-keys/20", nil)
	ctx.Params = gin.Params{{Key: "id", Value: "20"}}
	ctx.Set("user_id", 1)

	h := &Handlers{}
	h.DeleteCurrentUserAPIKey(ctx)

	if recorder.Code != http.StatusNotFound {
		t.Fatalf("status = %d, want 404", recorder.Code)
	}
}

func TestDeleteCurrentUserAPIKey_returns_not_found_when_row_disappears_before_delete(t *testing.T) {
	// Given
	database := setupAPIKeyTestDB(t)
	if _, err := database.Exec(`CREATE TRIGGER delete_key_before_outer_delete BEFORE DELETE ON api_keys
		WHEN OLD.id=10 BEGIN DELETE FROM api_keys WHERE id=OLD.id; SELECT RAISE(IGNORE); END`); err != nil {
		t.Fatalf("create delete race trigger: %v", err)
	}
	recorder := httptest.NewRecorder()
	ctx, _ := gin.CreateTestContext(recorder)
	ctx.Request = httptest.NewRequest(http.MethodDelete, "/api/v1/users/me/api-keys/10", nil)
	ctx.Params = gin.Params{{Key: "id", Value: "10"}}
	ctx.Set("user_id", 1)

	// When
	(&Handlers{}).DeleteCurrentUserAPIKey(ctx)

	// Then
	if recorder.Code != http.StatusNotFound {
		t.Fatalf("status=%d body=%s, want 404", recorder.Code, recorder.Body.String())
	}
}

func TestUpdateAPIKeyStatus_returns_not_found_when_row_disappears_before_update(t *testing.T) {
	// Given
	database := setupAPIKeyTestDB(t)
	if _, err := database.Exec(`CREATE TRIGGER delete_key_before_status_update BEFORE UPDATE ON api_keys
		WHEN OLD.id=10 BEGIN DELETE FROM api_keys WHERE id=OLD.id; SELECT RAISE(IGNORE); END`); err != nil {
		t.Fatalf("create update race trigger: %v", err)
	}
	recorder := httptest.NewRecorder()
	ctx, _ := gin.CreateTestContext(recorder)
	ctx.Request = httptest.NewRequest(http.MethodPatch, "/api/v1/api-keys/10/status", strings.NewReader(`{"is_enabled":false}`))
	ctx.Request.Header.Set("Content-Type", "application/json")
	ctx.Params = gin.Params{{Key: "id", Value: "10"}}

	// When
	(&Handlers{}).UpdateAPIKeyStatus(ctx)

	// Then
	if recorder.Code != http.StatusNotFound {
		t.Fatalf("status=%d body=%s, want 404", recorder.Code, recorder.Body.String())
	}
}

func TestCreateCurrentUserAPIKeyReturnsPlaintextOnce(t *testing.T) {
	database := setupAPIKeyTestDB(t)
	gin.SetMode(gin.TestMode)
	recorder := httptest.NewRecorder()
	ctx, _ := gin.CreateTestContext(recorder)
	ctx.Request = httptest.NewRequest(http.MethodPost, "/api/v1/users/me/api-keys", strings.NewReader(`{"name":"ci"}`))
	ctx.Request.Header.Set("Content-Type", "application/json")
	ctx.Set("user_id", 1)
	ctx.Set("role", "user")

	h := &Handlers{}
	h.CreateCurrentUserAPIKey(ctx)

	if recorder.Code != http.StatusCreated {
		t.Fatalf("status = %d, want 201", recorder.Code)
	}
	var body struct {
		Data struct {
			Key string `json:"key"`
		} `json:"data"`
	}
	if err := json.Unmarshal(recorder.Body.Bytes(), &body); err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(body.Data.Key, "lb_sk_") {
		t.Fatalf("key prefix invalid: %q", body.Data.Key)
	}
	var readOnly bool
	if err := database.QueryRow("SELECT read_only FROM api_keys WHERE name='ci'").Scan(&readOnly); err != nil {
		t.Fatal(err)
	}
	if !readOnly {
		t.Fatal("non-admin API key was not forced to read-only")
	}
}

// API Key 名称 TrimSpace 后非空且 ≤100 字符——空白名/超长名
// 此前直接落库(api_keys.name VARCHAR(100) 在 SQLite 不强制长度),列表与审计
// 出现不可读名。重名不拒绝(既有产品决策保持)。
func TestCreateCurrentUserAPIKey_validatesName(t *testing.T) {
	database := setupAPIKeyTestDB(t)
	gin.SetMode(gin.TestMode)
	create := func(body string) *httptest.ResponseRecorder {
		recorder := httptest.NewRecorder()
		ctx, _ := gin.CreateTestContext(recorder)
		ctx.Request = httptest.NewRequest(http.MethodPost, "/api/v1/users/me/api-keys", strings.NewReader(body))
		ctx.Request.Header.Set("Content-Type", "application/json")
		ctx.Set("user_id", 1)
		ctx.Set("role", "user")
		(&Handlers{}).CreateCurrentUserAPIKey(ctx)
		return recorder
	}

	// When/Then:空白名与 101 字符名 → 400
	for _, tc := range []struct{ label, body string }{
		{"whitespace", `{"name":"   "}`},
		{"overlong", `{"name":"` + strings.Repeat("密", 101) + `"}`},
	} {
		if recorder := create(tc.body); recorder.Code != http.StatusBadRequest {
			t.Fatalf("%s: status=%d body=%s, want 400", tc.label, recorder.Code, recorder.Body.String())
		}
	}
	// 边界:100 字符接受;首尾空白名修剪后落库
	if recorder := create(`{"name":"` + strings.Repeat("密", 100) + `"}`); recorder.Code != http.StatusCreated {
		t.Fatalf("100 字符名: status=%d body=%s, want 201", recorder.Code, recorder.Body.String())
	}
	if recorder := create(`{"name":"  padded  "}`); recorder.Code != http.StatusCreated {
		t.Fatalf("修剪后非空名: status=%d body=%s, want 201", recorder.Code, recorder.Body.String())
	}
	var stored string
	if err := database.QueryRow("SELECT name FROM api_keys WHERE name IN ('padded','  padded  ')").Scan(&stored); err != nil {
		t.Fatal(err)
	}
	if stored != "padded" {
		t.Fatalf("stored name=%q, want 修剪后的 padded", stored)
	}
}

func TestUpdateCurrentUserAPIKeyRejectsDisablingReadOnly(t *testing.T) {
	setupAPIKeyTestDB(t)
	recorder := httptest.NewRecorder()
	ctx, _ := gin.CreateTestContext(recorder)
	ctx.Request = httptest.NewRequest(http.MethodPatch, "/api/v1/users/me/api-keys/10", strings.NewReader(`{"read_only":false}`))
	ctx.Request.Header.Set("Content-Type", "application/json")
	ctx.Params = gin.Params{{Key: "id", Value: "10"}}
	ctx.Set("user_id", 1)
	ctx.Set("role", "user")

	(&Handlers{}).UpdateCurrentUserAPIKeyStatus(ctx)

	if recorder.Code != http.StatusBadRequest || !strings.Contains(recorder.Body.String(), "普通用户密钥必须为只读") {
		t.Fatalf("status=%d body=%s", recorder.Code, recorder.Body.String())
	}
}

func TestUpdateCurrentUserAPIKeyForcesLegacyKeyReadOnly(t *testing.T) {
	database := setupAPIKeyTestDB(t)
	recorder := httptest.NewRecorder()
	ctx, _ := gin.CreateTestContext(recorder)
	ctx.Request = httptest.NewRequest(http.MethodPatch, "/api/v1/users/me/api-keys/10", strings.NewReader(`{"mcp_enabled":true}`))
	ctx.Request.Header.Set("Content-Type", "application/json")
	ctx.Params = gin.Params{{Key: "id", Value: "10"}}
	ctx.Set("user_id", 1)
	ctx.Set("role", "user")

	(&Handlers{}).UpdateCurrentUserAPIKeyStatus(ctx)

	if recorder.Code != http.StatusOK {
		t.Fatalf("status=%d body=%s", recorder.Code, recorder.Body.String())
	}
	var readOnly bool
	if err := database.QueryRow("SELECT read_only FROM api_keys WHERE id=10").Scan(&readOnly); err != nil {
		t.Fatal(err)
	}
	if !readOnly {
		t.Fatal("legacy non-admin API key remained writable")
	}
}

func TestAdminAPIKeyReadOnlySettingIsUnchanged(t *testing.T) {
	database := setupAPIKeyTestDB(t)
	// 特权 Key(可写)创建现行语义=mfa_write_guard 的 MFA step-up
	//(428),无密码确认门;本用例未开 guard,直接创建。
	recorder := httptest.NewRecorder()
	ctx, _ := gin.CreateTestContext(recorder)
	ctx.Request = httptest.NewRequest(http.MethodPost, "/api/v1/api-keys", strings.NewReader(`{"name":"admin-write","read_only":false}`))
	ctx.Request.Header.Set("Content-Type", "application/json")
	ctx.Set("user_id", 1)
	ctx.Set("role", "admin")

	(&Handlers{}).CreateCurrentUserAPIKey(ctx)

	if recorder.Code != http.StatusCreated {
		t.Fatalf("status=%d body=%s", recorder.Code, recorder.Body.String())
	}
	var readOnly bool
	if err := database.QueryRow("SELECT read_only FROM api_keys WHERE name='admin-write'").Scan(&readOnly); err != nil {
		t.Fatal(err)
	}
	if readOnly {
		t.Fatal("admin API key read_only=false was overridden")
	}
}

func TestAdminCanDisableReadOnlyOnOwnAPIKey(t *testing.T) {
	database := setupAPIKeyTestDB(t)
	if _, err := database.Exec("UPDATE api_keys SET read_only=1 WHERE id=10"); err != nil {
		t.Fatal(err)
	}
	recorder := httptest.NewRecorder()
	ctx, _ := gin.CreateTestContext(recorder)
	ctx.Request = httptest.NewRequest(http.MethodPatch, "/api/v1/users/me/api-keys/10", strings.NewReader(`{"read_only":false}`))
	ctx.Request.Header.Set("Content-Type", "application/json")
	ctx.Params = gin.Params{{Key: "id", Value: "10"}}
	ctx.Set("user_id", 1)
	ctx.Set("role", "admin")

	(&Handlers{}).UpdateCurrentUserAPIKeyStatus(ctx)

	if recorder.Code != http.StatusOK {
		t.Fatalf("status=%d body=%s", recorder.Code, recorder.Body.String())
	}
	var readOnly bool
	if err := database.QueryRow("SELECT read_only FROM api_keys WHERE id=10").Scan(&readOnly); err != nil {
		t.Fatal(err)
	}
	if readOnly {
		t.Fatal("admin could not disable read_only on own API key")
	}
}

func TestCreateCurrentUserAPIKeyNormalizesMCPWhitelist(t *testing.T) {
	database := setupAPIKeyTestDB(t)
	recorder := httptest.NewRecorder()
	ctx, _ := gin.CreateTestContext(recorder)
	// mcp_enabled Key 属特权 Key——现行确认门为 mfa_write_guard
	// 的 MFA step-up(428),密码载荷已随裁定删除。
	ctx.Request = httptest.NewRequest(http.MethodPost, "/api/v1/users/me/api-keys", strings.NewReader(`{"name":"mcp","mcp_enabled":true,"read_only":true,"mcp_ip_whitelist":["192.168.1.5","2001:db8::1"]}`))
	ctx.Request.Header.Set("Content-Type", "application/json")
	ctx.Set("user_id", 1)

	(&Handlers{}).CreateCurrentUserAPIKey(ctx)

	if recorder.Code != http.StatusCreated {
		t.Fatalf("status=%d body=%s", recorder.Code, recorder.Body.String())
	}
	var mcpEnabled, readOnly bool
	var whitelist string
	if err := database.QueryRow("SELECT mcp_enabled,read_only,mcp_ip_whitelist FROM api_keys WHERE name='mcp'").Scan(&mcpEnabled, &readOnly, &whitelist); err != nil {
		t.Fatal(err)
	}
	if !mcpEnabled || !readOnly || whitelist != `["192.168.1.5/32","2001:db8::1/128"]` {
		t.Fatalf("mcp_enabled=%v read_only=%v whitelist=%q", mcpEnabled, readOnly, whitelist)
	}
}

func TestUpdateAPIKeyRejectsInvalidMCPWhitelist(t *testing.T) {
	setupAPIKeyTestDB(t)
	recorder := httptest.NewRecorder()
	ctx, _ := gin.CreateTestContext(recorder)
	ctx.Request = httptest.NewRequest(http.MethodPatch, "/api/v1/api-keys/10/status", strings.NewReader(`{"mcp_ip_whitelist":["invalid"]}`))
	ctx.Request.Header.Set("Content-Type", "application/json")
	ctx.Params = gin.Params{{Key: "id", Value: "10"}}

	(&Handlers{}).UpdateAPIKeyStatus(ctx)

	if recorder.Code != http.StatusBadRequest || !strings.Contains(recorder.Body.String(), "MCP IP 白名单无效") {
		t.Fatalf("status=%d body=%s", recorder.Code, recorder.Body.String())
	}
}

// 每用户 50 配额的判定与插入必须原子——并发创建
// 此前 count-then-insert TOCTOU 可越过上限。本测试用生产 DSN（db.Initialize：
// WAL+busy_timeout+_txlock=immediate）并发轰 55 个创建，总数不得超 50。
// 注：setupAPIKeyTestDB 的裸 sql.Open 无 busy_timeout，并发下会以 SQLITE_BUSY
// 500 污染断言，故此处独立搭生产形态环境。
func TestCreateAPIKey_quotaAtomicUnderConcurrency(t *testing.T) {
	// db.Initialize 会替换三个全局句柄，恢复必须
	// 三者齐全——此前漏 MetricsDB，后续用例会踩已关闭的临时指标库。
	oldDB, oldMetricsDB, oldAuditDB := db.DB, db.MetricsDB, db.AuditDB
	if err := db.Initialize(t.TempDir()); err != nil {
		t.Fatalf("initialize: %v", err)
	}
	t.Cleanup(func() {
		_ = db.Close()
		db.DB, db.MetricsDB, db.AuditDB = oldDB, oldMetricsDB, oldAuditDB
		db.SetDB(oldDB)
	})
	gin.SetMode(gin.TestMode)

	const attempts = 55
	start := make(chan struct{})
	codes := make([]int, attempts)
	var wg sync.WaitGroup
	for i := 0; i < attempts; i++ {
		wg.Add(1)
		go func(slot int) {
			defer wg.Done()
			<-start
			rec := httptest.NewRecorder()
			ctx, _ := gin.CreateTestContext(rec)
			ctx.Request = httptest.NewRequest(http.MethodPost, "/api/v1/users/me/api-keys", strings.NewReader(`{"name":"quota-key"}`))
			ctx.Request.Header.Set("Content-Type", "application/json")
			ctx.Set("user_id", 1)
			ctx.Set("role", "user")
			ctx.Set("auth_type", "jwt")
			createAPIKeyForUser(ctx, 1)
			codes[slot] = rec.Code
		}(i)
	}
	close(start)
	wg.Wait()

	var owned int
	if err := db.DB.QueryRow("SELECT COUNT(*) FROM api_keys WHERE created_by=1").Scan(&owned); err != nil {
		t.Fatal(err)
	}
	if owned > apiKeyMaxPerUser {
		t.Fatalf("created %d keys for user 1, must never exceed %d（配额判定与插入须原子）", owned, apiKeyMaxPerUser)
	}
	created := 0
	for _, c := range codes {
		if c == http.StatusCreated {
			created++
		}
	}
	if created != apiKeyMaxPerUser {
		t.Fatalf("created=%d, want exactly %d（限额满后其余必须 400 拒绝）", created, apiKeyMaxPerUser)
	}
}

// 创建审计必须区分特权授予——此前只记 id/name/过期，
// 「可写 + MCP 开 + 白名单」的 Key 与只读 Key 审计文案完全相同。字段级
// detail 不得落完整密钥。
func TestCreateAPIKey_auditDetailRecordsPrivilegeFields(t *testing.T) {
	setupAPIKeyTestDB(t)
	if err := db.InitializeAuditDB(t.TempDir()); err != nil {
		t.Fatalf("initialize audit db: %v", err)
	}
	gin.SetMode(gin.TestMode)
	recorder := httptest.NewRecorder()
	ctx, _ := gin.CreateTestContext(recorder)
	ctx.Request = httptest.NewRequest(http.MethodPost, "/api/v1/users/me/api-keys",
		strings.NewReader(`{"name":"privileged","read_only":false,"mcp_enabled":true,"mcp_ip_whitelist":["127.0.0.1","10.0.0.0/8"]}`))
	ctx.Request.Header.Set("Content-Type", "application/json")
	ctx.Set("user_id", 1)
	ctx.Set("role", "admin")
	(&Handlers{}).CreateCurrentUserAPIKey(ctx)
	if recorder.Code != http.StatusCreated {
		t.Fatalf("status=%d body=%s, want 201", recorder.Code, recorder.Body.String())
	}
	var body struct {
		Data struct {
			Key string `json:"key"`
		} `json:"data"`
	}
	if err := json.Unmarshal(recorder.Body.Bytes(), &body); err != nil {
		t.Fatal(err)
	}
	var detail string
	if err := db.AuditDB.QueryRow(`SELECT detail FROM audit_log WHERE action='创建' AND resource='API密钥' ORDER BY id DESC LIMIT 1`).Scan(&detail); err != nil {
		t.Fatalf("read audit detail: %v", err)
	}
	for _, want := range []string{"权限：可写", "MCP：开", "MCP 白名单：2 条"} {
		if !strings.Contains(detail, want) {
			t.Fatalf("audit detail=%q, want 含 %q", detail, want)
		}
	}
	if body.Data.Key != "" && strings.Contains(detail, body.Data.Key) {
		t.Fatalf("audit detail 不得落完整密钥: %q", detail)
	}
}

// 更新审计必须留痕安全相关变更（启用态/MCP/只读/白名单），
// 此前只有「密钥 id name」，禁用与放宽权限在审计中不可回溯。
func TestUpdateAPIKey_auditDetailRecordsSecurityDelta(t *testing.T) {
	setupAPIKeyTestDB(t)
	if err := db.InitializeAuditDB(t.TempDir()); err != nil {
		t.Fatalf("initialize audit db: %v", err)
	}
	recorder := httptest.NewRecorder()
	ctx, _ := gin.CreateTestContext(recorder)
	ctx.Request = httptest.NewRequest(http.MethodPatch, "/api/v1/users/me/api-keys/10",
		strings.NewReader(`{"is_enabled":false,"mcp_enabled":true,"read_only":true,"mcp_ip_whitelist":["192.0.2.0/24"]}`))
	ctx.Request.Header.Set("Content-Type", "application/json")
	ctx.Params = gin.Params{{Key: "id", Value: "10"}}
	ctx.Set("user_id", 1)
	ctx.Set("role", "admin")
	(&Handlers{}).UpdateCurrentUserAPIKeyStatus(ctx)
	if recorder.Code != http.StatusOK {
		t.Fatalf("status=%d body=%s, want 200", recorder.Code, recorder.Body.String())
	}
	var detail string
	if err := db.AuditDB.QueryRow(`SELECT detail FROM audit_log WHERE action='更新' AND resource='API密钥' ORDER BY id DESC LIMIT 1`).Scan(&detail); err != nil {
		t.Fatalf("read audit detail: %v", err)
	}
	for _, want := range []string{"启用状态：开→关", "MCP：关→开", "只读：关→开", "MCP 白名单：0 条→1 条"} {
		if !strings.Contains(detail, want) {
			t.Fatalf("audit detail=%q, want 含 %q", detail, want)
		}
	}
}

// 创建路径与删除路径同形守卫：认证上下文缺失（user_id 缺/类型未知 → 0）时
// 必须 401——不得写入 created_by=0 的孤儿 Key（配额按 0 计数且列表 JOIN
// users 隐藏它，不可见但可用）。
func TestCreateAPIKey_missingUserContextRejected(t *testing.T) {
	setupAPIKeyTestDB(t)
	recorder := httptest.NewRecorder()
	ctx, _ := gin.CreateTestContext(recorder)
	ctx.Request = httptest.NewRequest(http.MethodPost, "/api/v1/users/me/api-keys", strings.NewReader(`{"name":"orphan"}`))
	ctx.Request.Header.Set("Content-Type", "application/json")
	ctx.Set("role", "admin")
	// 刻意不置 user_id——生产链 jwtAuth/apiKeyAuth 必写，此为防御门。

	(&Handlers{}).CreateCurrentUserAPIKey(ctx)

	if recorder.Code != http.StatusUnauthorized {
		t.Fatalf("status=%d body=%s, want 401（认证上下文缺失）", recorder.Code, recorder.Body.String())
	}
	var orphanKeys int
	if err := db.DB.QueryRow("SELECT COUNT(*) FROM api_keys WHERE created_by=0").Scan(&orphanKeys); err != nil {
		t.Fatal(err)
	}
	if orphanKeys != 0 {
		t.Fatalf("orphan keys=%d, want 0（不得写入 created_by=0 的孤儿 Key）", orphanKeys)
	}
}
