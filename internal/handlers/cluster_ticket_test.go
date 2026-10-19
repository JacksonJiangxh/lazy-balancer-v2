package handlers

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/gin-gonic/gin"

	"lazy-balancer-v2/internal/db"
)

// 历史问题（历史 历史问题）：TicketLogin 的 500 分支（DB/内部故障）曾复用「登录
// 票据无效或已过期」凭证文案——审计侧已区分 database_error，响应面缺失让
// 运维误判为票据问题并反复重取票据。钉：DB 故障 → 500 + 独立文案；401
// 凭证分支文案不变。
func TestTicketLogin_databaseErrorUsesRetryMessage(t *testing.T) {
	h := newBackupTestHandlers(t)
	const clusterToken = "lb_cluster_a87"
	if _, err := db.DB.Exec(`UPDATE global_config SET is_master=0, cluster_token=?, registration_id=7 WHERE id=1`, clusterToken); err != nil {
		t.Fatal(err)
	}
	if _, err := db.DB.Exec(`INSERT INTO users (id, username, password_hash, role, is_enabled) VALUES (1,'alice','hash','admin',1)`); err != nil {
		t.Fatal(err)
	}
	// 构造合法票据（HMAC 键=sha256(cluster_token)），随后删表制造 DB 故障：
	// 票据验签/用户校验通过，消费票据语句失败 → 非 ErrInvalidLoginTicket 的 500。
	claims, err := json.Marshal(map[string]any{
		"user_id": 1, "username": "alice", "node_id": 7, "jti": "jti-a87",
		"expires_at": time.Now().Add(time.Minute).Unix(),
	})
	if err != nil {
		t.Fatal(err)
	}
	key := sha256.Sum256([]byte(clusterToken))
	payload := base64.RawURLEncoding.EncodeToString(claims)
	mac := hmac.New(sha256.New, key[:])
	// 服务层对 base64 载荷串（parts[0]）签名，而非原始 JSON 字节。
	_, _ = mac.Write([]byte(payload))
	ticket := payload + "." + base64.RawURLEncoding.EncodeToString(mac.Sum(nil))
	if _, err := db.DB.Exec(`DROP TABLE used_login_tickets`); err != nil {
		t.Fatalf("drop used_login_tickets: %v", err)
	}

	gin.SetMode(gin.TestMode)
	router := gin.New()
	router.POST("/auth/ticket-login", h.TicketLogin)
	response := httptest.NewRecorder()
	request := httptest.NewRequest(http.MethodPost, "/auth/ticket-login", strings.NewReader(`{"ticket":"`+ticket+`"}`))
	request.Header.Set("Content-Type", "application/json")
	router.ServeHTTP(response, request)

	if response.Code != http.StatusInternalServerError {
		t.Fatalf("status=%d body=%s, want 500", response.Code, response.Body.String())
	}
	if strings.Contains(response.Body.String(), "登录票据无效或已过期") {
		t.Fatalf("body=%s, DB 故障不得归因为票据无效", response.Body.String())
	}
	if !strings.Contains(response.Body.String(), "校验失败") {
		t.Fatalf("body=%s, want 独立故障文案（校验失败，请稍后重试）", response.Body.String())
	}
	var reason string
	if err := db.AuditDB.QueryRow(`SELECT detail FROM audit_log WHERE action='登录失败' AND resource='登录票据' ORDER BY id DESC LIMIT 1`).Scan(&reason); err != nil {
		t.Fatalf("query ticket failure audit: %v", err)
	}
	if !strings.Contains(reason, "数据库错误") {
		t.Fatalf("audit detail=%q, want 数据库错误（database_error 的落库形态）", reason)
	}
}

func TestRecordTicketLoginFailureAuditsSanitizedReasons(t *testing.T) {
	oldDB, oldMetricsDB, oldAuditDB := db.DB, db.MetricsDB, db.AuditDB
	if err := db.Initialize(t.TempDir()); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		_ = db.Close()
		db.DB, db.MetricsDB, db.AuditDB = oldDB, oldMetricsDB, oldAuditDB
		db.SetDB(oldDB)
	})
	gin.SetMode(gin.TestMode)
	context, _ := gin.CreateTestContext(httptest.NewRecorder())
	context.Request = httptest.NewRequest("POST", "/api/v1/auth/ticket-login", nil)
	const ticket = "secret-ticket-body"
	for _, reason := range []string{"invalid_request", "invalid_signature", "expired", "replay", "user_unavailable", "database_error"} {
		recordTicketLoginFailure(context, "alice", reason)
	}
	rows, err := db.AuditDB.Query("SELECT detail FROM audit_log WHERE resource='登录票据' ORDER BY id")
	if err != nil {
		t.Fatal(err)
	}
	defer rows.Close()
	count := 0
	for rows.Next() {
		var detail string
		if err := rows.Scan(&detail); err != nil {
			t.Fatal(err)
		}
		if strings.Contains(detail, ticket) {
			t.Fatalf("audit detail leaked ticket: %q", detail)
		}
		count++
	}
	if err := rows.Err(); err != nil {
		t.Fatal(err)
	}
	if count != 6 {
		t.Fatalf("ticket failure audit count=%d, want 6", count)
	}
}
