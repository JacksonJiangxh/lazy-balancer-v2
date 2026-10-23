package handlers

// 创建与鉴权两侧的单源契约：handler 已签发明文 → 落库的 key_hash/key_prefix
// 必须能被鉴权侧 db.ResolveAPIKeyIdentity 用同一份明文命中同一行。

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/gin-gonic/gin"

	"lazy-balancer-v2/internal/db"
)

func TestCreateAPIKey_roundtripAuthenticates(t *testing.T) {
	database := setupAPIKeyTestDB(t)
	gin.SetMode(gin.TestMode)
	recorder := httptest.NewRecorder()
	ctx, _ := gin.CreateTestContext(recorder)
	ctx.Request = httptest.NewRequest(http.MethodPost, "/api/v1/users/me/api-keys",
		strings.NewReader(`{"name":"roundtrip"}`))
	ctx.Request.Header.Set("Content-Type", "application/json")
	ctx.Set("user_id", 1)
	ctx.Set("role", "user")

	(&Handlers{}).CreateCurrentUserAPIKey(ctx)

	if recorder.Code != http.StatusCreated {
		t.Fatalf("status=%d body=%s, want 201", recorder.Code, recorder.Body.String())
	}
	var resp struct {
		Data struct {
			ID  int    `json:"id"`
			Key string `json:"key"`
		} `json:"data"`
	}
	if err := json.Unmarshal(recorder.Body.Bytes(), &resp); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if resp.Data.Key == "" {
		t.Fatal("创建响应必须返回一次完整明文")
	}

	identity, err := db.ResolveAPIKeyIdentity(database, resp.Data.Key)
	if err != nil {
		t.Fatalf("鉴权侧无法解析刚创建的明文: %v", err)
	}
	if identity.ID != resp.Data.ID || identity.UserID != 1 {
		t.Fatalf("identity=%+v, want id=%d user=1", identity, resp.Data.ID)
	}

	var prefix string
	if err := database.QueryRow(`SELECT key_prefix FROM api_keys WHERE id=?`, resp.Data.ID).Scan(&prefix); err != nil {
		t.Fatalf("read key prefix: %v", err)
	}
	if prefix != resp.Data.Key[:12] {
		t.Fatalf("key_prefix=%q, want 明文前 12 字节 %q", prefix, resp.Data.Key[:12])
	}
}
