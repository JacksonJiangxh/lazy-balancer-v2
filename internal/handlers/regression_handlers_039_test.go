package handlers

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/gin-gonic/gin"

	"lazy-balancer-v2/internal/db"
)

func putAccessLogFormat(t *testing.T, h *Handlers, format string) *httptest.ResponseRecorder {
	t.Helper()
	router := gin.New()
	router.PUT("/config", h.UpdateConfig)
	rec := httptest.NewRecorder()
	body := `{"access_log_format":` + jsonString(format) + `}`
	req := httptest.NewRequest(http.MethodPut, "/config", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	router.ServeHTTP(rec, req)
	return rec
}

func jsonString(s string) string {
	replacer := strings.NewReplacer(`\`, `\\`, `"`, `\"`, "\n", `\n`)
	return `"` + replacer.Replace(s) + `"`
}

// rename 行时也必须收敛为 delete），落库值=UI 所见。
func TestUpdateConfig_normalizesAPIKeyRedactionOnWrite(t *testing.T) {
	handler, _, _ := newAuditRuleHandlers(t, 0)

	rec := putAccessLogFormat(t, handler, "request>remote_ip -> src\nrequest>headers>X-API-Key -> apikey")
	if rec.Code != http.StatusOK {
		t.Fatalf("status=%d body=%s, want 200", rec.Code, rec.Body.String())
	}
	var stored string
	if err := db.DB.QueryRow("SELECT COALESCE(access_log_format,'') FROM global_config WHERE id=1").Scan(&stored); err != nil {
		t.Fatalf("read stored format: %v", err)
	}
	if strings.Contains(stored, "apikey") {
		t.Fatalf("rename 行未收敛，落库仍含明文映射: %q", stored)
	}
	if strings.Count(stored, "request>headers>X-API-Key -> delete") != 1 {
		t.Fatalf("落库缺少唯一规范脱敏行: %q", stored)
	}
	if !strings.Contains(stored, "request>remote_ip -> src") {
		t.Fatalf("用户自定义映射被误删: %q", stored)
	}

	// 幂等：再次提交同一格式 = 无变化（不得重复追加）。
	rec = putAccessLogFormat(t, handler, stored)
	if rec.Code != http.StatusOK || !strings.Contains(rec.Body.String(), "配置无变化") {
		t.Fatalf("重复保存 status=%d body=%s, want 200 配置无变化", rec.Code, rec.Body.String())
	}
	var after string
	if err := db.DB.QueryRow("SELECT COALESCE(access_log_format,'') FROM global_config WHERE id=1").Scan(&after); err != nil {
		t.Fatalf("read stored format: %v", err)
	}
	if after != stored {
		t.Fatalf("幂等保存改写了格式: before=%q after=%q", stored, after)
	}
}

// 空格式是受支持形态（「不裁剪原生字段」），写侧保持原样；渲染层恒注入
// 脱敏行（services 侧测试钉住）。
func TestUpdateConfig_keepsEmptyAccessLogFormat(t *testing.T) {
	handler, _, _ := newAuditRuleHandlers(t, 0)
	if _, err := db.DB.Exec("UPDATE global_config SET access_log_format='request>remote_ip -> src' WHERE id=1"); err != nil {
		t.Fatalf("seed: %v", err)
	}
	rec := putAccessLogFormat(t, handler, "")
	if rec.Code != http.StatusOK {
		t.Fatalf("status=%d body=%s, want 200", rec.Code, rec.Body.String())
	}
	var stored string
	if err := db.DB.QueryRow("SELECT COALESCE(access_log_format,'') FROM global_config WHERE id=1").Scan(&stored); err != nil {
		t.Fatalf("read stored format: %v", err)
	}
	if stored != "" {
		t.Fatalf("空格式被改写为 %q", stored)
	}
}

// 单源一致——NULL（legacy 脏行）视为节点角色默认（主节点），不得让 GET /config
// 500（前端 nodeMode 展示分叉）。
func TestGetConfig_isMasterNullFallsBackToMaster(t *testing.T) {
	handler, _, _ := newAuditRuleHandlers(t, 0)
	if _, err := db.DB.Exec("UPDATE global_config SET is_master=NULL WHERE id=1"); err != nil {
		t.Fatalf("seed null role: %v", err)
	}
	router := gin.New()
	router.GET("/config", handler.GetConfig)
	rec := httptest.NewRecorder()
	router.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/config", nil))
	if rec.Code != http.StatusOK {
		t.Fatalf("status=%d body=%s, want 200（NULL 角色应与 RoleOf 同口径）", rec.Code, rec.Body.String())
	}
	if !strings.Contains(rec.Body.String(), `"is_master":true`) {
		t.Fatalf("body=%s, want is_master=true（COALESCE(is_master,1) 口径）", rec.Body.String())
	}
}
