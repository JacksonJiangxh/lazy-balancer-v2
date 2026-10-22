package handlers

// UA 改名保护门只认精确路径——祖先改名
//（request>headers->hdrs 整树带走，filterencoder.go:466-471 引擎实证）
// 绕过校验，UA 统计静默失效。钉三形状：祖先改名/根改名/精确改名全拒。
// 回归：合法改名（remote_ip→src）与无关改名放行。

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/gin-gonic/gin"

	"lazy-balancer-v2/internal/db"
)

func TestValidateAccessLogFormat_rejectsUARenameIncludingAncestors(t *testing.T) {
	cases := []struct {
		name    string
		format  string
		wantErr string
	}{
		{"祖先 headers 整树改名", "request>headers -> hdrs", "User-Agent"},
		{"精确 UA 改名", "request>headers>User-Agent -> ua", "User-Agent"},
		{"根 request 整树改名", "request -> req", "统计"}, // 由 remote_ip 门先行拦截（文案不含 UA），拒绝即正确
		{"合法 remote_ip→src 放行", "request>remote_ip -> src", ""},
		{"合法 uri→uri_path 放行", "request>uri -> uri_path", ""},
		{"无关字段改名放行", "request>host -> h", ""},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			err := validateAccessLogFormat(tc.format)
			if tc.wantErr == "" {
				if err != nil {
					t.Fatalf("format %q must pass, got %v", tc.format, err)
				}
				return
			}
			if err == nil || !strings.Contains(err.Error(), tc.wantErr) {
				t.Fatalf("format %q must reject with %q, got %v", tc.format, tc.wantErr, err)
			}
		})
	}
}

// 非法行（无 ->、空路径、空动作）保存侧必须 400 并点名行号——
// 旧实现静默跳过，非法行落库后渲染层同样静默跳过，用户以为生效。
func TestValidateAccessLogFormat_rejectsInvalidLinesWithLineNumber(t *testing.T) {
	cases := []struct {
		name    string
		format  string
		wantErr string
	}{
		{"无箭头行", "request>remote_ip -> src\nnot-a-mapping", "第 2 行"},
		{"空路径", " -> delete", "第 1 行"},
		{"空动作", "request>host -> ", "第 1 行"},
		{"首行非法+末行非法", "junk\nrequest>uri -> uri_path\n???", "第 1 行"},
		{"空行不算非法", "\nrequest>remote_ip -> src\n\n", ""},
		{"全合法", "request>remote_ip -> src\nrequest>host -> delete", ""},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			err := validateAccessLogFormat(tc.format)
			if tc.wantErr == "" {
				if err != nil {
					t.Fatalf("format %q must pass, got %v", tc.format, err)
				}
				return
			}
			if err == nil || !strings.Contains(err.Error(), tc.wantErr) {
				t.Fatalf("format %q must reject with %q, got %v", tc.format, tc.wantErr, err)
			}
		})
	}
}

// 保存/预览两侧同口径 400（非法行进校验单源，预览不得给出「可变更」）。
func TestUpdateConfig_accessLogFormatInvalidLine400(t *testing.T) {
	h := newBackupTestHandlers(t)
	gin.SetMode(gin.TestMode)
	router := gin.New()
	router.POST("/config/preview", h.PreviewConfigUpdate)
	router.PUT("/config", h.UpdateConfig)
	post := func(handler gin.HandlerFunc, method, path, body string) *httptest.ResponseRecorder {
		request := httptest.NewRequest(method, path, strings.NewReader(body))
		request.Header.Set("Content-Type", "application/json")
		response := httptest.NewRecorder()
		router.ServeHTTP(response, request)
		return response
	}
	body := `{"source":"caddy","access_log_format":"request>remote_ip -> src\nnot-a-mapping"}`
	preview := post(h.PreviewConfigUpdate, http.MethodPost, "/config/preview", body)
	if preview.Code != http.StatusBadRequest || !strings.Contains(preview.Body.String(), "第 2 行") {
		t.Fatalf("preview status=%d body=%s, want 400 含行号", preview.Code, preview.Body.String())
	}
	save := post(h.UpdateConfig, http.MethodPut, "/config", body)
	if save.Code != http.StatusBadRequest || !strings.Contains(save.Body.String(), "第 2 行") {
		t.Fatalf("save status=%d body=%s, want 400 含行号", save.Code, save.Body.String())
	}
}

// access_log_json=false 时自定义格式不生效（渲染层仅在 json=true 消费映射）：
// 现状保存成功但运行态零生效（五链断裂、无告警）。写侧口径：
//  1. 同一请求显式携带非空格式且 json=false → 400（不静默丢弃用户输入）；
//  2. json 关闭后的存量残留格式 → 归一清空并在响应披露（不再静默忽略）。
func TestUpdateConfig_accessLogFormatIgnoredWhenJSONDisabled(t *testing.T) {
	h := newBackupTestHandlers(t)
	gin.SetMode(gin.TestMode)
	router := gin.New()
	router.PUT("/config", h.UpdateConfig)
	router.POST("/config/preview", h.PreviewConfigUpdate)
	send := func(method, path, body string) *httptest.ResponseRecorder {
		request := httptest.NewRequest(method, path, strings.NewReader(body))
		request.Header.Set("Content-Type", "application/json")
		response := httptest.NewRecorder()
		router.ServeHTTP(response, request)
		return response
	}
	put := func(body string) *httptest.ResponseRecorder { return send(http.MethodPut, "/config", body) }
	preview := func(body string) *httptest.ResponseRecorder { return send(http.MethodPost, "/config/preview", body) }
	if _, err := db.DB.Exec(`UPDATE global_config SET access_log_json=1, access_log_format='request>host -> h' WHERE id=1`); err != nil {
		t.Fatalf("seed format: %v", err)
	}

	// 显式携带非空格式 + json=false → 400 点名不生效（保存与预览同门）。
	for name, response := range map[string]*httptest.ResponseRecorder{
		"save":    put(`{"access_log_json":false,"access_log_format":"request>host -> h"}`),
		"preview": preview(`{"access_log_json":false,"access_log_format":"request>host -> h"}`),
	} {
		if response.Code != http.StatusBadRequest || !strings.Contains(response.Body.String(), "不生效") {
			t.Fatalf("%s：json=false + 非空格式必须 400 点名，status=%d body=%s", name, response.Code, response.Body.String())
		}
	}

	// 预览仅关闭 json（不携带格式）→ 200 且变更清单预告「日志格式模板」清空。
	previewed := preview(`{"access_log_json":false}`)
	if previewed.Code != http.StatusOK {
		t.Fatalf("preview status=%d body=%s, want 200", previewed.Code, previewed.Body.String())
	}
	if !strings.Contains(previewed.Body.String(), "日志格式模板") {
		t.Fatalf("预览必须预告存量格式将被清空，body=%s", previewed.Body.String())
	}

	// 仅关闭 json（不携带格式）→ 归一清空存量格式并披露。
	saved := put(`{"access_log_json":false}`)
	if saved.Code != http.StatusOK {
		t.Fatalf("status=%d body=%s, want 200", saved.Code, saved.Body.String())
	}
	if !strings.Contains(saved.Body.String(), "自定义格式已清空") {
		t.Fatalf("归一清空必须披露，body=%s", saved.Body.String())
	}
	var storedJSON, storedFormat string
	if err := db.DB.QueryRow(`SELECT COALESCE(access_log_json,1), COALESCE(access_log_format,'') FROM global_config WHERE id=1`).Scan(&storedJSON, &storedFormat); err != nil {
		t.Fatalf("read stored: %v", err)
	}
	if storedJSON != "0" || storedFormat != "" {
		t.Fatalf("落库終态 json=%s format=%q, want 0/空", storedJSON, storedFormat)
	}
}
