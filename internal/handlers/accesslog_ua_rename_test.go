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
