package handlers

// 版本表的行级布尔门必须先于「单侧文件缺失剔除」执行：剔除会先删表，
// 若在校验之前发生，预览与导入都会静默放过坏值（合法备份形态下不可观察，
// 但次序一旦颠倒，双路径同时失去这层校验）。

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/gin-gonic/gin"
)

func TestConfigImport_versionTableBooleanGatePrecedesFileMissingExclusion(t *testing.T) {
	h := newBackupTestHandlers(t)
	gin.SetMode(gin.TestMode)
	// 纯 JSON 备份（无 lbbak 数据文件）：安全分类携带版本表行，auto_update 为
	// 字符串坏值。若剔除步前移，该表会被「无数据文件」剔掉，坏值无从校验。
	tables := map[string][]map[string]any{
		"security_crs_version": {{"auto_update": "yes"}},
	}
	body := backupJSONFixture(t, tables, nil, []string{"security"})
	wantError := "security_crs_version 第 1 行 auto_update 需为布尔值"

	router := gin.New()
	router.POST("/config/import/validate", h.ValidateConfigImport)
	preview := httptest.NewRecorder()
	request := httptest.NewRequest(http.MethodPost, "/config/import/validate", strings.NewReader(string(body)))
	request.Header.Set("Content-Type", "application/json")
	router.ServeHTTP(preview, request)
	if preview.Code != http.StatusOK {
		t.Fatalf("preview status=%d body=%s", preview.Code, preview.Body.String())
	}
	var envelope struct {
		Data importValidateResponse `json:"data"`
	}
	if err := json.Unmarshal(preview.Body.Bytes(), &envelope); err != nil {
		t.Fatalf("decode preview: %v", err)
	}
	if envelope.Data.Valid {
		t.Fatalf("预览必须拒绝坏值: %s", preview.Body.String())
	}
	if !strings.Contains(envelope.Data.Error, wantError) {
		t.Fatalf("preview error=%q, want 含 %q", envelope.Data.Error, wantError)
	}

	// 导入侧同一判据（双路径同序）。
	importRouter := gin.New()
	importRouter.POST("/config/import", h.ImportConfigBackup)
	recorder := httptest.NewRecorder()
	request = httptest.NewRequest(http.MethodPost, "/config/import", strings.NewReader(string(body)))
	request.Header.Set("Content-Type", "application/json")
	importRouter.ServeHTTP(recorder, request)
	if recorder.Code != http.StatusBadRequest {
		t.Fatalf("import status=%d body=%s, want 400", recorder.Code, recorder.Body.String())
	}
	if !strings.Contains(recorder.Body.String(), wantError) {
		t.Fatalf("import body=%s, want 含 %q", recorder.Body.String(), wantError)
	}
}
