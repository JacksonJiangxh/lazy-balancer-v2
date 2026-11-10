package handlers

// 纯 JSON 备份的零导入交集门：分类选择与备份实际内容无交集（过滤后既无表、
// 也未选系统数据）时必须 400 点名双方，杜绝「什么都没导入但提示成功」。

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/gin-gonic/gin"

	"lazy-balancer-v2/internal/db"
)

func TestImportConfigBackup_rejectsEmptySectionIntersection(t *testing.T) {
	h := newBackupTestHandlers(t)
	// 本机已保留一个启用管理员：400 的唯一成因必须是「零导入交集」，不得被
	// 管理员门掩盖。
	if _, err := db.DB.Exec(`INSERT INTO users (id,username,password_hash,role,is_enabled) VALUES (1,'current-admin','hash','admin',1)`); err != nil {
		t.Fatalf("seed current admin: %v", err)
	}
	gin.SetMode(gin.TestMode)
	router := gin.New()
	router.POST("/config/import", h.ImportConfigBackup)

	// Given 备份只含 users 表，但请求分类只有 rules（交集为空）。
	body := buildBackup(t, backupFixtureOptions{
		Sections: []string{"rules"},
		Tables: map[string][]map[string]any{
			"users": {{"id": 1, "username": "backup-admin", "password_hash": "hash", "role": "admin", "is_enabled": 1}},
		},
		EmptyConfigIfNil: true,
	})

	// When
	recorder := httptest.NewRecorder()
	request := httptest.NewRequest(http.MethodPost, "/config/import", strings.NewReader(body))
	request.Header.Set("Content-Type", "application/json")
	router.ServeHTTP(recorder, request)

	// Then 400 且点名请求分类，不谎报成功。
	if recorder.Code != http.StatusBadRequest {
		t.Fatalf("status=%d body=%s, want 400（零导入交集）", recorder.Code, recorder.Body.String())
	}
	response := recorder.Body.String()
	if !strings.Contains(response, "无交集") || !strings.Contains(response, "rules") || !strings.Contains(response, "未导入任何数据") {
		t.Fatalf("body=%s, want 点名请求分类与未导入说明", response)
	}

	// Then 本地用户未被替换（零导入）。
	var count int
	if err := db.DB.QueryRow(`SELECT COUNT(*) FROM users WHERE username='backup-admin'`).Scan(&count); err != nil {
		t.Fatal(err)
	}
	if count != 0 {
		t.Fatalf("零导入交集仍写入了备份用户 %d 行", count)
	}
}

// 对照：分类与内容有交集时照常导入（门不得恒拒）。
func TestImportConfigBackup_importsWhenSectionIntersectsContent(t *testing.T) {
	h := newBackupTestHandlers(t)
	gin.SetMode(gin.TestMode)
	router := gin.New()
	router.POST("/config/import", h.ImportConfigBackup)

	body := buildBackup(t, backupFixtureOptions{
		Sections: []string{"users"},
		Tables: map[string][]map[string]any{
			"users": {{"id": 1, "username": "backup-admin", "password_hash": "hash", "role": "admin", "is_enabled": 1}},
		},
		EmptyConfigIfNil: true,
	})

	recorder := httptest.NewRecorder()
	request := httptest.NewRequest(http.MethodPost, "/config/import", strings.NewReader(body))
	request.Header.Set("Content-Type", "application/json")
	router.ServeHTTP(recorder, request)

	if recorder.Code != http.StatusOK {
		t.Fatalf("status=%d body=%s, want 200", recorder.Code, recorder.Body.String())
	}
	var count int
	if err := db.DB.QueryRow(`SELECT COUNT(*) FROM users WHERE username='backup-admin'`).Scan(&count); err != nil {
		t.Fatal(err)
	}
	if count != 1 {
		t.Fatalf("交集非空时备份用户应被导入，count=%d", count)
	}
}
