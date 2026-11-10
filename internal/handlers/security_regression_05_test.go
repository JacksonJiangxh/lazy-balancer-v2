package handlers

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/gin-gonic/gin"

	"lazy-balancer-v2/internal/db"
)

// 备份可携带 ≥2 个 is_default=1 的拦截页。导入后仅 MIN(id)
// 保留默认，其余降级为非默认，避免产生不可编辑/删除的死行及 branding 覆盖误伤。
func TestImportConfigBackup_demotesExtraDefaultBlockPages(t *testing.T) {
	// Given
	h := newBackupTestHandlers(t)
	backup := completeBackupJSON(t, map[string][]map[string]any{
		"users": {{"id": 1, "username": "backup-admin", "password_hash": "hash", "role": "admin", "is_enabled": true}},
		"security_block_pages": {
			{"id": 1, "name": "默认拦截页面", "description": "sys", "content": "<html>a</html>", "is_default": true},
			{"id": 5, "name": "旧默认页", "description": "legacy", "content": "<html>b</html>", "is_default": true},
			{"id": 7, "name": "自定义页", "description": "custom", "content": "<html>c</html>", "is_default": false},
		},
	})
	router := gin.New()
	router.POST("/config/import", h.ImportConfigBackup)
	request := httptest.NewRequest(http.MethodPost, "/config/import", strings.NewReader(backup))
	request.Header.Set("Content-Type", "application/json")
	response := httptest.NewRecorder()

	// When
	router.ServeHTTP(response, request)

	// Then
	if response.Code != http.StatusOK {
		t.Fatalf("status=%d body=%s, want 200", response.Code, response.Body.String())
	}
	var defaultCount int
	if err := db.DB.QueryRow("SELECT COUNT(*) FROM security_block_pages WHERE is_default=1").Scan(&defaultCount); err != nil {
		t.Fatalf("count default pages: %v", err)
	}
	if defaultCount != 1 {
		t.Fatalf("default page count=%d, want 1（仅 MIN(id) 保留默认）", defaultCount)
	}
	var defaultID int
	if err := db.DB.QueryRow("SELECT id FROM security_block_pages WHERE is_default=1").Scan(&defaultID); err != nil {
		t.Fatalf("read default page id: %v", err)
	}
	if defaultID != 1 {
		t.Fatalf("default page id=%d, want 1（MIN(id)）", defaultID)
	}
	var legacyDefault bool
	if err := db.DB.QueryRow("SELECT is_default FROM security_block_pages WHERE id=5").Scan(&legacyDefault); err != nil {
		t.Fatalf("read legacy page: %v", err)
	}
	if legacyDefault {
		t.Fatalf("id=5 应被降级为非默认页")
	}
	var customDefault bool
	if err := db.DB.QueryRow("SELECT is_default FROM security_block_pages WHERE id=7").Scan(&customDefault); err != nil {
		t.Fatalf("read custom page: %v", err)
	}
	if customDefault {
		t.Fatalf("id=7 本就不是默认页，不应被误改")
	}
}

// 备份未携带任何拦截页时，重播种必须在导入事务内随提交生效，
// 提交后系统存在 id=1 的默认页（拦截响应不退化）。
func TestImportConfigBackup_reseedsDefaultBlockPageWhenBackupHasNone(t *testing.T) {
	// Given
	h := newBackupTestHandlers(t)
	backup := completeBackupJSON(t, map[string][]map[string]any{
		"users": {{"id": 1, "username": "backup-admin", "password_hash": "hash", "role": "admin", "is_enabled": true}},
		// security_block_pages 为空数组：DELETE 清空后 INSERT 零行 → 重播种应触发
	})
	router := gin.New()
	router.POST("/config/import", h.ImportConfigBackup)
	request := httptest.NewRequest(http.MethodPost, "/config/import", strings.NewReader(backup))
	request.Header.Set("Content-Type", "application/json")
	response := httptest.NewRecorder()

	// When
	router.ServeHTTP(response, request)

	// Then
	if response.Code != http.StatusOK {
		t.Fatalf("status=%d body=%s, want 200", response.Code, response.Body.String())
	}
	var count int
	if err := db.DB.QueryRow("SELECT COUNT(*) FROM security_block_pages WHERE is_default=1 AND id=1").Scan(&count); err != nil {
		t.Fatalf("count default pages: %v", err)
	}
	if count != 1 {
		t.Fatalf("reseeded default page count=%d, want 1（重播种随事务提交）", count)
	}
}

// （事务性反例）重播种在导入事务内执行：在重播种**之后**注入事务内失败
// （users 口令版本更新触发 BEFORE UPDATE 触发器），导入整体回滚后拦截页行集
// 必须与导入前逐行一致——若重播种被挪到事务外单独落库，行集会变成「只剩
// 重播种的默认页」，本用例即转红。对照子用例用同一备份去掉故障 → 提交生效：
// 自定义页消失、默认页 id=1 重播种，证明「行集不变」不是删除未执行的假绿。
func TestImportConfigBackup_reseedRollsBackWithFailedImport(t *testing.T) {
	// Given：导入前存在一张自定义拦截页（会被导入的 DELETE 清掉）
	h := newBackupTestHandlers(t)
	if _, err := db.DB.Exec(`INSERT INTO security_block_pages
		(id, name, description, content, is_default, created_at, updated_at)
		VALUES (50, '自定义拦截页', '', '自定义内容', 0, datetime('now'), datetime('now'))`); err != nil {
		t.Fatalf("insert custom block page: %v", err)
	}
	before := blockPageSnapshot(t)
	backup := completeBackupJSON(t, map[string][]map[string]any{
		"users":                {{"id": 1, "username": "backup-admin", "password_hash": "hash", "role": "admin", "is_enabled": true}},
		"security_block_pages": {}, // 清空后触发事务内重播种
	})
	router := gin.New()
	router.POST("/config/import", h.ImportConfigBackup)
	importBackup := func() *httptest.ResponseRecorder {
		request := httptest.NewRequest(http.MethodPost, "/config/import", strings.NewReader(backup))
		request.Header.Set("Content-Type", "application/json")
		response := httptest.NewRecorder()
		router.ServeHTTP(response, request)
		return response
	}
	// 触发器在重播种（拦截页恢复 + 默认页 INSERT）之后才命中：导入流程对
	// users 的唯一 UPDATE 是口令版本递增，位于重播种块之后。
	if _, err := db.DB.Exec(`CREATE TRIGGER fail_import_after_reseed
		BEFORE UPDATE ON users BEGIN SELECT RAISE(ABORT, '注入的事务内失败'); END`); err != nil {
		t.Fatalf("create failure trigger: %v", err)
	}

	// When：导入在事务内失败
	response := importBackup()

	// Then：回滚生效，拦截页行集与导入前完全一致
	if response.Code != http.StatusInternalServerError {
		t.Fatalf("status=%d body=%s, want 500", response.Code, response.Body.String())
	}
	if !strings.Contains(response.Body.String(), "已回滚") {
		t.Fatalf("body=%s, want rollback message", response.Body.String())
	}
	if after := blockPageSnapshot(t); after != before {
		t.Fatalf("拦截页行集在回滚后发生变化\nbefore:\n%s\nafter:\n%s", before, after)
	}

	// And：同一备份去除故障后成功提交——自定义页被替换、默认页重播种
	if _, err := db.DB.Exec(`DROP TRIGGER fail_import_after_reseed`); err != nil {
		t.Fatalf("drop failure trigger: %v", err)
	}
	if response := importBackup(); response.Code != http.StatusOK {
		t.Fatalf("对照导入 status=%d body=%s, want 200", response.Code, response.Body.String())
	}
	var customRows int
	if err := db.DB.QueryRow("SELECT COUNT(*) FROM security_block_pages WHERE id=50").Scan(&customRows); err != nil {
		t.Fatalf("count custom page: %v", err)
	}
	if customRows != 0 {
		t.Fatalf("自定义页行数=%d，导入提交后应被清空", customRows)
	}
	var defaultRows int
	if err := db.DB.QueryRow("SELECT COUNT(*) FROM security_block_pages WHERE is_default=1 AND id=1").Scan(&defaultRows); err != nil {
		t.Fatalf("count default page: %v", err)
	}
	if defaultRows != 1 {
		t.Fatalf("重播种默认页行数=%d，want 1（重播种随事务提交）", defaultRows)
	}
}

// blockPageSnapshot 把拦截页表快照成可比较字符串（逐行、按 id 排序）。
func blockPageSnapshot(t *testing.T) string {
	t.Helper()
	rows, err := db.DB.Query(`SELECT id, name, description, content, is_default FROM security_block_pages ORDER BY id`)
	if err != nil {
		t.Fatalf("snapshot block pages: %v", err)
	}
	defer rows.Close()
	var lines []string
	for rows.Next() {
		var id int
		var name, description, content string
		var isDefault bool
		if err := rows.Scan(&id, &name, &description, &content, &isDefault); err != nil {
			t.Fatalf("scan block page snapshot: %v", err)
		}
		lines = append(lines, fmt.Sprintf("%d|%s|%s|%s|%t", id, name, description, content, isDefault))
	}
	if err := rows.Err(); err != nil {
		t.Fatalf("iterate block page snapshot: %v", err)
	}
	return strings.Join(lines, "\n")
}
