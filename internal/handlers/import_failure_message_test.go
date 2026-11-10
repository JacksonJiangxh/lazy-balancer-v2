package handlers

// 导入/还原失败文案口径：动作词只出现一次（审计 action 已带「导入失败/还原失败」，
// detail 不再重复动作前缀）；成功失败分流如实表述——除 commit 阶段外都中止在
// 事务回滚后，commit 阶段的失败结果不可判定，不得断言「数据库未变更」。

import (
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"

	"github.com/gin-gonic/gin"

	"lazy-balancer-v2/internal/db"
	"lazy-balancer-v2/internal/services"
)

// deadCaddyURL 指向未监听端口：任何 admin 调用立即连接失败，用于在事务回滚
// 路径上稳定触发失败。
const deadCaddyURL = "http://127.0.0.1:1"

func TestImportConfigBackup_failureMessageCarriesActionOnce(t *testing.T) {
	h := newBackupTestHandlers(t)
	h.cfg.CaddyAdminURL = deadCaddyURL
	h.caddyService = services.NewCaddyService(deadCaddyURL)
	gin.SetMode(gin.TestMode)
	router := gin.New()
	router.POST("/config/import", h.ImportConfigBackup)

	body := buildBackup(t, backupFixtureOptions{FillAll: true, EmptyConfigIfNil: true})
	recorder := httptest.NewRecorder()
	request := httptest.NewRequest(http.MethodPost, "/config/import", strings.NewReader(body))
	request.Header.Set("Content-Type", "application/json")
	router.ServeHTTP(recorder, request)

	if recorder.Code != http.StatusInternalServerError {
		t.Fatalf("status=%d body=%s, want 500", recorder.Code, recorder.Body.String())
	}
	var response struct {
		Message string `json:"message"`
	}
	if err := json.Unmarshal(recorder.Body.Bytes(), &response); err != nil {
		t.Fatalf("decode response: %v body=%s", err, recorder.Body.String())
	}
	// 动作词只出现一次（旧实现 detail 自带「导入失败：」→ 双前缀）。
	if count := strings.Count(response.Message, "导入失败"); count != 1 {
		t.Fatalf("message=%q，动作词出现 %d 次, want 1（禁止双前缀）", response.Message, count)
	}
	if !strings.Contains(response.Message, "数据库未变更") {
		t.Fatalf("message=%q, want 阶段描述「数据库未变更」", response.Message)
	}

	var action, detail string
	if err := db.AuditDB.QueryRow(`SELECT action, detail FROM audit_log WHERE resource='配置备份' ORDER BY id DESC LIMIT 1`).Scan(&action, &detail); err != nil {
		t.Fatalf("read failure audit: %v", err)
	}
	if action != "导入失败" {
		t.Fatalf("audit action=%q, want 导入失败", action)
	}
	if strings.Contains(detail, "导入失败") {
		t.Fatalf("audit detail=%q 重复动作前缀", detail)
	}
	if !strings.Contains(detail, "数据库未变更") {
		t.Fatalf("audit detail=%q, want 阶段描述", detail)
	}
}

func TestRestoreAutoBackup_failureMessageUsesRestoreAction(t *testing.T) {
	h := newAutoBackupTestHandlers(t)
	h.cfg.CaddyAdminURL = deadCaddyURL
	h.caddyService = services.NewCaddyService(deadCaddyURL)
	gin.SetMode(gin.TestMode)

	payload := buildBackup(t, backupFixtureOptions{FillAll: true, EmptyConfigIfNil: true})
	filename := "lbbak-manual-restore-fail.lbbak"
	if err := os.WriteFile(filepath.Join(h.cfg.BackupDir, filename), []byte(payload), 0o600); err != nil {
		t.Fatalf("write backup file: %v", err)
	}
	res, err := db.DB.Exec(`INSERT INTO auto_backups (filename, created_at, status, size_bytes, trigger_type) VALUES (?, datetime('now'), 'success', ?, 'manual')`, filename, len(payload))
	if err != nil {
		t.Fatalf("seed auto_backups row: %v", err)
	}
	backupID, err := res.LastInsertId()
	if err != nil {
		t.Fatal(err)
	}

	router := gin.New()
	router.POST("/auto-backup/:id/restore", h.RestoreAutoBackup)
	recorder := httptest.NewRecorder()
	request := httptest.NewRequest(http.MethodPost, "/auto-backup/"+itoa64(backupID)+"/restore", nil)
	router.ServeHTTP(recorder, request)

	if recorder.Code != http.StatusInternalServerError {
		t.Fatalf("status=%d body=%s, want 500", recorder.Code, recorder.Body.String())
	}
	var response struct {
		Message string `json:"message"`
	}
	if err := json.Unmarshal(recorder.Body.Bytes(), &response); err != nil {
		t.Fatalf("decode response: %v body=%s", err, recorder.Body.String())
	}
	// 还原失败的文案必须跟随「还原」动作（旧实现恒写「导入失败」形成双前缀）。
	if count := strings.Count(response.Message, "还原失败"); count != 1 {
		t.Fatalf("message=%q，还原动作词出现 %d 次, want 1", response.Message, count)
	}
	if strings.Contains(response.Message, "导入失败") {
		t.Fatalf("message=%q 混入导入动作词（还原路径文案串档）", response.Message)
	}

	var action, detail string
	if err := db.AuditDB.QueryRow(`SELECT action, detail FROM audit_log WHERE resource='配置备份' ORDER BY id DESC LIMIT 1`).Scan(&action, &detail); err != nil {
		t.Fatalf("read failure audit: %v", err)
	}
	if action != "还原失败" {
		t.Fatalf("audit action=%q, want 还原失败", action)
	}
	if strings.Contains(detail, "还原失败") || strings.Contains(detail, "导入失败") {
		t.Fatalf("audit detail=%q 重复/串档动作前缀", detail)
	}
	if !strings.Contains(detail, "数据库未变更") {
		t.Fatalf("audit detail=%q, want 阶段描述", detail)
	}
}

// commit 阶段失败不得断言数据库未变更：Commit 报错无法区分「未提交」与
// 「已提交但确认丢失」——文案必须如实表述为「提交结果不确定」。
func TestImportFailureDetail_commitPhaseClaimsUncertainResult(t *testing.T) {
	err := &importCoordinatorError{phase: importPhaseCommit, err: errCommitInjected, action: "还原"}

	detail := importFailureAuditDetail(err)
	if !strings.Contains(detail, "数据库提交结果不确定") {
		t.Fatalf("detail=%q, want 提交结果不确定", detail)
	}
	if strings.Contains(detail, "未变更") {
		t.Fatalf("detail=%q 不得断言数据库未变更", detail)
	}
	if strings.Contains(detail, "还原失败") {
		t.Fatalf("detail=%q 重复动作前缀", detail)
	}
	if description := err.Error(); !strings.Contains(description, "还原失败（数据库提交结果不确定）") {
		t.Fatalf("Error()=%q, want 还原动作 + 不确定结果", description)
	}
}

var errCommitInjected = errors.New("commit failed: disk I/O error")

func itoa64(value int64) string {
	return strconv.FormatInt(value, 10)
}
