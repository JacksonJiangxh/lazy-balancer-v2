package handlers

// 自动备份「还原/下载/删除」的**行查询面**失败（400 非法 ID、404 行不存在、
// 500 DB 故障）此前只有裸 c.JSON：文件面（failRestoreFileAccess）已有失败
// 审计，行面却在同一高危操作族的前置阶段留白——列表页点按钮时行可能已被
// 保留期裁剪或并发删除，被拒尝试在操作审计页零记录。本文件钉住三个出口的
// 「失败审计 + 原响应」形态，并确认不产生虚假的成功审计。

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/gin-gonic/gin"

	"lazy-balancer-v2/internal/db"
)

func rowAccessRouter(h *Handlers) *gin.Engine {
	gin.SetMode(gin.TestMode)
	router := gin.New()
	router.POST("/api/v1/auto-backup/:id/restore", h.RestoreAutoBackup)
	router.GET("/api/v1/auto-backup/:id/download", h.DownloadAutoBackup)
	router.DELETE("/api/v1/auto-backup/:id", h.DeleteAutoBackup)
	return router
}

func deleteBackupRow(t *testing.T, id int64) {
	t.Helper()
	if _, err := db.DB.Exec(`DELETE FROM auto_backups WHERE id=?`, id); err != nil {
		t.Fatalf("delete auto_backups row: %v", err)
	}
}

// Given 备份行已被保留期裁剪/并发删除（列表页仍显示该行）。
// When POST restore。
// Then 404 + 恰一条「还原失败」审计（含备份标识），无成功审计。
func TestRestoreAutoBackup_rowGoneAuditsRejection(t *testing.T) {
	h := newAutoBackupTestHandlers(t)
	router := rowAccessRouter(h)
	id, _ := seedManualBackup(t, h)
	deleteBackupRow(t, id)

	rec := httptest.NewRecorder()
	router.ServeHTTP(rec, httptest.NewRequest(http.MethodPost, fmt.Sprintf("/api/v1/auto-backup/%d/restore", id), nil))

	if rec.Code != http.StatusNotFound {
		t.Fatalf("status=%d body=%s, want 404", rec.Code, rec.Body.String())
	}
	if !strings.Contains(rec.Body.String(), "备份不存在") {
		t.Fatalf("body=%s, want 备份不存在 文案", rec.Body.String())
	}
	failures := restoreRejectionAuditRows(t, "还原失败")
	if len(failures) != 1 {
		t.Fatalf("还原失败 审计行=%d, want 1（行面拒绝必须留痕）", len(failures))
	}
	if want := fmt.Sprintf("备份 #%d", id); !strings.Contains(failures[0], want) {
		t.Fatalf("审计 detail=%q 必须含 %q", failures[0], want)
	}
	if successes := restoreRejectionAuditRows(t, "还原"); len(successes) != 0 {
		t.Fatalf("被拒绝的还原不得留下成功审计: %v", successes)
	}
}

// Given 非法备份 ID（客户端/书签残留形态）。
// When POST restore。
// Then 400 + 恰一条「还原失败」审计（含原始 ID），无成功审计。
func TestRestoreAutoBackup_invalidIDAuditsRejection(t *testing.T) {
	h := newAutoBackupTestHandlers(t)
	router := rowAccessRouter(h)

	rec := httptest.NewRecorder()
	router.ServeHTTP(rec, httptest.NewRequest(http.MethodPost, "/api/v1/auto-backup/abc/restore", nil))

	if rec.Code != http.StatusBadRequest {
		t.Fatalf("status=%d body=%s, want 400", rec.Code, rec.Body.String())
	}
	if !strings.Contains(rec.Body.String(), "无效的备份 ID") {
		t.Fatalf("body=%s, want 无效的备份 ID 文案", rec.Body.String())
	}
	failures := restoreRejectionAuditRows(t, "还原失败")
	if len(failures) != 1 {
		t.Fatalf("还原失败 审计行=%d, want 1", len(failures))
	}
	if !strings.Contains(failures[0], "abc") || !strings.Contains(failures[0], "无效的备份 ID") {
		t.Fatalf("审计 detail=%q 必须含原始 ID 与归因", failures[0])
	}
	if successes := restoreRejectionAuditRows(t, "还原"); len(successes) != 0 {
		t.Fatalf("被拒绝的还原不得留下成功审计: %v", successes)
	}
}

// Given 备份行已消失。
// When GET download。
// Then 404 + 恰一条「下载失败」审计，且不记「备份下载」成功审计（未交付）。
func TestDownloadAutoBackup_rowGoneAuditsRejectionNotDelivery(t *testing.T) {
	h := newAutoBackupTestHandlers(t)
	router := rowAccessRouter(h)
	id, _ := seedManualBackup(t, h)
	deleteBackupRow(t, id)

	rec := httptest.NewRecorder()
	router.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, fmt.Sprintf("/api/v1/auto-backup/%d/download", id), nil))

	if rec.Code != http.StatusNotFound {
		t.Fatalf("status=%d body=%s, want 404", rec.Code, rec.Body.String())
	}
	if n := downloadAuditCount(t); n != 0 {
		t.Fatalf("行不存在时「备份下载」审计行=%d, want 0（未交付不得记成功）", n)
	}
	failures := restoreRejectionAuditRows(t, "下载失败")
	if len(failures) != 1 {
		t.Fatalf("下载失败 审计行=%d, want 1", len(failures))
	}
	if want := fmt.Sprintf("备份 #%d", id); !strings.Contains(failures[0], want) {
		t.Fatalf("审计 detail=%q 必须含 %q", failures[0], want)
	}
}

// Given 备份行已消失。
// When DELETE /auto-backup/:id。
// Then 404 + 恰一条「删除失败」审计，且不记「备份删除」成功审计。
func TestDeleteAutoBackup_rowGoneAuditsRejection(t *testing.T) {
	h := newAutoBackupTestHandlers(t)
	router := rowAccessRouter(h)
	id, _ := seedManualBackup(t, h)
	deleteBackupRow(t, id)

	rec := httptest.NewRecorder()
	router.ServeHTTP(rec, httptest.NewRequest(http.MethodDelete, fmt.Sprintf("/api/v1/auto-backup/%d", id), nil))

	if rec.Code != http.StatusNotFound {
		t.Fatalf("status=%d body=%s, want 404", rec.Code, rec.Body.String())
	}
	if n := countAutoBackupAudit(t, "备份删除"); n != 0 {
		t.Fatalf("行不存在时「备份删除」审计行=%d, want 0", n)
	}
	failures := restoreRejectionAuditRows(t, "删除失败")
	if len(failures) != 1 {
		t.Fatalf("删除失败 审计行=%d, want 1", len(failures))
	}
	if want := fmt.Sprintf("备份 #%d", id); !strings.Contains(failures[0], want) {
		t.Fatalf("审计 detail=%q 必须含 %q", failures[0], want)
	}
}

// Given 行查询本身失败（DB 故障：auto_backups 不可读）。
// When POST restore。
// Then 500 固定文案（不回显 SQL 结构）+ 恰一条「还原失败」审计。
func TestRestoreAutoBackup_queryFailureAuditsRejectionWithoutLeak(t *testing.T) {
	h := newAutoBackupTestHandlers(t)
	router := rowAccessRouter(h)
	if _, err := db.DB.Exec(`DROP TABLE auto_backups`); err != nil {
		t.Fatalf("drop auto_backups: %v", err)
	}

	rec := httptest.NewRecorder()
	router.ServeHTTP(rec, httptest.NewRequest(http.MethodPost, "/api/v1/auto-backup/1/restore", nil))

	if rec.Code != http.StatusInternalServerError {
		t.Fatalf("status=%d body=%s, want 500", rec.Code, rec.Body.String())
	}
	if body := rec.Body.String(); !strings.Contains(body, "数据库错误") || strings.Contains(body, "auto_backups") {
		t.Fatalf("body=%s, want 固定文案且不含内部表名", body)
	}
	failures := restoreRejectionAuditRows(t, "还原失败")
	if len(failures) != 1 {
		t.Fatalf("还原失败 审计行=%d, want 1", len(failures))
	}
	if !strings.Contains(failures[0], "数据库错误") {
		t.Fatalf("审计 detail=%q, want 含 数据库错误 归因", failures[0])
	}
	if successes := restoreRejectionAuditRows(t, "还原"); len(successes) != 0 {
		t.Fatalf("被拒绝的还原不得留下成功审计: %v", successes)
	}
}
