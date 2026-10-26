package handlers

// 设置族的提交失败收尾此前没有行为钉测（只有源码结构门）：txCommitForTest 缝
// 存在，但没人真的走过「提交失败 → 恢复 → 横幅/审计/响应」。参数错位（把
// recovery.db 误传给 runtimeErr）会让横幅在下一次成功 apply 之前持续谎报
// 「运行配置状态未知」，而测试全绿。
//
// 两种形态逐一对齐规则族口径：
//   - 提交失败 + 恢复成功 = 库态/运行态一致：不写横幅，但「重载」审计在册；
//   - 提交失败 + 恢复失败 = 分叉：横幅用提交口径 + 「运行配置状态未知」标签，
//     且系统审计动作是「保存失败」（不是「应用失败」）。

import (
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"

	"github.com/gin-gonic/gin"

	"lazy-balancer-v2/internal/db"
	"lazy-balancer-v2/internal/services"
)

func newSettingsCommitFailureHandlers(t *testing.T, dropLoads ...int) *Handlers {
	t.Helper()
	handler := newBackupTestHandlers(t)
	_, fake := newApplyThenDropServer(t, dropLoads...)
	service := services.NewCaddyService(fake.URL)
	service.SetLastGoodPath(filepath.Join(t.TempDir(), "last_good.json"))
	handler.caddyService = service
	return handler
}

func putSettingsForCommitFailure(t *testing.T, handler *Handlers) *httptest.ResponseRecorder {
	t.Helper()
	gin.SetMode(gin.TestMode)
	router := gin.New()
	router.PUT("/config", handler.UpdateConfig)
	request := httptest.NewRequest(http.MethodPut, "/config", strings.NewReader(`{"request_body_max_size_mb":9}`))
	request.Header.Set("Content-Type", "application/json")
	response := httptest.NewRecorder()
	router.ServeHTTP(response, request)
	return response
}

func TestUpdateConfig_commitFailureRestoreOKNoBanner(t *testing.T) {
	handler := newSettingsCommitFailureHandlers(t)
	forceCommitFailure(t)
	response := putSettingsForCommitFailure(t, handler)

	if response.Code != http.StatusInternalServerError {
		t.Fatalf("status=%d body=%s, want 500", response.Code, response.Body.String())
	}
	if !strings.Contains(response.Body.String(), commitUncertainLabel) {
		t.Fatalf("响应未表述提交结果不确定: %s", response.Body.String())
	}
	if banner := readApplyError(t); banner != "" {
		t.Fatalf("恢复成功不得写横幅（库态与运行态一致），got %q", banner)
	}
	var rows int
	if err := db.AuditDB.QueryRow(`SELECT COUNT(*) FROM audit_log WHERE action='重载' AND resource='Caddy服务'`).Scan(&rows); err != nil {
		t.Fatalf("统计重载审计: %v", err)
	}
	if rows == 0 {
		t.Fatal("真实 /load 已发生，提交失败不得豁免「重载」留痕")
	}
}

func TestUpdateConfig_commitFailureRestoreFailWritesSaveBanner(t *testing.T) {
	// 第 2 次 /load = 已提交视图恢复，掐断它 → 运行配置恢复失败。
	handler := newSettingsCommitFailureHandlers(t, 2)
	forceCommitFailure(t)
	response := putSettingsForCommitFailure(t, handler)

	if response.Code != http.StatusInternalServerError {
		t.Fatalf("status=%d body=%s, want 500", response.Code, response.Body.String())
	}
	banner := readApplyError(t)
	if !strings.Contains(banner, postCommitSaveFailedBanner) {
		t.Fatalf("横幅=%q, want 提交口径（%s）", banner, postCommitSaveFailedBanner)
	}
	if !strings.Contains(banner, caddyApplyRestoreFailedLabel) {
		t.Fatalf("横幅=%q, want 「%s」（恢复失败不得声称旧配置已保留）", banner, caddyApplyRestoreFailedLabel)
	}
	// 系统审计的动作列必须随失败对象走（提交失败不是配置应用失败）。
	var action string
	if err := db.AuditDB.QueryRow(`SELECT action FROM audit_log WHERE detail LIKE ? ORDER BY id DESC LIMIT 1`, "%"+postCommitSaveFailedBanner+"%").Scan(&action); err != nil {
		t.Fatalf("读取提交失败审计: %v", err)
	}
	if action != "保存失败" {
		t.Fatalf("系统审计动作=%q, want 保存失败", action)
	}
}
