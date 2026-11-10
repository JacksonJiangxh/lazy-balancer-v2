package handlers

import (
	"net/http"
	"strings"
	"testing"

	"lazy-balancer-v2/internal/services"
	"lazy-balancer-v2/internal/taskengine"
)

func TestRunAutoBackupNow_engineRoleRaceReturnsForbidden(t *testing.T) {
	// Given：HTTP 预检读取的 DB 仍为主节点，但引擎已在响应前降级。
	h := newAutoBackupTestHandlers(t)
	wireAutoBackupEngineForTest(t, h)
	services.TaskEngine().SetRole(false)

	// When：原子占位阶段返回主节点角色错误。
	response := serveAutoBackupJSON(t, h, http.MethodPost, "/auto-backup/run", "/auto-backup/run", "", h.RunAutoBackupNow)

	// Then：哨兵映射 403，不能落入通用 500，也不能返回 202 假受理。
	if response.Code != http.StatusForbidden {
		t.Fatalf("status=%d body=%s, want 403", response.Code, response.Body.String())
	}
	if !strings.Contains(response.Body.String(), taskengine.ErrNotMaster.Error()) {
		t.Fatalf("body=%s, want %q", response.Body.String(), taskengine.ErrNotMaster.Error())
	}
}
