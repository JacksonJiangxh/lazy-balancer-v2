package handlers

// U1-P3-1（第 67 轮审计，P3）：7/12 可手动触发族手动触发在 audit_log 无痕——
// AuditPolicySkip 的前提「任务体 defer 单记审计」（R63 时仅 3 自记族）随 v2.0
// 可触发族扩容失效：现 12 族中 5 族自记（threat/crs/ip2region 任务体 defer +
// auto-backup 执行器 + startup:config-load 载入审计），7 族任务体零审计
// （log-cleanup/audit-retention/security-events-retention/cert-renewal-scan/
// cert-reconcile/cert-manual-poll/cert-waiting-ca）。自动执行有审计（自记族）
// 而手动（更高特权）反而无痕的倒挂随 trigger 路由整族豁免固化。
// 修复口径：trigger handler 对非自记族显式补记「触发/任务监控」，自记族复记
// 会违反 U1-P3-2 单记裁定（2026-09-29 用户裁定），必须跳过。

import (
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"lazy-balancer-v2/internal/db"
)

// countTriggerAudit 统计「触发/任务监控」审计行数。
func countTriggerAudit(t *testing.T) int {
	t.Helper()
	var n int
	if err := db.AuditDB.QueryRow(`SELECT COUNT(*) FROM audit_log WHERE action='触发' AND resource='任务监控'`).Scan(&n); err != nil {
		t.Fatalf("count trigger audit: %v", err)
	}
	return n
}

// Given 非自记族 log-cleanup（任务体零 RecordAuditLog）与主节点库。
// When POST /system/tasks/log-cleanup/trigger 手动触发。
// Then audit_log 必须留痕（动作「触发」/对象「任务监控」）——现实现零记录（RED）。
func TestTriggerSystemTask_nonSelfRecordingTriggerLeavesAudit(t *testing.T) {
	initTaskEngineForTest(t)
	newBackupTestHandlers(t)
	r, _ := taskMonitorRouter()

	resp := httptest.NewRecorder()
	r.ServeHTTP(resp, httptest.NewRequest(http.MethodPost, "/system/tasks/log-cleanup/trigger", nil))
	if resp.Code != http.StatusOK {
		t.Fatalf("log-cleanup 手动触发应 200, got %d %s", resp.Code, resp.Body.String())
	}
	if n := countTriggerAudit(t); n == 0 {
		t.Fatal("手动触发非自记族 log-cleanup 在 audit_log 无痕——高特权操作零追责")
	}
}

// 回归形状：自记族 auto-backup（执行器注入点，测试环境未注入→任务体立即失败
// 且零审计）手动触发时 handler 不得复记——否则与任务体 defer/执行器审计构成
// 双记，违反 U1-P3-2（2026-09-29 用户裁定）的单记口径。
func TestTriggerSystemTask_selfRecordingTriggerSkipsHandlerAudit(t *testing.T) {
	initTaskEngineForTest(t)
	newBackupTestHandlers(t)
	r, _ := taskMonitorRouter()

	resp := httptest.NewRecorder()
	r.ServeHTTP(resp, httptest.NewRequest(http.MethodPost, "/system/tasks/auto-backup/trigger", nil))
	if resp.Code != http.StatusOK {
		t.Fatalf("auto-backup 手动触发应 200, got %d %s", resp.Code, resp.Body.String())
	}
	if n := countTriggerAudit(t); n != 0 {
		t.Fatalf("自记族 auto-backup 的 handler 复记会产生双审计（U1-P3-2 单记裁定）, got %d 行", n)
	}
}

// countTriggerFailAudit 统计「触发失败」补偿审计行数。
func countTriggerFailAudit(t *testing.T) int {
	t.Helper()
	var n int
	if err := db.AuditDB.QueryRow(`SELECT COUNT(*) FROM audit_log WHERE action='触发失败'`).Scan(&n); err != nil {
		t.Fatalf("count trigger-fail audit: %v", err)
	}
	return n
}

// F-U3-01+F-U1-1（第 68 轮）：四处 go 闭包 te.Trigger 错误被吞——非自记族已
// 补记「触发」但 Trigger 失败时任务未执行，审计只剩孤儿行；自记族零痕迹。
// 修复：go 内 err 非 nil 时补记「触发失败」审计+日志（operator 闭包外预取——
// gin.Context 在 handler 返回后被复用，闭包内读是竞态）。
//
// Given 自动备份执行器未注入（测试环境任务体立即失败→te.Trigger 回传错误）。
// When POST /system/tasks/auto-backup/trigger 手动触发。
// Then 必须补记「触发失败」补偿审计（现实现零——RED）。
func TestTriggerSystemTask_triggerFailureLeavesCompensationAudit(t *testing.T) {
	initTaskEngineForTest(t)
	newBackupTestHandlers(t)
	r, _ := taskMonitorRouter()

	resp := httptest.NewRecorder()
	r.ServeHTTP(resp, httptest.NewRequest(http.MethodPost, "/system/tasks/auto-backup/trigger", nil))
	if resp.Code != http.StatusOK {
		t.Fatalf("auto-backup 手动触发应 200, got %d %s", resp.Code, resp.Body.String())
	}
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		if countTriggerFailAudit(t) > 0 {
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatal("Trigger 失败路径零补偿审计——任务未执行/失败无痕（孤儿审计）")
}
