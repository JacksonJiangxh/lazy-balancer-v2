package services

// 排程/配置读失败必须经 logScheduleReadFailure 单源留痕（首报
// warn + 恢复 info）——自动备份槽位计算与启用源最早槽两处此前静默归零，
// 库故障窗口任务「静默停摆」零信号。

import (
	"strings"
	"testing"
	"time"

	"lazy-balancer-v2/internal/db"
)

func TestScheduleReads_readFailureLeavesWarnTrace(t *testing.T) {
	newClusterTestService(t)
	for _, key := range []string{"schedule-read-auto-backup", "schedule-earliest-security_threat_sources"} {
		delete(metricsStateFailed, key)
	}
	t.Cleanup(func() {
		delete(metricsStateFailed, "schedule-read-auto-backup")
		delete(metricsStateFailed, "schedule-earliest-security_threat_sources")
	})
	if err := db.DB.Close(); err != nil {
		t.Fatalf("close db: %v", err)
	}
	buf := captureLogf(t)

	// 两处读取各失败两次：首报警告各一条，重复不刷屏。
	if _, ok := nextAutoBackupSlot(time.Now()); ok {
		t.Fatal("closed DB must yield no slot")
	}
	nextAutoBackupSlot(time.Now())
	if got := earliestEnabledSourceUpdate("security_threat_sources"); got != "" {
		t.Fatalf("closed DB must yield empty earliest slot, got %q", got)
	}
	earliestEnabledSourceUpdate("security_threat_sources")

	out := buf.String()
	if strings.Count(out, "schedule-read-auto-backup") != 1 {
		t.Fatalf("auto-backup schedule read failure warn count wrong\n%s", out)
	}
	if strings.Count(out, "schedule-earliest-security_threat_sources") != 1 {
		t.Fatalf("earliest source read failure warn count wrong\n%s", out)
	}
}
