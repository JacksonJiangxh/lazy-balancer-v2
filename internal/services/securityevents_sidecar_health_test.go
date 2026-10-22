package services

import (
	"os"
	"path/filepath"
	"testing"
	"time"
)

// 侧车计数文件连续读取/解析失败达阈值 =「写侧计数不可用」：磁盘满/目录只读
// 正是侧车要覆盖的故障形态，双向失效时写侧丢弃/IO 计数恒 0——不可用事实
// 必须进健康位（healthy=false + writer_stats_unavailable），不得保持假绿。
func TestWriterStatsHealth_sidecarUnreadableBecomesUnavailable(t *testing.T) {
	dir := t.TempDir()
	oldPath := auditLogPath
	auditLogPath = filepath.Join(dir, "audit.log")
	t.Cleanup(func() { auditLogPath = oldPath })
	SecurityEventsSetIngestionHealthForTest(SecurityEventsIngestionStatus{Observed: true, Healthy: true})
	t.Cleanup(func() {
		SecurityEventsSetIngestionHealthForTest(SecurityEventsIngestionStatus{})
	})

	// 侧车路径上放目录 → ReadFile 持续失败（非 ErrNotExist）。
	if err := os.Mkdir(securityEventsAuditWriterStatsPath(), 0o755); err != nil {
		t.Fatal(err)
	}
	for range securityEventsWriterFailureThreshold {
		securityEventsObserveAuditWriterStats()
	}
	status := SecurityEventsIngestionHealthSnapshot()
	if !status.WriterStatsUnavailable || status.Healthy {
		t.Fatalf("sidecar unreadable: unavailable=%v healthy=%v, want unavailable+unhealthy（假绿）", status.WriterStatsUnavailable, status.Healthy)
	}

	// 恢复可读 → 下一轮观测即恢复可用。
	if err := os.Remove(securityEventsAuditWriterStatsPath()); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(securityEventsAuditWriterStatsPath(), []byte(`{"dropped":0,"io_errors":0}`), 0o644); err != nil {
		t.Fatal(err)
	}
	securityEventsObserveAuditWriterStats()
	status = SecurityEventsIngestionHealthSnapshot()
	if status.WriterStatsUnavailable || !status.Healthy {
		t.Fatalf("sidecar recovered: unavailable=%v healthy=%v, want available+healthy", status.WriterStatsUnavailable, status.Healthy)
	}

	// 文件缺失（插件未产生失败）是正常形态：不计失败、不降级。
	if err := os.Remove(securityEventsAuditWriterStatsPath()); err != nil {
		t.Fatal(err)
	}
	for range securityEventsWriterFailureThreshold + 1 {
		securityEventsObserveAuditWriterStats()
	}
	if status := SecurityEventsIngestionHealthSnapshot(); status.WriterStatsUnavailable {
		t.Fatal("missing sidecar（无失败信号）不得判不可用")
	}
}

// data_loss 与 degraded 分离表达：窗口滑出后 degraded 恢复（不再「正在失败」），
// 但曾发生的丢弃/写盘错误/畸形区跳过是永久事实——data_loss 保持 true 直至
// 进程重启/测试重置，前端据此区分「正在失败」与「曾丢失 N 条」。
func TestIngestionHealth_dataLossOutlivesDegradedWindow(t *testing.T) {
	SecurityEventsSetIngestionHealthForTest(SecurityEventsIngestionStatus{Observed: true, Healthy: true})
	t.Cleanup(func() {
		SecurityEventsSetIngestionHealthForTest(SecurityEventsIngestionStatus{})
	})
	// 曾发生写侧丢弃，但失败窗口已滑出（15min 前）。
	securityEventsWriterHealth.mu.Lock()
	securityEventsWriterHealth.droppedTotal = 5
	securityEventsWriterHealth.windowStart = time.Now().Add(-securityEventsWriterFailureWindow - time.Minute)
	securityEventsWriterHealth.windowFailures = securityEventsWriterFailureThreshold
	securityEventsWriterHealth.lastFailureAt = time.Now().Add(-securityEventsWriterFailureWindow - time.Minute)
	securityEventsWriterHealth.mu.Unlock()

	status := SecurityEventsIngestionHealthSnapshot()
	if status.WriterDegraded {
		t.Fatal("窗口滑出后 degraded 必须恢复 false")
	}
	if !status.DataLoss {
		t.Fatal("曾丢失事件（droppedTotal>0）必须保持 data_loss=true，不得随窗口滑出消失")
	}
	if !status.Healthy {
		t.Fatal("窗口滑出且无新失败时 healthy 保持 true（丢失事实经 data_loss 表达）")
	}

	// 畸形区跳过同样计入 data_loss。
	securityEventsRecordSkips(128, 1)
	securityEventsWriterHealth.mu.Lock()
	securityEventsWriterHealth.droppedTotal = 0
	securityEventsWriterHealth.ioTotal = 0
	securityEventsWriterHealth.windowStart = time.Now().Add(-securityEventsWriterFailureWindow - time.Minute)
	securityEventsWriterHealth.windowFailures = 0
	securityEventsWriterHealth.mu.Unlock()
	securityEventsSkipHealth.mu.Lock()
	securityEventsSkipHealth.windowStart = time.Now().Add(-securityEventsWriterFailureWindow - time.Minute)
	securityEventsSkipHealth.mu.Unlock()
	if status := SecurityEventsIngestionHealthSnapshot(); !status.DataLoss {
		t.Fatal("畸形区跳过累计>0 也必须保持 data_loss=true")
	}
}
