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

// 插件写不进侧车时（磁盘满/目录只读、首写即失败 → 计数文件永不存在）必须
// 留下失败标记：根侧据标记判「写侧计数不可用」，而不是把文件缺失当正常。
func TestWriterStatsHealth_writeFailureMarkerBecomesUnavailable(t *testing.T) {
	dir := t.TempDir()
	oldPath := auditLogPath
	auditLogPath = filepath.Join(dir, "audit.log")
	t.Cleanup(func() { auditLogPath = oldPath })
	SecurityEventsSetIngestionHealthForTest(SecurityEventsIngestionStatus{Observed: true, Healthy: true})
	t.Cleanup(func() {
		SecurityEventsSetIngestionHealthForTest(SecurityEventsIngestionStatus{})
	})

	if err := os.WriteFile(securityEventsAuditWriterStatsFailurePath(), []byte("writer-stats sidecar write failed"), 0o644); err != nil {
		t.Fatal(err)
	}
	for range securityEventsWriterFailureThreshold {
		securityEventsObserveAuditWriterStats()
	}
	status := SecurityEventsIngestionHealthSnapshot()
	if !status.WriterStatsUnavailable || status.Healthy {
		t.Fatalf("failure marker: unavailable=%v healthy=%v, want unavailable+unhealthy", status.WriterStatsUnavailable, status.Healthy)
	}
	if status.WriterLastFailureAt == "" {
		t.Fatal("失败标记在场必须披露 writer_last_failure_at")
	}

	// 插件恢复写盘（标记清除）→ 下一轮观测即恢复可用。
	if err := os.Remove(securityEventsAuditWriterStatsFailurePath()); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(securityEventsAuditWriterStatsPath(), []byte(`{"dropped":0,"io_errors":0}`), 0o644); err != nil {
		t.Fatal(err)
	}
	securityEventsObserveAuditWriterStats()
	status = SecurityEventsIngestionHealthSnapshot()
	if status.WriterStatsUnavailable || !status.Healthy {
		t.Fatalf("marker cleared: unavailable=%v healthy=%v, want available+healthy", status.WriterStatsUnavailable, status.Healthy)
	}
}

// 侧车计数文件跨容器重启存活：早于本进程启动的 written_at 属于上一代进程，
// 必须整份忽略并复位基线。否则只要历史上出现过一次丢弃，重启后首个 tick
// 就把旧累计值当「本进程新失败」——degraded 15 分钟 + data_loss + 一条
// 「审计日志写侧失败」任务日志的误报；且新进程无失败时侧车永不重写，误报
// 长期存在。
func TestWriterStatsHealth_staleGenerationIgnored(t *testing.T) {
	dir := t.TempDir()
	oldPath := auditLogPath
	auditLogPath = filepath.Join(dir, "audit.log")
	t.Cleanup(func() { auditLogPath = oldPath })
	SecurityEventsSetIngestionHealthForTest(SecurityEventsIngestionStatus{Observed: true, Healthy: true})
	t.Cleanup(func() {
		SecurityEventsSetIngestionHealthForTest(SecurityEventsIngestionStatus{})
	})

	oldStart := securityEventsProcessStart
	securityEventsProcessStart = time.Now()
	t.Cleanup(func() { securityEventsProcessStart = oldStart })
	securityEventsWriterHealth.mu.Lock()
	securityEventsWriterHealth.baselineDropped = 0
	securityEventsWriterHealth.baselineIO = 0
	securityEventsWriterHealth.droppedTotal = 0
	securityEventsWriterHealth.ioTotal = 0
	securityEventsWriterHealth.windowStart = time.Time{}
	securityEventsWriterHealth.windowFailures = 0
	securityEventsWriterHealth.lastFailureAt = time.Time{}
	securityEventsWriterHealth.sidecarReadFailures = 0
	securityEventsWriterHealth.mu.Unlock()

	// 旧代际侧车：written_at 早于本进程启动，计数非零。
	stale := `{"dropped":7,"io_errors":3,"written_at":"` +
		securityEventsProcessStart.Add(-time.Hour).UTC().Format(time.RFC3339) + `"}`
	if err := os.WriteFile(securityEventsAuditWriterStatsPath(), []byte(stale), 0o644); err != nil {
		t.Fatal(err)
	}
	for range securityEventsWriterFailureThreshold + 1 {
		securityEventsObserveAuditWriterStats()
	}
	securityEventsWriterHealth.mu.Lock()
	dropped, ioErrors, windowFailures := securityEventsWriterHealth.droppedTotal,
		securityEventsWriterHealth.ioTotal, securityEventsWriterHealth.windowFailures
	securityEventsWriterHealth.mu.Unlock()
	if dropped != 0 || ioErrors != 0 || windowFailures != 0 {
		t.Fatalf("旧代际侧车必须整份忽略：dropped=%d io=%d windowFailures=%d", dropped, ioErrors, windowFailures)
	}
	status := SecurityEventsIngestionHealthSnapshot()
	if status.WriterDegraded || status.WriterDropped != 0 || status.WriterIOErrors != 0 {
		t.Fatalf("旧代际侧车不得判降级：degraded=%v dropped=%d io=%d",
			status.WriterDegraded, status.WriterDropped, status.WriterIOErrors)
	}

	// 本代际侧车（written_at 晚于进程启动）照常累计增量。
	fresh := `{"dropped":7,"io_errors":3,"written_at":"` +
		time.Now().UTC().Add(time.Second).Format(time.RFC3339) + `"}`
	if err := os.WriteFile(securityEventsAuditWriterStatsPath(), []byte(fresh), 0o644); err != nil {
		t.Fatal(err)
	}
	securityEventsObserveAuditWriterStats()
	securityEventsWriterHealth.mu.Lock()
	dropped, ioErrors = securityEventsWriterHealth.droppedTotal, securityEventsWriterHealth.ioTotal
	securityEventsWriterHealth.mu.Unlock()
	if dropped != 7 || ioErrors != 3 {
		t.Fatalf("本代际侧车必须累计：dropped=%d io=%d, want 7/3", dropped, ioErrors)
	}

	// 缺失 written_at 的旧版本产物退回基线差量口径（兼容形态，不得静默忽略）。
	legacy := `{"dropped":9,"io_errors":4}`
	if err := os.WriteFile(securityEventsAuditWriterStatsPath(), []byte(legacy), 0o644); err != nil {
		t.Fatal(err)
	}
	securityEventsObserveAuditWriterStats()
	securityEventsWriterHealth.mu.Lock()
	dropped = securityEventsWriterHealth.droppedTotal
	securityEventsWriterHealth.mu.Unlock()
	if dropped != 9 {
		t.Fatalf("无 written_at 的旧产物应按差量累计到 9，got %d", dropped)
	}
}

// 判据边界：written_at 只用于代际判定，**不得**按年龄判「写侧停摆/侧车停更」。
// 插件只在计数变化时重写侧车（无失败＝不写盘），陈旧 written_at 是无失败时的
// 正常形态；按年龄降级会在健康期长期误报（写侧真停摆无独立存活信号可观测）。
// 本用例把进程启动时间前移，使「1h 前的 written_at」属于本代际——任何按年龄
// 判停更的实现都会在此红。
func TestWriterStatsHealth_oldWrittenAtInCurrentGenerationIsNotStale(t *testing.T) {
	dir := t.TempDir()
	oldPath := auditLogPath
	auditLogPath = filepath.Join(dir, "audit.log")
	t.Cleanup(func() { auditLogPath = oldPath })
	SecurityEventsSetIngestionHealthForTest(SecurityEventsIngestionStatus{Observed: true, Healthy: true})
	t.Cleanup(func() {
		SecurityEventsSetIngestionHealthForTest(SecurityEventsIngestionStatus{})
	})

	oldStart := securityEventsProcessStart
	securityEventsProcessStart = time.Now().Add(-48 * time.Hour)
	t.Cleanup(func() { securityEventsProcessStart = oldStart })
	securityEventsWriterHealth.mu.Lock()
	securityEventsWriterHealth.baselineDropped = 0
	securityEventsWriterHealth.baselineIO = 0
	securityEventsWriterHealth.droppedTotal = 0
	securityEventsWriterHealth.ioTotal = 0
	securityEventsWriterHealth.windowStart = time.Time{}
	securityEventsWriterHealth.windowFailures = 0
	securityEventsWriterHealth.lastFailureAt = time.Time{}
	securityEventsWriterHealth.sidecarReadFailures = 0
	securityEventsWriterHealth.sidecarWriteFailureHits = 0
	securityEventsWriterHealth.mu.Unlock()

	// 本代际（晚于进程启动）但已 1h 未重写的侧车：无失败计数。
	stale := `{"dropped":0,"io_errors":0,"written_at":"` +
		time.Now().UTC().Add(-time.Hour).Format(time.RFC3339) + `"}`
	if err := os.WriteFile(securityEventsAuditWriterStatsPath(), []byte(stale), 0o644); err != nil {
		t.Fatal(err)
	}
	for range securityEventsWriterFailureThreshold + 1 {
		securityEventsObserveAuditWriterStats()
	}
	status := SecurityEventsIngestionHealthSnapshot()
	if status.WriterDegraded || status.WriterStatsUnavailable || !status.Healthy {
		t.Fatalf("陈旧但属本代际的 written_at 不得判停更/降级: degraded=%v unavailable=%v healthy=%v",
			status.WriterDegraded, status.WriterStatsUnavailable, status.Healthy)
	}
}
