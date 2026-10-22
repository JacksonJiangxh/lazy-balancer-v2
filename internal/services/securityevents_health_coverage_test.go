package services

import (
	"fmt"
	"os"
	"testing"
	"time"

	"lazy-balancer-v2/internal/taskengine"
)

// 采集健康位必须反映「任务已停」：任务已停用/未运行时，事件数据不再增长，
// 健康位不得继续显示 healthy（三处面板同源消费该快照）。
func TestSecurityEventsIngestionHealth_reflectsTaskState(t *testing.T) {
	previous := TaskEngine()
	te := taskengine.NewEngine(taskengine.Options{TickInterval: time.Hour})
	SetTaskEngineForTest(te)
	t.Cleanup(func() {
		te.StopWithTimeout(time.Second)
		SetTaskEngineForTest(previous)
		SecurityEventsSetIngestionHealthForTest(SecurityEventsIngestionStatus{})
	})
	if err := te.Register(taskengine.Descriptor{
		ID: "security-events-ingestion", Family: "system", Name: "安全事件采集",
		Kind: taskengine.KindDaemon,
		Run: func(rc taskengine.RunContext) error {
			<-rc.Ctx.Done()
			return nil
		},
	}); err != nil {
		t.Fatal(err)
	}
	SecurityEventsSetIngestionHealthForTest(SecurityEventsIngestionStatus{Observed: true, Healthy: true})

	// 任务未启动（调度关闭）：未采集 → 非 healthy，且任务态可区分。
	status := SecurityEventsIngestionHealthSnapshot()
	if status.TaskRunning {
		t.Fatalf("task_running=%v, want false before StartLoop", status.TaskRunning)
	}
	if status.TaskState != "stopped" {
		t.Fatalf("task_state=%q, want stopped", status.TaskState)
	}
	if status.Healthy {
		t.Fatalf("stopped task must not report healthy: %+v", status)
	}

	// 任务运行中：快照回归 tick 记账的 healthy。
	te.StartLoop("security-events-ingestion")
	deadline := time.Now().Add(2 * time.Second)
	for {
		if meta, ok := te.Lookup("security-events-ingestion"); ok && meta.Running {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("daemon did not reach running state")
		}
		time.Sleep(10 * time.Millisecond)
	}
	status = SecurityEventsIngestionHealthSnapshot()
	if !status.TaskRunning || status.TaskState != "running" {
		t.Fatalf("running task state=%q running=%v, want running", status.TaskState, status.TaskRunning)
	}
	if !status.Healthy {
		t.Fatalf("running task with a clean poll must stay healthy: %+v", status)
	}
}

// 审计写侧失败/丢弃（插件侧车计数）必须进入采集健康位：累计达阈值即降级，
// 下阈只披露计数；恢复后状态位复位。
func TestSecurityEventsPollOnce_auditWriterFailuresDegradeHealth(t *testing.T) {
	logPath, offsetPath := stallSetup(t)
	if err := os.WriteFile(logPath, nil, 0o644); err != nil {
		t.Fatal(err)
	}
	oldLogPath, oldOffsetPath := auditLogPath, securityEventsOffsetPath
	auditLogPath, securityEventsOffsetPath = logPath, offsetPath
	resetSecurityEventsPollState(t)
	SecurityEventsSetIngestionHealthForTest(SecurityEventsIngestionStatus{})
	t.Cleanup(func() {
		auditLogPath, securityEventsOffsetPath = oldLogPath, oldOffsetPath
		SecurityEventsSetIngestionHealthForTest(SecurityEventsIngestionStatus{})
	})

	writeWriterStats := func(dropped, ioErrors uint64) {
		t.Helper()
		body := fmt.Sprintf(`{"dropped":%d,"io_errors":%d,"written_at":%q}`, dropped, ioErrors, time.Now().UTC().Format(time.RFC3339))
		if err := os.WriteFile(securityEventsAuditWriterStatsPath(), []byte(body), 0o644); err != nil {
			t.Fatal(err)
		}
	}

	// 下阈：1 条丢弃 → 计数披露，健康位保持。
	writeWriterStats(1, 0)
	if _, err := SecurityEventsPollOnce(); err != nil {
		t.Fatalf("poll: %v", err)
	}
	status := SecurityEventsIngestionHealthSnapshot()
	if status.WriterDropped != 1 || status.WriterIOErrors != 0 {
		t.Fatalf("writer counters=%d/%d, want 1/0", status.WriterDropped, status.WriterIOErrors)
	}
	if status.WriterDegraded || !status.Healthy {
		t.Fatalf("below-threshold writer failures must not degrade: %+v", status)
	}

	// 达阈值：累计 3 条丢弃 → 降级（健康位与面板同一位）。
	writeWriterStats(3, 0)
	if _, err := SecurityEventsPollOnce(); err != nil {
		t.Fatalf("poll: %v", err)
	}
	status = SecurityEventsIngestionHealthSnapshot()
	if status.WriterDropped != 3 || !status.WriterDegraded || status.Healthy {
		t.Fatalf("threshold writer failures must degrade health: %+v", status)
	}
	if status.WriterLastFailureAt == "" {
		t.Fatalf("writer_last_failure_at must be set: %+v", status)
	}

	// 插件进程重启（计数器回落）：按新基线继续累计，不产生负增量假告警。
	writeWriterStats(0, 0)
	if _, err := SecurityEventsPollOnce(); err != nil {
		t.Fatalf("poll: %v", err)
	}
	status = SecurityEventsIngestionHealthSnapshot()
	if status.WriterDropped != 3 {
		t.Fatalf("counter reset must not lose accumulated failures: %+v", status)
	}
}
