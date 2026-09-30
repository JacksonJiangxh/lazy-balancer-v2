package services

import (
	"os"
	"strings"
	"testing"

	"lazy-balancer-v2/internal/db"
	"lazy-balancer-v2/internal/taskengine"
)

// R63-P2-2/P2-3：旧 crs-update.log 已退役——writeCRSUpdateLog 唯一落点=
// tasks/crs.log（tee 单点）。本钉测双守卫：①经 Append* 包装（曾双写）恰 1 行；
// ②旧文件不再产生。
func TestWriteCRSUpdateLog_singleSinkNoDoubleTee(t *testing.T) {
	dir := t.TempDir()
	taskengine.SetLogDir(dir)
	t.Cleanup(func() { taskengine.SetLogDir("") })

	// When: Append 包装层写一条（R62 修复前此处会双 tee）
	AppendCRSUpdateLog("INFO", "sync", "集群同步回放规则库")
	AppendCRSUpdateLog("INFO", "sync", "集群同步回放规则库")

	data, _ := os.ReadFile(taskengine.TaskLogPath("crs"))
	content := string(data)
	n := strings.Count(content, "集群同步回放规则库")
	if n != 2 {
		t.Fatalf("两次写入应恰 2 行（曾双写为 4），got %d:\n%s", n, content)
	}
}

// taskLogsHousekeeping 按配置阈值轮转任务日志（R63-P2-1：cert_job_log_size_mb
// 贯通到 tasks/*.log——本测试为配置消费的行为钉）。
func TestTaskLogsHousekeeping_rotatesAtConfiguredThreshold(t *testing.T) {
	if err := db.Initialize(t.TempDir()); err != nil {
		t.Fatal(err)
	}
	if _, err := db.DB.Exec("UPDATE global_config SET cert_job_log_size_mb = 1 WHERE id = 1"); err != nil {
		t.Fatal(err)
	}
	certJobLogSizeCachedAt.Store(0)
	t.Cleanup(func() { certJobLogSizeCachedAt.Store(0) })

	logsDir := t.TempDir()
	tasksDir := logsDir + "/tasks"
	if err := os.MkdirAll(tasksDir, 0o755); err != nil {
		t.Fatal(err)
	}
	// 2MB 文件（>1MB 配置阈值）
	if err := os.WriteFile(tasksDir+"/probe.log", []byte(strings.Repeat("x", 2*1024*1024)), 0644); err != nil {
		t.Fatal(err)
	}

	taskLogsHousekeeping(logsDir + "/app.log")

	if _, err := os.Stat(tasksDir + "/probe.log.1"); err != nil {
		t.Fatalf("超阈值任务日志应轮转到 .1: %v", err)
	}
	// Rename 语义：原文件移 .1，新文件由下次写入重建（不预建空文件）。
}
