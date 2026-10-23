package taskengine

// 终态 UPDATE 的一次瞬时失败（SQLITE_BUSY/瞬断）必须有界重试：无条件放弃会
// 让该行滞留 running，任务视图恒显「运行中」并禁用「运行」按钮，直到进程
// 重启才被孤儿回收。

import (
	"database/sql"
	"errors"
	"testing"

	"lazy-balancer-v2/internal/db"
)

func seedRunningRun(t *testing.T) int64 {
	t.Helper()
	newTestEngine(t)
	res, err := db.DB.Exec(`INSERT INTO task_runs (task_id, family, trigger, status, started_at)
		VALUES ('t-retry', 't', 'auto', 'running', datetime('now'))`)
	if err != nil {
		t.Fatal(err)
	}
	runID, err := res.LastInsertId()
	if err != nil {
		t.Fatal(err)
	}
	return runID
}

func runStatus(t *testing.T, runID int64) string {
	t.Helper()
	var status string
	if err := db.DB.QueryRow(`SELECT status FROM task_runs WHERE id=?`, runID).Scan(&status); err != nil {
		t.Fatal(err)
	}
	return status
}

func TestUpdateTaskRunTerminal_retriesTransientFailure(t *testing.T) {
	runID := seedRunningRun(t)
	orig := taskRunTerminalExec
	t.Cleanup(func() { taskRunTerminalExec = orig })
	attempts := 0
	taskRunTerminalExec = func(query string, args ...any) (sql.Result, error) {
		attempts++
		if attempts == 1 {
			return nil, errors.New("注入的瞬时失败")
		}
		return db.DB.Exec(query, args...)
	}

	updateTaskRunTerminal(runID, "success", 7, "")

	if attempts != 2 {
		t.Fatalf("首次失败后应重试一次（共 2 次），got %d", attempts)
	}
	if status := runStatus(t, runID); status != "success" {
		t.Fatalf("瞬时失败后重试应落终态 success, got %q", status)
	}
}

func TestUpdateTaskRunTerminal_boundedOnPersistentFailure(t *testing.T) {
	runID := seedRunningRun(t)
	orig := taskRunTerminalExec
	t.Cleanup(func() { taskRunTerminalExec = orig })
	attempts := 0
	taskRunTerminalExec = func(string, ...any) (sql.Result, error) {
		attempts++
		return nil, errors.New("注入的持续失败")
	}

	updateTaskRunTerminal(runID, "failed", 7, "")

	if attempts != terminalWriteAttempts {
		t.Fatalf("持续失败应有界重试 %d 次后放弃, got %d", terminalWriteAttempts, attempts)
	}
	if status := runStatus(t, runID); status != "running" {
		t.Fatalf("持续失败时行保持原状（由视图按残留呈现/重启回收）, got %q", status)
	}
}
