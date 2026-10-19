package db

import (
	"strings"
	"testing"
)

func indexExists(t *testing.T, name string) bool {
	t.Helper()
	var n int
	if err := DB.QueryRow(`SELECT COUNT(*) FROM sqlite_master WHERE type='index' AND name=?`, name).Scan(&n); err != nil {
		t.Fatalf("query index %s: %v", name, err)
	}
	return n > 0
}

// 迁移停止创建，存量库由迁移 DROP INDEX 回收。
func TestRunMigrations_dropsDeadNodesStatusIndex(t *testing.T) {
	// Given：存量库形态（历史版本创建的死索引仍在）。
	database := openMigrationTestDB(t)
	if err := createTables(); err != nil {
		t.Fatalf("create tables: %v", err)
	}
	if _, err := database.Exec("INSERT INTO global_config (id,caddy_config) VALUES (1,'{}')"); err != nil {
		t.Fatalf("seed global config: %v", err)
	}
	if _, err := database.Exec(`CREATE INDEX IF NOT EXISTS idx_nodes_status ON nodes(status)`); err != nil {
		t.Fatalf("seed legacy index: %v", err)
	}
	if !indexExists(t, "idx_nodes_status") {
		t.Fatal("前置条件失败：死索引未建立")
	}

	// When
	if err := runMigrations(); err != nil {
		t.Fatalf("run migrations: %v", err)
	}

	// Then：死索引被删除且不再被任何 DDL/重建路径创建。
	if indexExists(t, "idx_nodes_status") {
		t.Fatal("idx_nodes_status 死索引应在迁移后删除")
	}
}

// RunOverview 的「每任务最新行」查询（id IN (SELECT MAX(id) ... GROUP BY
// task_id)）必须走覆盖索引，不得全表扫描。只断言「索引存在」不足——列序写反
// 改为直接引用生产常量 db.TaskRunsLatestPerTaskQuery（taskengine.RunOverview
// 同一常量消费），不再从生产源文件按反引号切片文本。
func TestRunMigrations_createsTaskRunsLatestIndex(t *testing.T) {
	database := openMigrationTestDB(t)
	if err := createTables(); err != nil {
		t.Fatalf("create tables: %v", err)
	}
	if _, err := database.Exec("INSERT INTO global_config (id,caddy_config) VALUES (1,'{}')"); err != nil {
		t.Fatalf("seed global config: %v", err)
	}
	if err := runMigrations(); err != nil {
		t.Fatalf("run migrations: %v", err)
	}
	if !indexExists(t, "idx_task_runs_task_latest") {
		t.Fatal("idx_task_runs_task_latest 必须存在（每任务最新行免全表扫描）")
	}

	plan := queryPlan(t, TaskRunsLatestPerTaskQuery)
	if !strings.Contains(plan, "USING COVERING INDEX idx_task_runs_task_latest") {
		t.Fatalf("RunOverview 查询计划未使用覆盖索引（索引列序/查询形态漂移）:\n%s", plan)
	}
	if strings.Contains(plan, "SCAN task_runs\n") || strings.HasSuffix(plan, "SCAN task_runs") {
		t.Fatalf("RunOverview 查询仍含全表 SCAN task_runs:\n%s", plan)
	}
}

// queryPlan 执行 EXPLAIN QUERY PLAN 并把 detail 列拼成单串。
func queryPlan(t *testing.T, query string) string {
	t.Helper()
	rows, err := DB.Query("EXPLAIN QUERY PLAN " + query)
	if err != nil {
		t.Fatalf("EXPLAIN QUERY PLAN: %v", err)
	}
	defer rows.Close()
	var lines []string
	for rows.Next() {
		var id, parent, notUsed int
		var detail string
		if err := rows.Scan(&id, &parent, &notUsed, &detail); err != nil {
			t.Fatalf("scan plan row: %v", err)
		}
		lines = append(lines, detail)
	}
	if err := rows.Err(); err != nil {
		t.Fatalf("iterate plan rows: %v", err)
	}
	if len(lines) == 0 {
		t.Fatal("EXPLAIN QUERY PLAN 无输出")
	}
	return strings.Join(lines, "\n")
}
