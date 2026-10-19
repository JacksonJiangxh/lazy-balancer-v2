package db

// 历史问题（历史）：ensureNewColumns 的 ADD COLUMN 与一次性回填必须
// 原子——此前各自自动提交，ALTER 成功后回填失败/进程被杀会让「列已存在」
// 成为下次启动的跳过判据，回填永久丢失（mfa_challenges.password_version
// 会让存量挑战按 0 校验；upstream_keepalive_timeout 残留旧默认 60）。

import "testing"

func TestEnsureNewColumns_alterAndBackfillAreAtomic(t *testing.T) {
	database := openMigrationTestDB(t)
	if _, err := database.Exec(`CREATE TABLE probe (id INTEGER PRIMARY KEY, value INTEGER)`); err != nil {
		t.Fatalf("create probe table: %v", err)
	}
	if _, err := database.Exec(`INSERT INTO probe (id,value) VALUES (1,5)`); err != nil {
		t.Fatalf("seed probe row: %v", err)
	}

	columns := map[string]string{"probe.added": "INTEGER DEFAULT 0"}
	brokenBackfill := map[string]string{"probe.added": "UPDATE no_such_table SET x=1"}

	// When：回填失败（模拟 ALTER 后崩溃/回填语句错误）。
	if err := ensureNewColumns(columns, brokenBackfill); err == nil {
		t.Fatal("回填失败必须向上返回错误")
	}

	// Then：ALTER 随事务回滚——列不存在，下次启动可原样重试。
	var columnCount int
	if err := database.QueryRow(`SELECT COUNT(*) FROM pragma_table_info('probe') WHERE name='added'`).Scan(&columnCount); err != nil {
		t.Fatalf("inspect probe columns: %v", err)
	}
	if columnCount != 0 {
		t.Fatal("回填失败后列仍存在——ADD COLUMN 未与回填同事务，回填将永久跳过")
	}

	// And：重试（有效回填）后列存在且回填生效。
	if err := ensureNewColumns(columns, map[string]string{"probe.added": "UPDATE probe SET added=7"}); err != nil {
		t.Fatalf("retry ensureNewColumns: %v", err)
	}
	var added int
	if err := database.QueryRow(`SELECT added FROM probe WHERE id=1`).Scan(&added); err != nil {
		t.Fatalf("read backfilled column: %v", err)
	}
	if added != 7 {
		t.Fatalf("backfilled value=%d, want 7", added)
	}
}
