package db

// 整表重建迁移必须清理「升级前旧构建」崩溃留下的临时表：旧构建逐语句自动
// 提交，半失败会残留 *_new/*_old/*_not_null，下一轮 CREATE/RENAME 直接报
// already exists → 每次重启都失败（启动死循环，只能人工 DROP）。事务化只覆盖
// 本轮 DDL 半失败的回滚，不覆盖历史残留。

import "testing"

func TestMigrateCrawlerSourcesID_clearsLegacyBuildResidue(t *testing.T) {
	database := openMigrationTestDB(t)
	// 初版建表形态：无 id 主键（触发重建）。
	if _, err := database.Exec(`CREATE TABLE security_crawler_sources (
		name TEXT NOT NULL UNIQUE,
		display_name TEXT NOT NULL DEFAULT '',
		url TEXT NOT NULL DEFAULT '',
		format TEXT NOT NULL DEFAULT 'plain',
		update_enabled INTEGER NOT NULL DEFAULT 1,
		entry_count INTEGER NOT NULL DEFAULT 0,
		version TEXT NOT NULL DEFAULT '',
		update_status TEXT NOT NULL DEFAULT 'idle',
		message TEXT NOT NULL DEFAULT '',
		last_checked DATETIME,
		next_update DATETIME,
		"trigger" TEXT NOT NULL DEFAULT '',
		started_at DATETIME,
		finished_at DATETIME,
		consecutive_failures INTEGER NOT NULL DEFAULT 0,
		created_at DATETIME DEFAULT (datetime('now')),
		updated_at DATETIME DEFAULT (datetime('now'))
	);
	INSERT INTO security_crawler_sources (name, display_name, entry_count) VALUES ('googlebot','Googlebot',42);
	CREATE TABLE security_crawler_sources_with_id (name TEXT);`); err != nil {
		t.Fatal(err)
	}

	if err := migrateCrawlerSourcesID(); err != nil {
		t.Fatalf("残留临时表必须被清理后重建成功: %v", err)
	}

	var hasID int
	if err := database.QueryRow("SELECT COUNT(*) FROM pragma_table_info('security_crawler_sources') WHERE name='id'").Scan(&hasID); err != nil {
		t.Fatal(err)
	}
	if hasID != 1 {
		t.Fatal("重建后必须带 id 主键")
	}
	var count, entries int
	if err := database.QueryRow(`SELECT COUNT(*), COALESCE(MAX(entry_count),0) FROM security_crawler_sources WHERE name='googlebot'`).Scan(&count, &entries); err != nil {
		t.Fatal(err)
	}
	if count != 1 || entries != 42 {
		t.Fatalf("源行未保留：count=%d entries=%d", count, entries)
	}
}
