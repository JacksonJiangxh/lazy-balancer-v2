package db

// 整表重建迁移必须清理「升级前旧构建」崩溃留下的临时表：旧构建逐语句自动
// 提交，半失败会残留 *_new/*_old/*_not_null，下一轮 CREATE/RENAME 直接报
// already exists → 每次重启都失败（启动死循环，只能人工 DROP）。事务化只覆盖
// 本轮 DDL 半失败的回滚，不覆盖历史残留。

import (
	"strings"
	"testing"
)

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

// 旧构建的崩溃窗口是「DROP 旧主表之后、RENAME 新表之前」：残留表此时是唯一
// 数据副本，而下次启动的 CREATE TABLE IF NOT EXISTS 已先建出空主表。清理动作
// 必须按主表状态裁决——主表为空而残留带行时中止迁移，不得静默删除唯一副本。
func TestMigrateCrawlerSourcesID_refusesToDropResidueHoldingOnlyRemainingData(t *testing.T) {
	database := openMigrationTestDB(t)
	// 崩溃残留形态：主表存在但为空（旧数据已被 DROP），残留带真实行。
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
	CREATE TABLE security_crawler_sources_with_id (id INTEGER PRIMARY KEY AUTOINCREMENT, name TEXT);
	INSERT INTO security_crawler_sources_with_id (name) VALUES ('googlebot');`); err != nil {
		t.Fatal(err)
	}

	err := migrateCrawlerSourcesID()
	if err == nil {
		t.Fatal("主表为空而残留带行时必须中止迁移（否则唯一数据副本被静默删除）")
	}
	if !strings.Contains(err.Error(), "security_crawler_sources_with_id") || !strings.Contains(err.Error(), "唯一数据副本") {
		t.Fatalf("error=%v, want 点名残留表并说明唯一数据副本风险", err)
	}

	var rows int
	if err := database.QueryRow("SELECT COUNT(*) FROM security_crawler_sources_with_id").Scan(&rows); err != nil {
		t.Fatalf("残留表必须保留: %v", err)
	}
	if rows != 1 {
		t.Fatalf("残留表行数=%d, want 1（唯一副本不得被删除）", rows)
	}
}
