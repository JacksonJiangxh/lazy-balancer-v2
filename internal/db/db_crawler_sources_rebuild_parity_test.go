package db

// security_crawler_sources 整表重建（初版漏 id 主键）此前是「整表重建」家族里
// 唯一没有 fresh↔rebuilt 逐列 parity 钉测的一张：重建 DDL 一旦漂移（只改 fresh
// + newColumns 忘了改重建），同启动的二次 ensureNewColumns 只会以列默认值补列
// ——爬虫源的开关/版本/失败计数/排程时间静默归零，无任何报错。同族先例：
// server_map_lat/lon、OIDC 三列、阶段拦截页四列。

import (
	"database/sql"
	"testing"
)

// legacyCrawlerSourcesDDL 是「初版漏 id 主键」的 security_crawler_sources 形态
// （17 列、无 id）。重建功能测试与 parity 钉测共用本单源，避免两份夹具漂移。
const legacyCrawlerSourcesDDL = `CREATE TABLE security_crawler_sources (
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
		trigger TEXT NOT NULL DEFAULT '',
		started_at DATETIME,
		finished_at DATETIME,
		consecutive_failures INTEGER NOT NULL DEFAULT 0,
		created_at DATETIME DEFAULT (datetime('now')),
		updated_at DATETIME DEFAULT (datetime('now'))
	)`

func createLegacyCrawlerSourcesTable(t *testing.T, database *sql.DB) {
	t.Helper()
	if _, err := database.Exec(legacyCrawlerSourcesDDL); err != nil {
		t.Fatalf("create legacy crawler sources fixture: %v", err)
	}
}

func TestCrawlerSourcesRebuildSchema_matchesFreshDDL(t *testing.T) {
	// Given fresh 稳态形状（createTables 的 CREATE 是权威列集合）。
	database := openMigrationTestDB(t)
	if err := createTables(); err != nil {
		t.Fatalf("create fresh tables: %v", err)
	}
	freshShape := tablePragmaShape(t, database, "security_crawler_sources")
	if _, err := database.Exec(`DROP TABLE security_crawler_sources`); err != nil {
		t.Fatalf("drop fresh crawler sources for legacy fixture: %v", err)
	}
	createLegacyCrawlerSourcesTable(t, database)
	if _, err := database.Exec(`INSERT INTO security_crawler_sources (name,display_name,url,format,update_enabled,entry_count,version)
		VALUES ('googlebot','爬虫机器人 Google','https://example.com/ips.json','json',0,170,'2026.10.16')`); err != nil {
		t.Fatalf("seed legacy crawler source: %v", err)
	}

	// When 真实升级路径整表重建。
	if err := migrateCrawlerSourcesID(); err != nil {
		t.Fatalf("rebuild crawler sources: %v", err)
	}

	// Then 重建列集合及 name/type/notnull/default/pk 与 fresh 逐列一致
	//（新增列只改一处 DDL 即在此失败，而不是静默丢值）。
	assertShapeMatchesFresh(t, "security_crawler_sources", freshShape, tablePragmaShape(t, database, "security_crawler_sources"))

	// And 运行态列保值（parity 只比形状，值由显式列拷贝保证）。
	var enabled, entryCount, failures int
	var version, status string
	if err := database.QueryRow(`SELECT update_enabled, entry_count, version, update_status, consecutive_failures
		FROM security_crawler_sources WHERE name='googlebot'`).Scan(&enabled, &entryCount, &version, &status, &failures); err != nil {
		t.Fatalf("read rebuilt crawler source: %v", err)
	}
	if enabled != 0 || entryCount != 170 || version != "2026.10.16" || status != "idle" || failures != 0 {
		t.Fatalf("重建后运行态列漂移: enabled=%d count=%d version=%q status=%q failures=%d", enabled, entryCount, version, status, failures)
	}
}
