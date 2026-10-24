package db

// caddy_id 在旧库无唯一约束（仅主键重建后成为 PK）：存量重复行会让重建的
// INSERT 主键冲突 → 回滚 → runMigrations 上抛 → 启动永久失败。重建前必须
// 先去重（与 nodes/cert_jobs 同族），保留最近更新者并聚合留痕。

import (
	"context"
	"testing"
)

func TestMigrateLbRulesPrimaryKey_dedupesDuplicateCaddyID(t *testing.T) {
	database := openMigrationTestDB(t)
	// 真实旧形态：PK=id，两行同 caddy_id（旧版本导入/手改可达）。
	createLegacyLbRulesTables(t, database, legacyLbRulesSchema{withCaddyID: true, withStagePages: true, withNewHealthCols: true, upstreams: legacyUpstreamsMinimal})
	if _, err := database.Exec(`INSERT INTO lb_rules (id,name,protocol,listen_port,updated_at,caddy_id) VALUES
		(1,'older','http',8080,'2026-01-01 00:00:00','lb_dup'),
		(2,'newer','http',8080,'2026-06-01 00:00:00','lb_dup');
		INSERT INTO upstreams (id,rule_id,host,port) VALUES (1,2,'127.0.0.1',8080)`); err != nil {
		t.Fatal(err)
	}

	if err := migrateLbRulesPrimaryKey(); err != nil {
		t.Fatalf("重复 caddy_id 必须先去重而非让重建失败: %v", err)
	}

	var count int
	if err := database.QueryRow(`SELECT COUNT(*) FROM lb_rules WHERE caddy_id='lb_dup'`).Scan(&count); err != nil {
		t.Fatal(err)
	}
	if count != 1 {
		t.Fatalf("caddy_id='lb_dup' 行数=%d, want 1", count)
	}
	var name, pk string
	if err := database.QueryRow(`SELECT name FROM lb_rules WHERE caddy_id='lb_dup'`).Scan(&name); err != nil {
		t.Fatal(err)
	}
	if name != "newer" {
		t.Fatalf("保留行 name=%q, want 最近更新者 newer", name)
	}
	if err := database.QueryRow("SELECT name FROM pragma_table_info('lb_rules') WHERE pk = 1").Scan(&pk); err != nil {
		t.Fatal(err)
	}
	if pk != "caddy_id" {
		t.Fatalf("primary key=%q, want caddy_id", pk)
	}
	var upstreams int
	if err := database.QueryRow(`SELECT COUNT(*) FROM upstreams WHERE rule_id='lb_dup'`).Scan(&upstreams); err != nil {
		t.Fatal(err)
	}
	if upstreams != 1 {
		t.Fatalf("upstream 行数=%d, want 1（caddy_id 关联不受去重影响）", upstreams)
	}

	// 去重留痕：审计必须点名重复的 caddy_id。
	ids, err := queryDuplicateLbRulesCaddyIDs(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if len(ids) != 0 {
		t.Fatalf("迁移后不应再有重复：%v", ids)
	}
}
