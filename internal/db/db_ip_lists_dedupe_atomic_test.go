package db

import (
	"strconv"
	"strings"
	"testing"
)

// 去重三步（删重复行 → 重写引用 → 建唯一索引）必须同一事务：中途失败整体
// 回滚。否则「已删行 + 未重写引用」的中间态会让策略引用永久指向不存在的
// 名单 id（渲染期该名单条目整体消失：少拦/少放）。本测用同名占位表迫使第三
// 步 CREATE INDEX 失败，断言前两步的数据改写全部回滚。
func TestMigrateSystemIPListUniqueIndex_dedupeRollsBackAtomically(t *testing.T) {
	database := openMigrationTestDB(t)
	if err := createTables(); err != nil {
		t.Fatalf("create tables: %v", err)
	}
	// 同名 system=1 三行：id1 未被引用，id2/id3 被策略引用。
	// 保留 MIN(被引用 id)=id2，remap={id1:id2, id3:id2}——引用 [2,3] 应被
	// 重写为 [2,2]（重写是第三步失败前必须一并回滚的写）。
	if _, err := database.Exec(`INSERT INTO security_ip_lists (name,description,category,entries,system,created_at,updated_at) VALUES
		('自动封禁名单','旧A','自动封禁','["1.1.1.1"]',1,'2026-01-01 00:00:00','2026-01-01 00:00:00'),
		('自动封禁名单','旧B','自动封禁','[]',1,'2026-01-01 00:00:00','2026-01-01 00:00:00'),
		('自动封禁名单','旧C','自动封禁','[]',1,'2026-01-01 00:00:00','2026-01-01 00:00:00')`); err != nil {
		t.Fatalf("seed duplicates: %v", err)
	}
	var id2, id3 int
	if err := database.QueryRow(`SELECT id FROM security_ip_lists WHERE name='自动封禁名单' AND description='旧B'`).Scan(&id2); err != nil {
		t.Fatal(err)
	}
	if err := database.QueryRow(`SELECT id FROM security_ip_lists WHERE name='自动封禁名单' AND description='旧C'`).Scan(&id3); err != nil {
		t.Fatal(err)
	}
	refs := "[" + strconv.Itoa(id2) + "," + strconv.Itoa(id3) + "]"
	if _, err := database.Exec(`INSERT INTO security_policies (id, name, ip_acl_list_refs) VALUES (1, 'p', ?)`, refs); err != nil {
		t.Fatalf("seed policy refs: %v", err)
	}
	// 同名占位表：CREATE UNIQUE INDEX 会以「already a table named …」失败，
	// 模拟「去重与引用重写已执行、建索引阶段出错」的崩溃窗口。
	if _, err := database.Exec(`CREATE TABLE u_security_ip_lists_system_name (placeholder INTEGER)`); err != nil {
		t.Fatalf("create index-name placeholder: %v", err)
	}

	if err := migrateSystemIPListUniqueIndex(); err == nil {
		t.Fatal("create unique index must fail with the placeholder table occupying the index name")
	}

	var rows int
	if err := database.QueryRow(`SELECT COUNT(*) FROM security_ip_lists WHERE name='自动封禁名单' AND system=1`).Scan(&rows); err != nil {
		t.Fatal(err)
	}
	if rows != 3 {
		t.Fatalf("system rows=%d, want 3（失败必须整体回滚：DELETE 不得先提交）", rows)
	}
	var keptRefs string
	if err := database.QueryRow(`SELECT ip_acl_list_refs FROM security_policies WHERE id=1`).Scan(&keptRefs); err != nil {
		t.Fatal(err)
	}
	if keptRefs != refs {
		t.Fatalf("policy refs=%q, want %q（引用重写必须与删行同事务回滚）", keptRefs, refs)
	}
	// 失败后不留写迁移审计（删行未发生）。
	for _, entry := range drainSystemAuditBuffer() {
		if strings.Contains(entry.detail, "已去重") {
			t.Fatalf("回滚后不得留去重审计: %+v", entry)
		}
	}
}

// 历史非原子去重窗口的残留形态（引用指向已删 id、重复行已不存在）无法自动
// 修好：迁移只统计并告警，不改写引用（被引用行已删，无法推断用户意图）。
func TestMigrateSystemIPListUniqueIndex_reportsDanglingReferences(t *testing.T) {
	database := openMigrationTestDB(t)
	if err := createTables(); err != nil {
		t.Fatalf("create tables: %v", err)
	}
	var validID int
	if _, err := database.Exec(`INSERT INTO security_ip_lists (name,description,category,entries,system) VALUES ('存活名单','','自定义','[]',0)`); err != nil {
		t.Fatalf("seed live list: %v", err)
	}
	if err := database.QueryRow(`SELECT id FROM security_ip_lists WHERE name='存活名单'`).Scan(&validID); err != nil {
		t.Fatal(err)
	}
	// 一行引用存活 id（不计悬空），一行引用不存在的 id=999，一行同时含两者（只计一次）。
	if _, err := database.Exec(`INSERT INTO security_policies (id, name, ip_acl_list_refs) VALUES
		(7, 'ok', ?),
		(8, 'dangling', '[999]'),
		(9, 'mixed', ?)`,
		"["+strconv.Itoa(validID)+"]", "["+strconv.Itoa(validID)+",999]"); err != nil {
		t.Fatalf("seed policy refs: %v", err)
	}

	before := systemIPListDanglingRefs.Load()
	if err := migrateSystemIPListUniqueIndex(); err != nil {
		t.Fatalf("migrate: %v", err)
	}
	if got := systemIPListDanglingRefs.Load() - before; got != 2 {
		t.Fatalf("悬空引用行数=%d, want 2（行 8 与行 9 各计一次）", got)
	}
	// 迁移不自动改引用：悬空 id 原样保留，供用户按告警自行修正。
	var mixedRefs string
	if err := database.QueryRow(`SELECT ip_acl_list_refs FROM security_policies WHERE id=9`).Scan(&mixedRefs); err != nil {
		t.Fatal(err)
	}
	if mixedRefs != "["+strconv.Itoa(validID)+",999]" {
		t.Fatalf("mixed refs=%q, want 原样保留（迁移不得自动摘除引用）", mixedRefs)
	}
}
