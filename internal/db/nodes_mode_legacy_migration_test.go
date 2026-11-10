package db

import (
	"strings"
	"testing"
)

// nodes.mode 的唯一写点（RegisterNode）恒写 'slave'，巡检按 mode='slave'
// 过滤。旧构建导入/直改库遗留的 'master' 行既永久退出离线/滞后判定，又会让
// 当前版本导出的自备份在导入行级门被拒（自备份不可还原——备份自毒）。
// 启动收敛为 'slave'，且整批留一条聚合审计；重跑幂等零写零审计。
func TestRunMigrations_normalizesLegacyNodeMode(t *testing.T) {
	database := openMigrationTestDB(t)
	if err := createTables(); err != nil {
		t.Fatalf("create tables: %v", err)
	}
	if _, err := database.Exec("INSERT INTO global_config (id,caddy_config) VALUES (1,'{}')"); err != nil {
		t.Fatalf("seed global config: %v", err)
	}
	if _, err := database.Exec(`INSERT INTO nodes (name,mode,ip_address,port) VALUES
		('legacy-master','master','10.0.0.11',8000),
		('legacy-empty','','10.0.0.12',8000),
		('healthy-slave','slave','10.0.0.13',8000)`); err != nil {
		t.Fatalf("seed nodes: %v", err)
	}
	drainSystemAuditBuffer()

	if err := runMigrations(); err != nil {
		t.Fatalf("run migrations: %v", err)
	}

	var nonSlave int
	if err := database.QueryRow(`SELECT COUNT(*) FROM nodes WHERE COALESCE(mode,'')<>'slave'`).Scan(&nonSlave); err != nil {
		t.Fatalf("count non-slave nodes: %v", err)
	}
	if nonSlave != 0 {
		t.Fatalf("non-slave nodes=%d after startup migration, want 0（巡检会永久漏判该节点）", nonSlave)
	}
	entries := drainSystemAuditBuffer()
	if len(entries) != 1 {
		t.Fatalf("migration audit entries=%d, want 1（整批聚合一行）: %+v", len(entries), entries)
	}
	if entries[0].action != "启动迁移" || !strings.Contains(entries[0].detail, "nodes.mode") {
		t.Fatalf("audit entry=%+v, want 启动迁移/nodes.mode", entries[0])
	}
	if !strings.Contains(entries[0].detail, "2") {
		t.Fatalf("audit detail=%q, want 命中行数 2", entries[0].detail)
	}

	// 幂等：重跑零写、零新审计。
	if err := runMigrations(); err != nil {
		t.Fatalf("rerun migrations: %v", err)
	}
	if entries := drainSystemAuditBuffer(); len(entries) != 0 {
		t.Fatalf("rerun audit entries=%d, want 0: %+v", len(entries), entries)
	}
}
