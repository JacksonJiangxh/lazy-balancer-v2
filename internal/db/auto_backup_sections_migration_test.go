package db

import "testing"

func TestMigrateAutoBackupNodeTopologySection_appendsOnlyOldDefaultOnce(t *testing.T) {
	dir := t.TempDir()
	oldDB, oldMetricsDB, oldAuditDB := DB, MetricsDB, AuditDB
	t.Cleanup(func() {
		_ = Close()
		DB, MetricsDB, AuditDB = oldDB, oldMetricsDB, oldAuditDB
	})
	if err := Initialize(dir); err != nil {
		t.Fatalf("initialize database: %v", err)
	}

	// 旧默认三分类 + version 0 → 追加节点拓扑。
	if _, err := DB.Exec(`UPDATE global_config SET auto_backup_sections='["users","rules","security"]', auto_backup_sections_version=0 WHERE id=1`); err != nil {
		t.Fatalf("seed legacy sections: %v", err)
	}
	if err := migrateAutoBackupNodeTopologySection(); err != nil {
		t.Fatalf("migrate: %v", err)
	}
	var sections, version string
	if err := DB.QueryRow(`SELECT auto_backup_sections, auto_backup_sections_version FROM global_config WHERE id=1`).Scan(&sections, &version); err != nil {
		t.Fatalf("read migrated sections: %v", err)
	}
	if sections != `["users","rules","security","cluster"]` || version != "1" {
		t.Fatalf("sections=%s version=%s", sections, version)
	}

	// 用户显式取消节点拓扑（version 已为 1）→ 再次启动不得加回。
	if _, err := DB.Exec(`UPDATE global_config SET auto_backup_sections='["users","rules","security"]' WHERE id=1`); err != nil {
		t.Fatalf("uncheck cluster: %v", err)
	}
	if err := migrateAutoBackupNodeTopologySection(); err != nil {
		t.Fatalf("second migrate: %v", err)
	}
	if err := DB.QueryRow(`SELECT auto_backup_sections FROM global_config WHERE id=1`).Scan(&sections); err != nil {
		t.Fatalf("read unchecked sections: %v", err)
	}
	if sections != `["users","rules","security"]` {
		t.Fatalf("sections=%s, want explicit uncheck preserved", sections)
	}
}
