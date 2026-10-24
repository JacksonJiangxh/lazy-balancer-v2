package handlers

import (
	"context"
	"testing"

	"lazy-balancer-v2/internal/db"
)

// Given 导入已提交但请求 ctx 已被取消（前端超时/关页/网关断连的真实形态）。
// When 提交后撤销临时版本种子行。
// Then 清理照常完成：残留 `__lazy_balancer_import_seed__` 行会让版本表停在
// auto_update=0 且不被 rearm 补槽（自动更新静默停摆）。
func TestImportVersionSentinelCleanupSurvivesCanceledRequestContext(t *testing.T) {
	newBackupTestHandlers(t)
	if _, err := db.DB.Exec(`INSERT OR REPLACE INTO security_crs_version (id, version, auto_update) VALUES (1, ?, 0)`, importVersionSeedSentinel); err != nil {
		t.Fatalf("seed sentinel row: %v", err)
	}
	// 对照行：已被并发真实更新（版本不同）→ CAS 必须保留。
	if _, err := db.DB.Exec(`INSERT OR REPLACE INTO security_ip2region_version (id, version, auto_update) VALUES (1, 'v3.99.0', 1)`); err != nil {
		t.Fatalf("seed concurrently-updated row: %v", err)
	}

	canceled, cancel := context.WithCancel(context.Background())
	cancel()
	cleanupImportVersionSentinels(canceled, []string{"security_crs_version", "security_ip2region_version"})

	var sentinelRows int
	if err := db.DB.QueryRow(`SELECT COUNT(*) FROM security_crs_version WHERE id=1`).Scan(&sentinelRows); err != nil {
		t.Fatalf("count crs version rows: %v", err)
	}
	if sentinelRows != 0 {
		t.Fatalf("sentinel rows=%d after canceled-ctx cleanup, want 0", sentinelRows)
	}
	var concurrentVersion string
	if err := db.DB.QueryRow(`SELECT version FROM security_ip2region_version WHERE id=1`).Scan(&concurrentVersion); err != nil {
		t.Fatalf("read concurrently-updated row: %v", err)
	}
	if concurrentVersion != "v3.99.0" {
		t.Fatalf("concurrently-updated version=%q, want preserved v3.99.0", concurrentVersion)
	}
}
