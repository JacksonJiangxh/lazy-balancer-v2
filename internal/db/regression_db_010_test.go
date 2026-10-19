package db

import (
	"database/sql"
	"testing"
)

// 固定 2..64 契约废除——一次性迁移把存量 2..64（含旧默认 4/8）与其它越界值
// 全部归 -1；{-1,0,1} 原样保留；marker 置位后不再触碰运行期写值。
func TestMigrateThreatTrafficSampleUnified_normalizesToAdaptive(t *testing.T) {
	openMigrationTestDB(t)
	if err := createTables(); err != nil {
		t.Fatalf("create tables: %v", err)
	}
	if _, err := DB.Exec("INSERT INTO global_config (id, caddy_config) VALUES (1, '{}')"); err != nil {
		t.Fatalf("seed global config: %v", err)
	}
	// runMigrations 的 ensureNewColumns 是本列（含 DEFAULT）在存量/新建库上的
	// 唯一登记通道；同时首轮会执行一次统一迁移（值 -1 保持、marker 置位）。
	if err := runMigrations(); err != nil {
		t.Fatalf("run migrations: %v", err)
	}
	// 默认值（列声明）必须是自适应——查 PRAGMA 而非行值：行值随后续迁移
	// 恒被归一 -1，无法区分 DEFAULT 登记是否有误。
	if got := columnDefault(t, "global_config", "threat_traffic_sample_n"); got != "-1" {
		t.Fatalf("fresh threat_traffic_sample_n DEFAULT=%q, want -1", got)
	}

	for _, legacy := range []int{2, 4, 8, 64, 365, -7} {
		if _, err := DB.Exec(`UPDATE global_config SET threat_traffic_sample_n=?, threat_traffic_sample_unified_migrated=0 WHERE id=1`, legacy); err != nil {
			t.Fatal(err)
		}
		if err := migrateThreatTrafficSampleUnified(); err != nil {
			t.Fatalf("migrate for %d: %v", legacy, err)
		}
		var got int
		if err := DB.QueryRow(`SELECT threat_traffic_sample_n FROM global_config WHERE id=1`).Scan(&got); err != nil {
			t.Fatal(err)
		}
		if got != -1 {
			t.Fatalf("legacy sample_n=%d migrated to %d, want -1", legacy, got)
		}
	}

	for _, valid := range []int{-1, 0, 1} {
		if _, err := DB.Exec(`UPDATE global_config SET threat_traffic_sample_n=?, threat_traffic_sample_unified_migrated=0 WHERE id=1`, valid); err != nil {
			t.Fatal(err)
		}
		if err := migrateThreatTrafficSampleUnified(); err != nil {
			t.Fatal(err)
		}
		var got int
		if err := DB.QueryRow(`SELECT threat_traffic_sample_n FROM global_config WHERE id=1`).Scan(&got); err != nil {
			t.Fatal(err)
		}
		if got != valid {
			t.Fatalf("valid sample_n=%d migrated to %d, want unchanged", valid, got)
		}
	}

	// marker 已置位：再次执行不得覆盖运行期写值（幂等 + 不重放）。
	if _, err := DB.Exec(`UPDATE global_config SET threat_traffic_sample_n=4, threat_traffic_sample_unified_migrated=1 WHERE id=1`); err != nil {
		t.Fatal(err)
	}
	if err := migrateThreatTrafficSampleUnified(); err != nil {
		t.Fatal(err)
	}
	var got int
	if err := DB.QueryRow(`SELECT threat_traffic_sample_n FROM global_config WHERE id=1`).Scan(&got); err != nil {
		t.Fatal(err)
	}
	if got != 4 {
		t.Fatalf("second run overwrote marker-protected value: got %d, want 4", got)
	}
}

func columnDefault(t *testing.T, table, column string) string {
	t.Helper()
	rows, err := DB.Query("PRAGMA table_info(" + table + ")")
	if err != nil {
		t.Fatalf("pragma table_info(%s): %v", table, err)
	}
	defer rows.Close()
	for rows.Next() {
		var cid, notNull, pk int
		var name, columnType string
		var defaultValue sql.NullString
		if err := rows.Scan(&cid, &name, &columnType, &notNull, &defaultValue, &pk); err != nil {
			t.Fatalf("scan pragma: %v", err)
		}
		if name == column {
			return defaultValue.String
		}
	}
	t.Fatalf("column %s.%s not found", table, column)
	return ""
}
