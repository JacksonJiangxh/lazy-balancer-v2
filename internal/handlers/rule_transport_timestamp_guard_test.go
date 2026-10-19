package handlers

import (
	"context"
	"database/sql"
	"testing"

	"lazy-balancer-v2/internal/db"
)

// 历史问题 同族回归：v1/v2 导入共用的 normalizeRuleRowsForTransport 与启动
// 迁移必须同口径——strftime 无法解析的带 T 垃圾值保持原样，不得被静默写成
// NULL（NULL 随后会让快照裸列 time.Time 扫描整包失败）。
func TestNormalizeRuleRowsForTransport_preservesMalformedTimestamps(t *testing.T) {
	// Given：可解析 RFC3339、不可解析垃圾值、平面格式与 NULL 四种形态。
	newBackupTestHandlers(t)
	const malformed = "2026-13-45T99:99:99Z"
	if _, err := db.DB.Exec(`INSERT INTO lb_rules (caddy_id,name,protocol,domain,listen_port,enabled,created_at,updated_at) VALUES
		('lb_import_ts_valid','valid','http','valid.example.test',8080,1,'2026-01-02T03:04:05Z','2026-01-02 03:04:05'),
		('lb_import_ts_bad','bad','http','bad.example.test',8081,1,'2026-13-45T99:99:99Z','2026-02-03T04:05:06Z');
		INSERT INTO path_rules (rule_id,sort_order,match_type,path,created_at,updated_at)
		VALUES ('lb_import_ts_bad',0,'prefix','/','2026-13-45T99:99:99Z',NULL)`); err != nil {
		t.Fatalf("seed timestamp shapes: %v", err)
	}
	tx, err := db.DB.Begin()
	if err != nil {
		t.Fatalf("begin import normalization transaction: %v", err)
	}
	defer func() { _ = tx.Rollback() }()

	// When：执行导入事务内的共享归一实现。
	if _, err := normalizeRuleRowsForTransport(context.Background(), tx); err != nil {
		t.Fatalf("normalize rule rows: %v", err)
	}
	if err := tx.Commit(); err != nil {
		t.Fatalf("commit normalization: %v", err)
	}

	// Then：有效值平面化；垃圾值保留为异常信号；既有 NULL 保持 NULL。
	assertRaw := func(query, want string) {
		t.Helper()
		var got sql.NullString
		if err := db.DB.QueryRow(query).Scan(&got); err != nil {
			t.Fatalf("query %s: %v", query, err)
		}
		if !got.Valid || got.String != want {
			t.Errorf("query %s = %+v, want %q", query, got, want)
		}
	}
	assertRaw(`SELECT CAST(created_at AS TEXT) FROM lb_rules WHERE caddy_id='lb_import_ts_valid'`, "2026-01-02 03:04:05")
	assertRaw(`SELECT CAST(updated_at AS TEXT) FROM lb_rules WHERE caddy_id='lb_import_ts_valid'`, "2026-01-02 03:04:05")
	assertRaw(`SELECT CAST(updated_at AS TEXT) FROM lb_rules WHERE caddy_id='lb_import_ts_bad'`, "2026-02-03 04:05:06")
	assertRaw(`SELECT CAST(created_at AS TEXT) FROM lb_rules WHERE caddy_id='lb_import_ts_bad'`, malformed)
	assertRaw(`SELECT CAST(created_at AS TEXT) FROM path_rules WHERE rule_id='lb_import_ts_bad'`, malformed)
	var nullCount int
	if err := db.DB.QueryRow(`SELECT COUNT(*) FROM path_rules WHERE rule_id='lb_import_ts_bad' AND updated_at IS NULL`).Scan(&nullCount); err != nil {
		t.Fatal(err)
	}
	if nullCount != 1 {
		t.Fatalf("existing NULL updated_at count=%d, want 1", nullCount)
	}
}
