package services

import (
	"context"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"

	"lazy-balancer-v2/internal/db"
)

// 条数塌缩门：上游返回「每行都是合法 CIDR 但只剩几条」的自洽短名单时，
// 解析率（100%）与绝对上限门都放行——没有条数基线门就会把万余条内置威胁
// 名单整体替换（原名单 IP 静默不再拦）。门拒绝后保留上次快照，源行落 failed
// 供任务监控与运行审计可见；人工清理基线后合法重构可恢复写入。
func TestThreatEntryShrinkGuard_rejectsParseableCollapsedList(t *testing.T) {
	overrideWafDirForTest(t)
	newClusterTestService(t)

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "text/plain")
		_, _ = w.Write([]byte("203.0.113.1\n203.0.113.2\n203.0.113.3\n203.0.113.4\n203.0.113.5\n"))
	}))
	t.Cleanup(server.Close)

	var id int
	if err := db.DB.QueryRow(`SELECT id FROM security_threat_sources WHERE name='ustc'`).Scan(&id); err != nil {
		t.Fatal(err)
	}
	// 基线 = 当前快照 100 条；新名单 5 条（不是误页也仍是塌缩）。
	if _, err := db.DB.Exec(`UPDATE security_threat_sources SET entry_count=100, raw_hash='' WHERE id=?`, id); err != nil {
		t.Fatal(err)
	}

	changed, failed := GetThreatUpdateManager().updateOneSource(context.Background(),
		threatSourceRow{id: id, name: "ustc", url: server.URL}, "manual", "2026-10-22 00:00:00")

	if !failed || changed {
		t.Fatalf("changed=%v failed=%v, want (false,true)（塌缩名单必须按源失败）", changed, failed)
	}
	if _, err := os.Stat(filepath.Join(wafDir, "threat-ustc.iplist")); !os.IsNotExist(err) {
		t.Fatal("塌缩名单不得写盘（必须保留上次快照）")
	}
	var status string
	if err := db.DB.QueryRow(`SELECT update_status FROM security_threat_sources WHERE id=?`, id).Scan(&status); err != nil {
		t.Fatal(err)
	}
	if status != "failed" {
		t.Fatalf("status=%q, want failed", status)
	}

	// 人工清理基线后同源放行（上游合法重构的恢复路径）。
	if _, err := db.DB.Exec(`UPDATE security_threat_sources SET entry_count=0, raw_hash='' WHERE id=?`, id); err != nil {
		t.Fatal(err)
	}
	changed, failed = GetThreatUpdateManager().updateOneSource(context.Background(),
		threatSourceRow{id: id, name: "ustc", url: server.URL}, "manual", "2026-10-22 00:00:00")
	if failed || !changed {
		t.Fatalf("清基线后应放行: changed=%v failed=%v", changed, failed)
	}
	if _, err := os.Stat(filepath.Join(wafDir, "threat-ustc.iplist")); err != nil {
		t.Fatalf("放行后必须写盘: %v", err)
	}
}
