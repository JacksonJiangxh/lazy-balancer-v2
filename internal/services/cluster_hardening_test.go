package services

import (
	"context"
	"database/sql"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"lazy-balancer-v2/internal/config"
	"lazy-balancer-v2/internal/db"
	"lazy-balancer-v2/internal/models"
)

// 快照读取路径必须带 SQL 级角色复核（与写路径 masterRoleConditionSQL 同不变量）：
// handler 的 requireMaster 与快照事务之间无共享锁，降级窗口内缓存命中/重建
// 都不得再下发完整快照（含用户 hash/证书私钥/凭据）。
func TestSnapshot_demotedRoleFailsClosed(t *testing.T) {
	service, database := newClusterTestService(t)
	ctx := context.Background()

	// 主节点态先建一份快照并填充缓存（缓存命中路径同样必须过角色复核）。
	if _, changed, err := service.Snapshot(ctx, 0, "", ""); err != nil || !changed {
		t.Fatalf("master snapshot changed=%v err=%v", changed, err)
	}
	if _, err := database.Exec(`UPDATE global_config SET is_master=0 WHERE id=1`); err != nil {
		t.Fatal(err)
	}

	if _, _, err := service.Snapshot(ctx, 0, "", ""); !errors.Is(err, ErrNotMasterNode) {
		t.Fatalf("demoted snapshot err=%v, want ErrNotMasterNode（读路径角色复核）", err)
	}
	// 缓存条目不得残留已降级库的旧快照（下一访问必须重新判定）。
	if _, _, err := service.Snapshot(ctx, 0, "", ""); !errors.Is(err, ErrNotMasterNode) {
		t.Fatalf("second demoted snapshot err=%v, want ErrNotMasterNode", err)
	}
}

// 快照缓存与节哈希缓存同以库句柄为键：注销 ClusterService 必须一并回收
// （否则已 Close 句柄连同完整快照驻留进程级 map 至退出）。
func TestUnregisterClusterService_reclaimsSnapshotCache(t *testing.T) {
	service, database := newClusterTestService(t)
	if _, _, err := service.Snapshot(context.Background(), 0, "", ""); err != nil {
		t.Fatalf("seed snapshot cache: %v", err)
	}
	if _, ok := clusterSnapshotCaches.Load(database); !ok {
		t.Fatal("snapshot cache not populated after Snapshot")
	}

	unregisterClusterService(service)

	if _, ok := clusterSnapshotCaches.Load(database); ok {
		t.Fatal("snapshot cache entry survives unregister（强引用已关闭句柄）")
	}
	if len(clusterServicesFor(database)) != 0 {
		t.Fatal("cluster service registry entry survives unregister")
	}
}

// NewSyncService 内建并登记一个 ClusterService：注销同步服务必须连带注销
// 内建实例（含其快照缓存），否则 teardown 后全局表仍强引用库句柄。
func TestUnregisterSyncDrainer_reclaimsInnerClusterService(t *testing.T) {
	oldDB, oldMetricsDB, oldAuditDB := db.DB, db.MetricsDB, db.AuditDB
	if err := db.Initialize(t.TempDir()); err != nil {
		t.Fatal(err)
	}
	database := db.DB
	t.Cleanup(func() {
		_ = db.Close()
		db.DB, db.MetricsDB, db.AuditDB = oldDB, oldMetricsDB, oldAuditDB
	})
	sync := NewSyncService(database, &config.Config{DataDir: t.TempDir()}, nil)
	if sync.cluster == nil {
		t.Fatal("sync service must build an inner cluster service")
	}

	unregisterSyncDrainer(sync)

	if got := clusterServicesFor(database); len(got) != 0 {
		t.Fatalf("inner cluster service survives sync teardown: %d entries", len(got))
	}
	if got := syncDrainersFor(database); len(got) != 0 {
		t.Fatalf("sync drainer survives teardown: %d entries", len(got))
	}
}

// pin 目录解析单源=服务的 dataDir：写入/校验侧经 cfg.DataDir，删除/清理侧
// 此前走 DB 文件目录推导——data_dir ≠ dirname(DB) 时清理打到错误目录，
// 旧 pin 残留、持续 PinMismatch 只能手工删盘。
func TestForgetNodePin_usesServiceDataDirForPinCleanup(t *testing.T) {
	stubUpdateRetrySleep(t)
	oldDB, oldMetricsDB, oldAuditDB := db.DB, db.MetricsDB, db.AuditDB
	dbDir := t.TempDir() // 库目录 ≠ 数据目录（双源分叉形态）
	if err := db.Initialize(dbDir); err != nil {
		t.Fatal(err)
	}
	database := db.DB
	t.Cleanup(func() {
		_ = db.Close()
		db.DB, db.MetricsDB, db.AuditDB = oldDB, oldMetricsDB, oldAuditDB
	})
	dataDir := t.TempDir()
	service := NewClusterService(database, dataDir)
	t.Cleanup(func() { unregisterClusterService(service) })
	nodeID := insertApprovedClusterNode(t, database, "slave-datadir")
	if _, err := database.Exec(`UPDATE nodes SET access_url='http://10.0.0.21:8000' WHERE id=?`, nodeID); err != nil {
		t.Fatal(err)
	}
	writePin := func(dir string) string {
		pinPath, err := clusterPinPath(dir, database, "10.0.0.21:8000")
		if err != nil {
			t.Fatal(err)
		}
		if err := os.MkdirAll(filepath.Dir(pinPath), 0o700); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(pinPath, []byte("fingerprint\n"), 0o600); err != nil {
			t.Fatal(err)
		}
		return pinPath
	}
	// 两个目录各置一枚 pin：清理必须命中 dataDir 侧，DB 目录侧原样保留。
	dataDirPin := writePin(dataDir)
	dbDirPin := writePin(filepath.Dir(mustDatabasePath(t, database)))

	if _, err := service.ForgetNodePin(context.Background(), nodeID); err != nil {
		t.Fatalf("forget node pin: %v", err)
	}
	if _, err := os.Stat(dataDirPin); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("dataDir pin stat err=%v, want removed（清理必须走服务 dataDir）", err)
	}
	if _, err := os.Stat(dbDirPin); err != nil {
		t.Fatalf("db-dir pin must be untouched（不同目录不得误删）: %v", err)
	}
}

func mustDatabasePath(t *testing.T, database *sql.DB) string {
	t.Helper()
	var sequence int
	var name, path string
	if err := database.QueryRow("PRAGMA database_list").Scan(&sequence, &name, &path); err != nil || path == "" {
		t.Fatalf("resolve database path: %v path=%q", err, path)
	}
	return path
}

// 记账通道失败必须返回 error（调用方据此回退「不依赖 DB 记账」的 WAF 内容
// 哈希兜底并入审计），不得仅 warn 后静默。
func TestRecordAppliedSectionHashes_reportsWriteFailure(t *testing.T) {
	_, database := newClusterTestService(t)
	snapshot := models.ClusterSnapshot{Version: 7, SectionHashes: map[string]string{"users": "u", "rules": "r", "security": "s"}}
	switches := SyncSwitches{Users: true, Rules: true, Security: true}
	sk := &sectionSkips{disabled: map[string]bool{}, unchanged: map[string]bool{}}
	if err := recordAppliedSectionHashes(context.Background(), database, snapshot, sk, switches, nil); err != nil {
		t.Fatalf("healthy bookkeeping err=%v, want nil", err)
	}

	closed, err := sql.Open("sqlite", filepath.Join(t.TempDir(), "closed.db"))
	if err != nil {
		t.Fatal(err)
	}
	if err := closed.Close(); err != nil {
		t.Fatal(err)
	}
	if err := recordAppliedSectionHashes(context.Background(), closed, snapshot, sk, switches, nil); err == nil {
		t.Fatal("closed-handle bookkeeping err=nil, want aggregated error（调用方须能感知记账失败）")
	}
}

// nodes.last_sync_at 刻意不写（全仓无读者，格式与全库平面 UTC 不一致）：
// 上报携带 LastSyncAt 时该列必须保持 NULL，展示值只走 health_json。
func TestReportNode_doesNotWriteLastSyncAtColumn(t *testing.T) {
	svc, database := newClusterTestService(t)
	nodeID := insertApprovedClusterNode(t, database, "slave-lastsync")
	report := models.ClusterReport{
		AppliedVersion: 3,
		LastSyncAt:     time.Now().UTC().Format(time.RFC3339),
	}
	if err := svc.ReportNode(context.Background(), nodeID, report, time.Now()); err != nil {
		t.Fatalf("report node: %v", err)
	}
	var lastSyncAt sql.NullString
	if err := database.QueryRow(`SELECT last_sync_at FROM nodes WHERE id=?`, nodeID).Scan(&lastSyncAt); err != nil {
		t.Fatal(err)
	}
	if lastSyncAt.Valid {
		t.Fatalf("nodes.last_sync_at=%q, want NULL（死列不得写入；展示值在 health_json）", lastSyncAt.String)
	}
	// 展示面健康 JSON 仍携带上报的同步时间。
	var healthJSON string
	if err := database.QueryRow(`SELECT health_json FROM nodes WHERE id=?`, nodeID).Scan(&healthJSON); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(healthJSON, report.LastSyncAt) {
		t.Fatalf("health_json=%q, want 携带 last_sync_at=%q", healthJSON, report.LastSyncAt)
	}
}

// cluster-sync 两角色语义不同（从端=拉取，主端=服务面巡检）：升主保持用户
// 停止态（既有裁定），但主端巡检未启用必须在升主审计行可见。
func TestPromote_stoppedClusterSyncLeavesInspectionAudit(t *testing.T) {
	_, database := newClusterTestService(t)
	probe := &roleLifecycleProbe{}
	te := wireClusterLifecycleEngineForTest(t, probe, false)
	waitForCond(t, 2*time.Second, func() bool { return probe.syncStarts.Load() == 1 })
	te.StopLoop("cluster-sync")
	waitForCond(t, 2*time.Second, func() bool {
		for _, meta := range te.DescribeAll() {
			if meta.ID == "cluster-sync" && !meta.Running {
				return true
			}
		}
		return false
	})
	if _, err := database.Exec(`UPDATE global_config SET is_master=0 WHERE id=1`); err != nil {
		t.Fatal(err)
	}
	service := NewClusterService(database, "")

	if err := service.Promote(context.Background()); err != nil {
		t.Fatalf("promote: %v", err)
	}

	if meta, ok := te.Lookup("cluster-sync"); ok && meta.LoopOn {
		t.Fatal("Promote 覆盖了 cluster-sync 用户停止态（偏好保留裁定不变）")
	}
	var found bool
	rows, err := db.AuditDB.Query(`SELECT detail FROM audit_log WHERE action='提升完成'`)
	if err != nil {
		t.Fatal(err)
	}
	defer rows.Close()
	for rows.Next() {
		var detail string
		if err := rows.Scan(&detail); err != nil {
			t.Fatal(err)
		}
		if strings.Contains(detail, "巡检") && strings.Contains(detail, "未启用") {
			found = true
		}
	}
	if !found {
		t.Fatal("升主审计缺少「cluster-sync 停止→主端巡检未启用」提示行")
	}
}
