package services

// 「活动态只属执行者进程」的读侧投影：从节点读到主端镜像/本机残留的活动态时
// 必须按 failed 呈现（不写库），主节点原样返回（在途状态由内存快照覆盖）。

import (
	"testing"
)

func TestProjectActiveUpdateStatusForLocalRole(t *testing.T) {
	_, database := newClusterTestService(t)

	// 主节点：活动态原样（不得被读侧抹成 failed）
	if _, err := database.Exec(`UPDATE global_config SET is_master=1 WHERE id=1`); err != nil {
		t.Fatalf("set master: %v", err)
	}
	if status, message := ProjectActiveUpdateStatusForLocalRole("downloading", "正在下载"); status != "downloading" || message != "正在下载" {
		t.Fatalf("主节点投影=%q/%q，want 原值", status, message)
	}

	// 从节点：活动态（三族词表）投影为 failed + 归属文案
	if _, err := database.Exec(`UPDATE global_config SET is_master=0 WHERE id=1`); err != nil {
		t.Fatalf("demote: %v", err)
	}
	for _, active := range []string{"checking", "downloading", "installing", "reloading", "running"} {
		status, message := ProjectActiveUpdateStatusForLocalRole(active, "旧文案")
		if status != "failed" || message != snapshotActiveUpdateStatusMessage {
			t.Fatalf("从节点投影(%s)=%q/%q，want failed/%q", active, status, message, snapshotActiveUpdateStatusMessage)
		}
	}
	// 终态不受影响
	for _, terminal := range []string{"success", "failed", "idle", "cancelled"} {
		if status, message := ProjectActiveUpdateStatusForLocalRole(terminal, "保留文案"); status != terminal || message != "保留文案" {
			t.Fatalf("从节点终态投影(%s)=%q/%q，want 原值", terminal, status, message)
		}
	}
}

// 从节点上版本表的残留活动态经状态读取面投影为 failed（storedStatusSnapshot /
// ip2RegionStoredStatusSnapshot），且库值不被改写（投影只影响展示）。
func TestStoredStatusSnapshotsProjectActiveStatusOnSlave(t *testing.T) {
	_, database := newClusterTestService(t)
	if _, err := database.Exec(`INSERT OR IGNORE INTO security_crs_version (id, version, auto_update) VALUES (1,'v',1)`); err != nil {
		t.Fatalf("seed crs row: %v", err)
	}
	if _, err := database.Exec(`UPDATE security_crs_version SET update_status='downloading', message='正在下载' WHERE id=1`); err != nil {
		t.Fatalf("seed crs active: %v", err)
	}
	if _, err := database.Exec(`UPDATE security_ip2region_version SET update_status='installing', message='正在安装' WHERE id=1`); err != nil {
		t.Fatalf("seed ip2region active: %v", err)
	}
	if _, err := database.Exec(`UPDATE global_config SET is_master=0 WHERE id=1`); err != nil {
		t.Fatalf("demote: %v", err)
	}

	crs := storedStatusSnapshot()
	if crs.Status != "failed" || crs.Message != snapshotActiveUpdateStatusMessage {
		t.Fatalf("CRS 从端快照=%q/%q，want failed/归属文案", crs.Status, crs.Message)
	}
	ip2 := ip2RegionStoredStatusSnapshot()
	if ip2.Status != "failed" || ip2.Message != snapshotActiveUpdateStatusMessage {
		t.Fatalf("IP2Region 从端快照=%q/%q，want failed/归属文案", ip2.Status, ip2.Message)
	}

	// 库值保持原样（投影不写库；数据面收敛由快照应用/启动归一负责）
	var crsStatus, ip2Status string
	if err := database.QueryRow(`SELECT update_status FROM security_crs_version WHERE id=1`).Scan(&crsStatus); err != nil {
		t.Fatalf("read crs row: %v", err)
	}
	if err := database.QueryRow(`SELECT update_status FROM security_ip2region_version WHERE id=1`).Scan(&ip2Status); err != nil {
		t.Fatalf("read ip2region row: %v", err)
	}
	if crsStatus != "downloading" || ip2Status != "installing" {
		t.Fatalf("读侧投影改写了库值: crs=%q ip2region=%q", crsStatus, ip2Status)
	}

	// 主节点：不投影（在途/中断归一由启动期处理）
	if _, err := database.Exec(`UPDATE global_config SET is_master=1 WHERE id=1`); err != nil {
		t.Fatalf("promote: %v", err)
	}
	if got := storedStatusSnapshot(); got.Status != "downloading" {
		t.Fatalf("主节点 CRS 快照=%q，want downloading（读侧不得改写主节点在途态）", got.Status)
	}
}

// 启动归一覆盖源表族（主节点）：残留 running 行归一为 failed，便于任务视图与
// 规则库页自洽（此前源表完全没有启动归一）。
func TestNormalizeInterruptedStatusesCoversSourceRows(t *testing.T) {
	_, database := newClusterTestService(t)
	if _, err := database.Exec(`UPDATE security_threat_sources SET update_status='running', message='正在下载' WHERE name='ustc'`); err != nil {
		t.Fatalf("seed threat active: %v", err)
	}
	if _, err := database.Exec(`INSERT INTO security_crawler_sources (name, update_enabled, update_status) VALUES ('crawler-running',1,'running')`); err != nil {
		t.Fatalf("seed crawler active: %v", err)
	}

	normalizeInterruptedUpdateStatuses()

	var status, message string
	if err := database.QueryRow(`SELECT update_status, message FROM security_threat_sources WHERE name='ustc'`).Scan(&status, &message); err != nil {
		t.Fatalf("read threat row: %v", err)
	}
	if status != "failed" || message != "（进程重启回收）" {
		t.Fatalf("威胁源启动归一=%q/%q，want failed/（进程重启回收）", status, message)
	}
	if err := database.QueryRow(`SELECT update_status, message FROM security_crawler_sources WHERE name='crawler-running'`).Scan(&status, &message); err != nil {
		t.Fatalf("read crawler row: %v", err)
	}
	if status != "failed" || message != "（进程重启回收）" {
		t.Fatalf("爬虫源启动归一=%q/%q，want failed/（进程重启回收）", status, message)
	}

	// 幂等：再跑一轮无变化（无活动行即静默）
	normalizeInterruptedUpdateStatuses()
	if err := database.QueryRow(`SELECT update_status FROM security_threat_sources WHERE name='ustc'`).Scan(&status); err != nil {
		t.Fatalf("re-read threat row: %v", err)
	}
	if status != "failed" {
		t.Fatalf("第二轮归一后状态=%q，want failed", status)
	}
}
