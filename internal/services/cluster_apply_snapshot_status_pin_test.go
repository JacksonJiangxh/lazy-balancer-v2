package services

// 快照活动态归一的钉测：从节点收到主端快照里的「进行中」状态后必须落成
// failed + 归属文案——活动列不进节哈希/版本 bump，归一若回归，从节点规则库
// 会长期滞留「更新中」且没有任何其它收敛通道。反向用例锁住「不过度归一」：
// 终态（success/idle/failed）必须原样保留。

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"lazy-balancer-v2/internal/config"
)

func TestClusterApply_normalizesSnapshotActiveUpdateStatus(t *testing.T) {
	// Given：四表都带活动态
	cluster, database := newClusterTestService(t)
	if _, err := database.Exec(`UPDATE security_threat_sources SET update_status='running', message='正在下载' WHERE name='ustc'`); err != nil {
		t.Fatalf("seed threat active status: %v", err)
	}
	if _, err := database.Exec(`INSERT INTO security_crawler_sources (name, update_enabled, update_status, message) VALUES ('crawler-active',1,'running','正在下载')`); err != nil {
		t.Fatalf("seed crawler active status: %v", err)
	}
	if _, err := database.Exec(`INSERT OR IGNORE INTO security_crs_version (id, version, auto_update) VALUES (1,'v-local',1)`); err != nil {
		t.Fatalf("seed crs row: %v", err)
	}
	if _, err := database.Exec(`UPDATE security_crs_version SET update_status='downloading', message='正在下载' WHERE id=1`); err != nil {
		t.Fatalf("seed crs active status: %v", err)
	}
	if _, err := database.Exec(`UPDATE security_ip2region_version SET update_status='installing', message='正在安装' WHERE id=1`); err != nil {
		t.Fatalf("seed ip2region active status: %v", err)
	}

	snapshot, _, err := cluster.Snapshot(context.Background(), 0, "", "")
	if err != nil {
		t.Fatalf("snapshot: %v", err)
	}
	// 夹具前提：快照确实携带活动态（否则下方断言无区分力）。
	var threatRows []map[string]any
	if err := json.Unmarshal(snapshot.SecurityThreatSources, &threatRows); err != nil {
		t.Fatalf("快照未携带 security_threat_sources: %v", err)
	}
	activeInSnapshot := false
	for _, row := range threatRows {
		if row["name"] == "ustc" && row["update_status"] == "running" {
			activeInSnapshot = true
		}
	}
	if !activeInSnapshot {
		t.Fatalf("夹具前提不成立：快照威胁源未携带 running，rows=%v", threatRows)
	}
	if len(snapshot.SecurityCRSVersion) != 1 || snapshot.SecurityCRSVersion[0].UpdateStatus != "downloading" {
		t.Fatalf("夹具前提不成立：快照 CRS 版本行=%+v", snapshot.SecurityCRSVersion)
	}

	// 让本地版本行与快照不同，逼出版本行差分重放路径（归一在该路径内）。
	if _, err := database.Exec(`UPDATE security_crs_version SET version='v-different', update_status='success' WHERE id=1`); err != nil {
		t.Fatalf("diverge local crs row: %v", err)
	}
	var versionBefore int
	if err := database.QueryRow(`SELECT COALESCE(cluster_version,0) FROM global_config WHERE id=1`).Scan(&versionBefore); err != nil {
		t.Fatalf("read cluster_version: %v", err)
	}
	// 断言要有区分力：仅比较「apply 前后」在版本记账恒写 snapshot.Version 时
	// 是恒等式（snapshot.Version 就是本地读出的值）。先把本地版本推到哨兵值
	// （快照版本之后），apply 必须把它拉回 snapshot.Version——归一若额外推进
	// 版本、或版本记账被移除/后移，这里必然不等。
	sentinelVersion := versionBefore + 100
	if _, err := database.Exec(`UPDATE global_config SET cluster_version=? WHERE id=1`, sentinelVersion); err != nil {
		t.Fatalf("seed sentinel cluster_version: %v", err)
	}
	if snapshot.Version == sentinelVersion {
		t.Fatalf("夹具前提不成立：快照版本与哨兵值相同（%d）", sentinelVersion)
	}

	// When：走生产入口 applySnapshot（版本记账与归一在同一事务内；
	// 只调 replaceSnapshotTx 不会覆盖 cluster_version，断言会失去区分力）。
	caddyServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer caddyServer.Close()
	syncService := NewSyncService(database, &config.Config{DataDir: t.TempDir(), CaddyAdminURL: caddyServer.URL}, NewCaddyService(caddyServer.URL))
	if err := syncService.applySnapshot(context.Background(), snapshot); err != nil {
		t.Fatalf("apply snapshot: %v", err)
	}

	// Then：四表活动态一律归一为 failed + 归属文案
	assertNormalized := func(query string, args ...any) {
		t.Helper()
		var status, message string
		if err := database.QueryRow(query, args...).Scan(&status, &message); err != nil {
			t.Fatalf("read normalized row (%s): %v", query, err)
		}
		if status != "failed" || message != snapshotActiveUpdateStatusMessage {
			t.Fatalf("%s: status=%q message=%q，want failed/%q", query, status, message, snapshotActiveUpdateStatusMessage)
		}
	}
	assertNormalized(`SELECT update_status, message FROM security_threat_sources WHERE name='ustc'`)
	assertNormalized(`SELECT update_status, message FROM security_crawler_sources WHERE name='crawler-active'`)
	assertNormalized(`SELECT update_status, message FROM security_crs_version WHERE id=1`)
	assertNormalized(`SELECT update_status, message FROM security_ip2region_version WHERE id=1`)

	// 归一属于「展示态修正」而非语义变更：版本只按快照版本记账一次，
	// 不得被归一路径额外推进。
	var versionAfter int
	if err := database.QueryRow(`SELECT COALESCE(cluster_version,0) FROM global_config WHERE id=1`).Scan(&versionAfter); err != nil {
		t.Fatalf("read cluster_version: %v", err)
	}
	if versionAfter != snapshot.Version {
		t.Fatalf("cluster_version=%d，want %d（活动态归一不得额外 bump 版本）", versionAfter, snapshot.Version)
	}
}

func TestClusterApply_preservesSnapshotTerminalUpdateStatus(t *testing.T) {
	// Given：快照携带终态（success/idle/failed）——归一不得越界
	cluster, database := newClusterTestService(t)
	if _, err := database.Exec(`UPDATE security_threat_sources SET update_status='success', message='' WHERE name='ustc'`); err != nil {
		t.Fatalf("seed threat terminal status: %v", err)
	}
	if _, err := database.Exec(`INSERT INTO security_crawler_sources (name, update_enabled, update_status, message) VALUES ('crawler-idle',1,'idle','')`); err != nil {
		t.Fatalf("seed crawler terminal status: %v", err)
	}
	if _, err := database.Exec(`INSERT OR IGNORE INTO security_crs_version (id, version, auto_update) VALUES (1,'v-local',1)`); err != nil {
		t.Fatalf("seed crs row: %v", err)
	}
	if _, err := database.Exec(`UPDATE security_crs_version SET update_status='failed', message='下载失败' WHERE id=1`); err != nil {
		t.Fatalf("seed crs terminal status: %v", err)
	}
	snapshot, _, err := cluster.Snapshot(context.Background(), 0, "", "")
	if err != nil {
		t.Fatalf("snapshot: %v", err)
	}
	if _, err := database.Exec(`UPDATE security_crs_version SET version='v-different' WHERE id=1`); err != nil {
		t.Fatalf("diverge local crs row: %v", err)
	}

	// When：走生产入口 applySnapshot（版本记账与归一在同一事务内；
	// 只调 replaceSnapshotTx 不会覆盖 cluster_version，断言会失去区分力）。
	caddyServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer caddyServer.Close()
	syncService := NewSyncService(database, &config.Config{DataDir: t.TempDir(), CaddyAdminURL: caddyServer.URL}, NewCaddyService(caddyServer.URL))
	if err := syncService.applySnapshot(context.Background(), snapshot); err != nil {
		t.Fatalf("apply snapshot: %v", err)
	}

	// Then：终态原样保留（含源自带 message，不得被归一文案覆盖）
	var status, message string
	if err := database.QueryRow(`SELECT update_status, message FROM security_threat_sources WHERE name='ustc'`).Scan(&status, &message); err != nil {
		t.Fatalf("read threat row: %v", err)
	}
	if status != "success" || message != "" {
		t.Fatalf("威胁源终态被改写: status=%q message=%q，want success/空", status, message)
	}
	if err := database.QueryRow(`SELECT update_status FROM security_crawler_sources WHERE name='crawler-idle'`).Scan(&status); err != nil {
		t.Fatalf("read crawler row: %v", err)
	}
	if status != "idle" {
		t.Fatalf("爬虫源终态被改写: status=%q，want idle", status)
	}
	if err := database.QueryRow(`SELECT update_status, message FROM security_crs_version WHERE id=1`).Scan(&status, &message); err != nil {
		t.Fatalf("read crs row: %v", err)
	}
	if status != "failed" || message != "下载失败" {
		t.Fatalf("CRS 终态被改写: status=%q message=%q，want failed/下载失败", status, message)
	}
}

func TestClusterApply_snapshotStatusHelpers(t *testing.T) {
	// 归一 helper 的词表边界：三族活动态 + 源表 running 命中；其余原样。
	for _, status := range []string{"checking", "downloading", "installing", "reloading", "running"} {
		if !snapshotActiveUpdateStatus(status) {
			t.Fatalf("snapshotActiveUpdateStatus(%q)=false，want true", status)
		}
	}
	for _, status := range []string{"", "idle", "success", "failed", "cancelled", "skipped"} {
		if snapshotActiveUpdateStatus(status) {
			t.Fatalf("snapshotActiveUpdateStatus(%q)=true，want false", status)
		}
	}
	// 非字符串载荷（旧快照/畸形行）不得被当作活动态，三列原值透传。
	if s, msg, _ := normalizeSnapshotTaskState(json.Number("1"), "m", "2026-01-01 00:00:00", "2026-01-01 00:00:00"); s != json.Number("1") || msg != "m" {
		t.Fatalf("normalizeSnapshotTaskState 非字符串=-%v/%v，want 原值透传", s, msg)
	}
	if s, msg, _ := normalizeSnapshotTaskState("idle", "旧文案", "", "旧结束"); s != "idle" || msg != "旧文案" {
		t.Fatalf("normalizeSnapshotTaskState(idle)=%v/%v，want 原值透传", s, msg)
	}
	// 活动态归一：文案固定；结束时间取主端最后检查时刻，缺失时回退源值。
	if s, msg, _ := normalizeSnapshotTaskState("running", "旧文案", "2026-01-02 03:04:05", "2026-01-01 00:00:00"); s != "failed" || msg != snapshotActiveUpdateStatusMessage {
		t.Fatalf("normalizeSnapshotTaskState(running)=%v/%v，want failed/归一文案", s, msg)
	}
	if _, _, fin := normalizeSnapshotTaskState("running", "", "2026-01-02 03:04:05", ""); fin != "2026-01-02 03:04:05" {
		t.Fatalf("活动态结束时间=%v，want 主端 last_checked", fin)
	}
	if _, _, fin := normalizeSnapshotTaskState("running", "", "", "2026-01-01 00:00:00"); fin != "2026-01-01 00:00:00" {
		t.Fatalf("活动态结束时间=%v，want 回退源 finished_at", fin)
	}
}
