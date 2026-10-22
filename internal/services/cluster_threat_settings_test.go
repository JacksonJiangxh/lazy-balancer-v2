package services

import (
	"context"
	"testing"
)

// v2.3.8：安全事件保留与流量采样随 users 节同步，从节点/升主后口径一致。
func TestClusterSnapshot_securityRetentionAndTrafficSampleRoundTrip(t *testing.T) {
	cluster, database := newClusterTestService(t)
	if _, err := database.Exec(`UPDATE global_config
		SET security_events_retention_days=120, security_events_row_cap=500000, threat_traffic_sample_n=0
		WHERE id=1`); err != nil {
		t.Fatal(err)
	}

	snapshot, _, err := cluster.Snapshot(context.Background(), 0, "", "")
	if err != nil {
		t.Fatalf("snapshot: %v", err)
	}
	s := snapshot.BasicSettings
	if s.SecurityEventsRetentionDays == nil || *s.SecurityEventsRetentionDays != 120 ||
		s.SecurityEventsRowCap == nil || *s.SecurityEventsRowCap != 500000 ||
		s.ThreatTrafficSampleN == nil || *s.ThreatTrafficSampleN != 0 {
		t.Fatalf("快照未携带安全事件保留/采样: %+v", s)
	}

	if _, err := database.Exec(`UPDATE global_config
		SET security_events_retention_days=90, security_events_row_cap=1000000, threat_traffic_sample_n=-1
		WHERE id=1`); err != nil {
		t.Fatal(err)
	}
	if err := replaceSnapshotDB(context.Background(), database, snapshot); err != nil {
		t.Fatalf("apply snapshot: %v", err)
	}
	var days, cap, sample int
	if err := database.QueryRow(`SELECT security_events_retention_days, security_events_row_cap, threat_traffic_sample_n FROM global_config WHERE id=1`).Scan(&days, &cap, &sample); err != nil {
		t.Fatal(err)
	}
	if days != 120 || cap != 500000 || sample != 0 {
		t.Fatalf("应用后配置漂移: days=%d cap=%d sample=%d", days, cap, sample)
	}
}

// 大屏视觉模式随 users 节同步：从节点写入口被只读门拒绝，该列若不在同步
// 契约内，从端永远停留在默认视觉（主端改了也经 304 门滞留）。
func TestClusterSnapshot_threatScreenModeRoundTrip(t *testing.T) {
	cluster, database := newClusterTestService(t)
	if _, err := database.Exec(`UPDATE global_config SET threat_screen_mode='globe' WHERE id=1`); err != nil {
		t.Fatal(err)
	}

	snapshot, _, err := cluster.Snapshot(context.Background(), 0, "", "")
	if err != nil {
		t.Fatalf("snapshot: %v", err)
	}
	if mode := snapshot.BasicSettings.ThreatScreenMode; mode == nil || *mode != "globe" {
		t.Fatalf("快照未携带大屏视觉模式: %+v", snapshot.BasicSettings.ThreatScreenMode)
	}

	// 从端本地为默认值：apply 后必须落主端值。
	if _, err := database.Exec(`UPDATE global_config SET threat_screen_mode='map' WHERE id=1`); err != nil {
		t.Fatal(err)
	}
	if err := replaceSnapshotDB(context.Background(), database, snapshot); err != nil {
		t.Fatalf("apply snapshot: %v", err)
	}
	var mode string
	if err := database.QueryRow(`SELECT threat_screen_mode FROM global_config WHERE id=1`).Scan(&mode); err != nil {
		t.Fatal(err)
	}
	if mode != "globe" {
		t.Fatalf("应用后大屏视觉模式=%q, want globe", mode)
	}
}

// 边界形态：①旧主端快照缺席该字段（nil）→ 保留从端本地值，不清零；
// ②快照携带非法枚举（脏备份/旧版本写入）→ apply 归默认，不落脏值。
func TestClusterSnapshot_threatScreenModeApplyEdges(t *testing.T) {
	cluster, database := newClusterTestService(t)
	if _, err := database.Exec(`UPDATE global_config SET threat_screen_mode='map' WHERE id=1`); err != nil {
		t.Fatal(err)
	}
	snapshot, _, err := cluster.Snapshot(context.Background(), 0, "", "")
	if err != nil {
		t.Fatalf("snapshot: %v", err)
	}

	// ① 缺席：先把从端改成 globe，再用去掉该字段的快照 apply。
	if _, err := database.Exec(`UPDATE global_config SET threat_screen_mode='globe' WHERE id=1`); err != nil {
		t.Fatal(err)
	}
	legacy := snapshot
	legacy.BasicSettings.ThreatScreenMode = nil
	if err := replaceSnapshotDB(context.Background(), database, legacy); err != nil {
		t.Fatalf("apply legacy snapshot: %v", err)
	}
	var mode string
	if err := database.QueryRow(`SELECT threat_screen_mode FROM global_config WHERE id=1`).Scan(&mode); err != nil {
		t.Fatal(err)
	}
	if mode != "globe" {
		t.Fatalf("旧主端缺席时不得覆盖本地值: mode=%q", mode)
	}

	// ② 非法枚举：apply 归默认。
	dirty := snapshot
	invalid := "sphere"
	dirty.BasicSettings.ThreatScreenMode = &invalid
	if err := replaceSnapshotDB(context.Background(), database, dirty); err != nil {
		t.Fatalf("apply dirty snapshot: %v", err)
	}
	if err := database.QueryRow(`SELECT threat_screen_mode FROM global_config WHERE id=1`).Scan(&mode); err != nil {
		t.Fatal(err)
	}
	if mode != "map" {
		t.Fatalf("非法枚举必须归默认 map, got %q", mode)
	}
}

// 装载侧同口径归一：库内脏值（历史写入/外部直改 SQL）在主端快照里归默认，
// 否则主从两侧对同一列算出不同节哈希，每次版本递增都会重放 users 节。
func TestClusterSnapshot_threatScreenModeLoadNormalizesDirtyValue(t *testing.T) {
	cluster, database := newClusterTestService(t)
	if _, err := database.Exec(`UPDATE global_config SET threat_screen_mode='sphere' WHERE id=1`); err != nil {
		t.Fatal(err)
	}
	snapshot, _, err := cluster.Snapshot(context.Background(), 0, "", "")
	if err != nil {
		t.Fatalf("snapshot: %v", err)
	}
	if mode := snapshot.BasicSettings.ThreatScreenMode; mode == nil || *mode != "map" {
		t.Fatalf("装载侧必须把脏枚举归默认: %+v", snapshot.BasicSettings.ThreatScreenMode)
	}
}
