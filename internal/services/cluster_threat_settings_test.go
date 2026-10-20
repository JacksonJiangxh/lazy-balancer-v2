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
