package services

import (
	"context"
	"database/sql"
	"fmt"
	"testing"

	"lazy-balancer-v2/internal/db"
	"lazy-balancer-v2/internal/models"
)

// 回归锁定：跳过的节（开关关闭或哈希一致）绝不能被 DELETE 清空——
// 从节点 users 被清空导致登录票据 user_unavailable 的根因。
func TestReplaceSnapshotTx_SkippedSectionsAreNotCleared(t *testing.T) {
	_, database := newClusterTestService(t)
	ctx := context.Background()

	// 本地已有用户与规则
	if _, err := database.ExecContext(ctx,
		`INSERT INTO users (id,username,password_hash,role,is_enabled) VALUES (1,'local-admin','hash','admin',1);
		 INSERT INTO lb_rules (caddy_id,name,protocol,listen_port,enabled) VALUES ('lb_local','local','http',8080,1)`,
	); err != nil {
		t.Fatalf("seed local data: %v", err)
	}

	// 快照：规则节内容不同、users 节哈希一致（跳过）
	snapshot := models.ClusterSnapshot{
		Version: 9,
		Rules:   []models.LbRule{}, // 空 = 主节点无规则
	}
	snapshot.SectionHashes = map[string]string{"users": "u9", "rules": "r9"}

	tx, err := database.BeginTx(ctx, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer tx.Rollback()

	// users 哈希一致 → skip；rules 应用（清空主节点已删的规则）
	sk := &sectionSkips{disabled: map[string]bool{}, unchanged: map[string]bool{"users": true}}
	if err := replaceSnapshotTx(ctx, tx, snapshot, sk); err != nil {
		t.Fatalf("replaceSnapshotTx: %v", err)
	}

	var userCount, ruleCount int
	if err := tx.QueryRowContext(ctx, "SELECT COUNT(*) FROM users").Scan(&userCount); err != nil {
		t.Fatalf("count users: %v", err)
	}
	if err := tx.QueryRowContext(ctx, "SELECT COUNT(*) FROM lb_rules").Scan(&ruleCount); err != nil {
		t.Fatalf("count rules: %v", err)
	}
	if userCount != 1 {
		t.Fatalf("skipped users section must keep local rows, got %d", userCount)
	}
	if ruleCount != 0 {
		t.Fatalf("applied rules section must mirror snapshot (empty), got %d", ruleCount)
	}
}

func TestReplaceSnapshotTx_DisabledSwitchKeepsLocalAndIgnoresSnapshot(t *testing.T) {
	_, database := newClusterTestService(t)
	ctx := context.Background()

	if _, err := database.ExecContext(ctx,
		`INSERT INTO users (id,username,password_hash,role,is_enabled) VALUES (1,'local-admin','hash','admin',1)`,
	); err != nil {
		t.Fatalf("seed local user: %v", err)
	}

	// 快照携带不同用户，但开关关闭 → 本地保留
	snapshot := models.ClusterSnapshot{
		Version: 4,
		Users:   []models.ClusterUser{{ID: 7, Username: "master-user", PasswordHash: "h", Role: "admin", IsEnabled: true}},
	}
	tx, err := database.BeginTx(ctx, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer tx.Rollback()

	sk := &sectionSkips{disabled: map[string]bool{"users": true}, unchanged: map[string]bool{}}
	if err := replaceSnapshotTx(ctx, tx, snapshot, sk); err != nil {
		t.Fatalf("replaceSnapshotTx: %v", err)
	}

	var username string
	if err := tx.QueryRowContext(ctx, "SELECT username FROM users WHERE id=1").Scan(&username); err != nil || username != "local-admin" {
		t.Fatalf("disabled users section must keep local-admin, got %q err=%v", username, err)
	}
	var count int
	tx.QueryRowContext(ctx, "SELECT COUNT(*) FROM users").Scan(&count)
	if count != 1 {
		t.Fatalf("snapshot user must not be inserted when switch off, got %d users", count)
	}
}

func applySnapshotBasicSettingsForTest(t *testing.T, database *sql.DB, settings models.ClusterBasicSettings) {
	t.Helper()
	tx, err := database.BeginTx(context.Background(), nil)
	if err != nil {
		t.Fatal(err)
	}
	defer tx.Rollback()
	if err := updateSnapshotSettings(context.Background(), tx, models.ClusterSnapshot{BasicSettings: settings}); err != nil {
		t.Fatalf("update snapshot settings: %v", err)
	}
	if err := tx.Commit(); err != nil {
		t.Fatal(err)
	}
}

func TestUpdateSnapshotSettings_normalizesCertExpiryDays(t *testing.T) {
	for _, tc := range []struct {
		stored int
		want   int
	}{
		{stored: 0, want: db.DefaultCertExpiryDays},
		{stored: 366, want: db.DefaultCertExpiryDays},
		{stored: 100000, want: db.DefaultCertExpiryDays},
		{stored: 1, want: 1},
		{stored: 365, want: 365},
	} {
		t.Run(fmt.Sprint(tc.stored), func(t *testing.T) {
			_, database := newClusterTestService(t)
			applySnapshotBasicSettingsForTest(t, database, models.ClusterBasicSettings{CertExpiryDays: new(tc.stored)})
			var got int
			if err := database.QueryRow("SELECT cert_expiry_days FROM global_config WHERE id=1").Scan(&got); err != nil {
				t.Fatal(err)
			}
			if got != tc.want {
				t.Fatalf("cert_expiry_days=%d, want %d", got, tc.want)
			}
		})
	}
}

func TestUpdateSnapshotSettings_normalizesSyncInterval(t *testing.T) {
	for _, tc := range []struct {
		stored int
		want   int
	}{
		{stored: 5, want: 60},
		{stored: 86401, want: 86400},
		{stored: 1000000, want: 86400},
		{stored: 10, want: 10},
		{stored: 86400, want: 86400},
	} {
		t.Run(fmt.Sprint(tc.stored), func(t *testing.T) {
			_, database := newClusterTestService(t)
			applySnapshotBasicSettingsForTest(t, database, models.ClusterBasicSettings{SyncInterval: new(tc.stored)})
			var got int
			if err := database.QueryRow("SELECT sync_interval FROM global_config WHERE id=1").Scan(&got); err != nil {
				t.Fatal(err)
			}
			if got != tc.want {
				t.Fatalf("sync_interval=%d, want %d", got, tc.want)
			}
		})
	}
}

func TestReplaceSnapshotTx_usersSkipNormalizesSyncInterval(t *testing.T) {
	_, database := newClusterTestService(t)
	if _, err := database.Exec("UPDATE global_config SET is_master=0 WHERE id=1"); err != nil {
		t.Fatal(err)
	}
	tx, err := database.BeginTx(context.Background(), nil)
	if err != nil {
		t.Fatal(err)
	}
	defer tx.Rollback()
	snapshot := models.ClusterSnapshot{BasicSettings: models.ClusterBasicSettings{SyncInterval: new(1000000)}}
	if err := replaceSnapshotTx(context.Background(), tx, snapshot, &sectionSkips{disabled: map[string]bool{"users": true}, unchanged: map[string]bool{}}); err != nil {
		t.Fatal(err)
	}
	var got int
	if err := tx.QueryRow("SELECT sync_interval FROM global_config WHERE id=1").Scan(&got); err != nil {
		t.Fatal(err)
	}
	if got != 86400 {
		t.Fatalf("sync_interval=%d, want upper clamp 86400 on users-skip path", got)
	}
}

func TestUpdateSnapshotSettings_normalizesSecurityEventValueDomains(t *testing.T) {
	_, database := newClusterTestService(t)
	applySnapshotBasicSettingsForTest(t, database, models.ClusterBasicSettings{
		ThreatTrafficSampleN:        new(8),
		SecurityEventsRetentionDays: new(3651),
		SecurityEventsRowCap:        new(100000001),
	})
	var sample, days, cap int
	if err := database.QueryRow(`SELECT threat_traffic_sample_n,security_events_retention_days,security_events_row_cap FROM global_config WHERE id=1`).Scan(&sample, &days, &cap); err != nil {
		t.Fatal(err)
	}
	if sample != -1 || days != securityEventsRetentionDefaultDays || cap != securityEventsRetentionDefaultMax {
		t.Fatalf("normalized=(sample %d,days %d,cap %d), want -1/%d/%d", sample, days, cap, securityEventsRetentionDefaultDays, securityEventsRetentionDefaultMax)
	}

	applySnapshotBasicSettingsForTest(t, database, models.ClusterBasicSettings{
		ThreatTrafficSampleN:        new(100),
		SecurityEventsRetentionDays: new(-1),
		SecurityEventsRowCap:        new(0),
	})
	if err := database.QueryRow(`SELECT threat_traffic_sample_n,security_events_retention_days,security_events_row_cap FROM global_config WHERE id=1`).Scan(&sample, &days, &cap); err != nil {
		t.Fatal(err)
	}
	if sample != -1 || days != securityEventsRetentionDefaultDays || cap != securityEventsRetentionDefaultMax {
		t.Fatalf("normalized lower/bogus=(sample %d,days %d,cap %d)", sample, days, cap)
	}

	applySnapshotBasicSettingsForTest(t, database, models.ClusterBasicSettings{
		ThreatTrafficSampleN:        new(0),
		SecurityEventsRetentionDays: new(3650),
		SecurityEventsRowCap:        new(100000000),
	})
	if err := database.QueryRow(`SELECT threat_traffic_sample_n,security_events_retention_days,security_events_row_cap FROM global_config WHERE id=1`).Scan(&sample, &days, &cap); err != nil {
		t.Fatal(err)
	}
	if sample != 0 || days != 3650 || cap != 100000000 {
		t.Fatalf("valid values changed=(sample %d,days %d,cap %d)", sample, days, cap)
	}
}
