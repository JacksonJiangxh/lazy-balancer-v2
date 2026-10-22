package services

import (
	"context"
	"testing"
	"time"

	"lazy-balancer-v2/internal/models"
)

// 从端落库用秒精度 crsTimeLayout；快照哈希输入必须同精度，否则主从节哈希
// 永久不等并触发多余全量重拉。
func TestSnapshotTime_truncatesToSecond(t *testing.T) {
	in := time.Date(2026, 10, 19, 4, 5, 6, 123456789, time.FixedZone("CST", 8*3600))
	got := snapshotTime(in)
	want := time.Date(2026, 10, 18, 20, 5, 6, 0, time.UTC)
	if !got.Equal(want) {
		t.Fatalf("snapshotTime=%v, want %v", got, want)
	}
	if got.Nanosecond() != 0 {
		t.Fatalf("nanosecond=%d, want 0", got.Nanosecond())
	}
	if !snapshotTime(time.Time{}).IsZero() {
		t.Fatal("zero time must stay zero")
	}
}

// 规则时间戳按秒/UTC 归一——运行期带亚秒/时区偏移的写入不再让
// rules 节哈希主从形态分叉。
func TestSnapshotRules_truncatesTimestampsToSecondUTC(t *testing.T) {
	service, database := newClusterTestService(t)
	ctx := context.Background()
	if _, err := database.Exec(`INSERT INTO lb_rules (caddy_id,name,protocol,domain,listen_port,created_at,updated_at)
		VALUES ('lb_ts','ts','http','ts.example.com',80,'2026-10-19T12:00:00.123456789+08:00','2026-10-19T13:00:00.987654321+08:00')`); err != nil {
		t.Fatalf("seed rule with fractional timestamps: %v", err)
	}
	rules, err := service.snapshotRules(ctx, database)
	if err != nil {
		t.Fatalf("snapshot rules: %v", err)
	}
	if len(rules) != 1 {
		t.Fatalf("rules=%d, want 1", len(rules))
	}
	rule := rules[0]
	wantCreated := time.Date(2026, 10, 19, 4, 0, 0, 0, time.UTC)
	if !rule.CreatedAt.Equal(wantCreated) || rule.CreatedAt.Nanosecond() != 0 {
		t.Fatalf("created_at=%v, want %v (second precision UTC)", rule.CreatedAt, wantCreated)
	}
	if !rule.UpdatedAt.Valid || rule.UpdatedAt.Time.Nanosecond() != 0 {
		t.Fatalf("updated_at=%v, want second precision", rule.UpdatedAt.Time)
	}
	if want := time.Date(2026, 10, 19, 5, 0, 0, 0, time.UTC); !rule.UpdatedAt.Time.Equal(want) {
		t.Fatalf("updated_at=%v, want %v", rule.UpdatedAt.Time, want)
	}

	// 哈希稳定：两次重建同形（修复前亚秒形态随驱动序列化差异分叉）。
	first := ComputeSnapshotSectionHashes(&models.ClusterSnapshot{Rules: rules})["rules"]
	rulesAgain, err := service.snapshotRules(ctx, database)
	if err != nil {
		t.Fatalf("snapshot rules second run: %v", err)
	}
	second := ComputeSnapshotSectionHashes(&models.ClusterSnapshot{Rules: rulesAgain})["rules"]
	if first == "" || first != second {
		t.Fatalf("rules hash unstable: %q vs %q", first, second)
	}
}
