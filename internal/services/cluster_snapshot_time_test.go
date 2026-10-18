package services

import (
	"testing"
	"time"
)

// 从端落库用秒精度 crsTimeLayout；快照哈希输入必须同精度，否则主从节哈希
// 永久不等并触发多余全量重拉（D2-历史问题）。
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
