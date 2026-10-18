package services

// 历史问题-1(历史,历史问题——幻影修复):历史问题-1 的 sync_interval 展示 clamp
// 被插入 if err != nil 分支 return 之后(unreachable,go vet 机器诊断)——
// Status() 展示链对存量脏值(0/负/1-9s)仍原样展示,与运行时 60s clamp 分叉。
// 本测试钉住:脏值入库 → Status() 读出已 clamp 值。

import (
	"context"
	"fmt"
	"testing"
	"time"

	"lazy-balancer-v2/internal/db"
)

func TestClusterStatus_syncIntervalDisplayClamp(t *testing.T) {
	cases := []struct {
		stored int
		want   int
	}{
		{0, 60},    // 脏值 0 → clamp 60
		{-5, 60},   // 负值 → 60
		{5, 60},    // 1-9s → 60
		{10, 10},   // 边界 10 不 clamp
		{60, 60},   // 正常值不变
		{120, 120}, // 大于 60 不变
		{86400, 86400},
		{86401, 86400},
		{1000000, 86400},
	}
	for _, tc := range cases {
		t.Run(fmt.Sprintf("stored_%d", tc.stored), func(t *testing.T) {
			if err := db.Initialize(t.TempDir()); err != nil {
				t.Fatal(err)
			}
			if _, err := db.DB.Exec("UPDATE global_config SET sync_interval=? WHERE id=1", tc.stored); err != nil {
				t.Fatal(err)
			}
			svc := NewClusterService(db.DB, t.TempDir())
			status, err := svc.Status(context.Background())
			if err != nil {
				t.Fatal(err)
			}
			if status.SyncInterval != tc.want {
				t.Fatalf("Status().SyncInterval=%d (stored %d), want %d", status.SyncInterval, tc.stored, tc.want)
			}
		})
	}
}

func TestNodeOfflineThreshold_clampsExcessiveSyncInterval(t *testing.T) {
	if got := nodeOfflineThreshold(1000000); got != 2*86400*time.Second {
		t.Fatalf("nodeOfflineThreshold=%v, want %v", got, 2*86400*time.Second)
	}
}
