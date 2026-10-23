package services

// 集群快照的 break-glass 标记传递：新主端载荷携带 is_setup_admin 时从节点
// 原样落库；旧主端载荷（无该字段）时从节点按「最低 id 的启用管理员」本地
// 重建，保证保护面可用。

import (
	"context"
	"testing"
	"time"

	"lazy-balancer-v2/internal/models"
)

func TestInsertSnapshotUsers_carriesSetupAdminFlag(t *testing.T) {
	_, database := newClusterTestService(t)
	ctx := context.Background()
	tx, err := database.Begin()
	if err != nil {
		t.Fatalf("begin: %v", err)
	}
	defer tx.Rollback()
	users := []models.ClusterUser{
		{ID: 1, Username: "plain-admin", PasswordHash: "h", Role: "admin", IsEnabled: true, CreatedAt: time.Now()},
		{ID: 4, Username: "setup-admin", PasswordHash: "h", Role: "admin", IsEnabled: true, CreatedAt: time.Now(), IsSetupAdmin: true},
	}
	if err := insertSnapshotUsersAndKeys(ctx, tx, models.ClusterSnapshot{Users: users}); err != nil {
		t.Fatalf("insert snapshot users: %v", err)
	}
	if err := tx.Commit(); err != nil {
		t.Fatalf("commit: %v", err)
	}
	var flagged string
	if err := database.QueryRow(`SELECT username FROM users WHERE COALESCE(is_setup_admin,0)=1`).Scan(&flagged); err != nil {
		t.Fatalf("read flagged user: %v", err)
	}
	if flagged != "setup-admin" {
		t.Fatalf("flagged=%q, want setup-admin（标记随载荷落库）", flagged)
	}
}

func TestInsertSnapshotUsers_rebuildsMarkerWhenPayloadLacksIt(t *testing.T) {
	_, database := newClusterTestService(t)
	ctx := context.Background()
	tx, err := database.Begin()
	if err != nil {
		t.Fatalf("begin: %v", err)
	}
	defer tx.Rollback()
	// 旧主端载荷：无 is_setup_admin 字段（全零值）。
	users := []models.ClusterUser{
		{ID: 2, Username: "user-a", PasswordHash: "h", Role: "user", IsEnabled: true, CreatedAt: time.Now()},
		{ID: 5, Username: "admin-a", PasswordHash: "h", Role: "admin", IsEnabled: true, CreatedAt: time.Now()},
		{ID: 6, Username: "admin-b", PasswordHash: "h", Role: "admin", IsEnabled: true, CreatedAt: time.Now()},
	}
	if err := insertSnapshotUsersAndKeys(ctx, tx, models.ClusterSnapshot{Users: users}); err != nil {
		t.Fatalf("insert snapshot users: %v", err)
	}
	if err := tx.Commit(); err != nil {
		t.Fatalf("commit: %v", err)
	}
	var flagged int
	if err := database.QueryRow(`SELECT id FROM users WHERE COALESCE(is_setup_admin,0)=1`).Scan(&flagged); err != nil {
		t.Fatalf("read flagged user: %v", err)
	}
	if flagged != 5 {
		t.Fatalf("flagged id=%d, want 5（最低 id 的启用管理员）", flagged)
	}
}
