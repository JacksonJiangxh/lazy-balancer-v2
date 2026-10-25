package services

// 集群快照的 break-glass 标记：users 节在 canonical 载荷（v3 唯一下发形态）
// 里由 sanitizeUsersForHash 清零，标记**不随快照同步**；从节点落库后按
// 「最低 id 的启用管理员」本地归一（db.EnsureSetupAdminFlag）。

import (
	"context"
	"database/sql"
	"testing"
	"time"

	"lazy-balancer-v2/internal/models"
)

// countFlaggedUsers 返回 users 表中带保护标记的行数：归一的「恰一个」不变量
// 由该计数断言，而非只看被补标的那一行。
func countFlaggedUsers(t *testing.T, database *sql.DB, ctx context.Context) int {
	t.Helper()
	var n int
	if err := database.QueryRow(`SELECT COUNT(*) FROM users WHERE COALESCE(is_setup_admin,0)=1`).Scan(&n); err != nil {
		t.Fatalf("count flagged users: %v", err)
	}
	return n
}

// TestSnapshotCanonicalDropsSetupAdminMarker 覆盖真实下发形态：主端标记即使
// 落在非最低 id 的启用管理员上，canonical 载荷也会把它清零；从节点落库后
// 由归一补标最低 id 的启用管理员——保护对象按本地用户表重建，不随载荷同步。
func TestSnapshotCanonicalDropsSetupAdminMarker(t *testing.T) {
	_, database := newClusterTestService(t)
	ctx := context.Background()

	// 主端带外形态：标记落在非最低 id 的启用管理员上。
	users := []models.ClusterUser{
		{ID: 1, Username: "plain-admin", PasswordHash: "h", Role: "admin", IsEnabled: true, CreatedAt: time.Now()},
		{ID: 4, Username: "setup-admin", PasswordHash: "h", Role: "admin", IsEnabled: true, CreatedAt: time.Now(), IsSetupAdmin: true},
	}
	canonical := sanitizeUsersForHash(users)
	for _, u := range canonical {
		if u.IsSetupAdmin {
			t.Fatalf("canonical payload carries is_setup_admin for %q（标记不随快照同步）", u.Username)
		}
	}

	tx, err := database.Begin()
	if err != nil {
		t.Fatalf("begin: %v", err)
	}
	defer tx.Rollback()
	if err := insertSnapshotUsersAndKeys(ctx, tx, models.ClusterSnapshot{Users: canonical}); err != nil {
		t.Fatalf("insert snapshot users: %v", err)
	}
	if err := tx.Commit(); err != nil {
		t.Fatalf("commit: %v", err)
	}

	var flagged string
	if err := database.QueryRow(`SELECT username FROM users WHERE COALESCE(is_setup_admin,0)=1`).Scan(&flagged); err != nil {
		t.Fatalf("read flagged user: %v", err)
	}
	if flagged != "plain-admin" {
		t.Fatalf("flagged=%q, want plain-admin（从节点按最低 id 的启用管理员重建）", flagged)
	}
	if n := countFlaggedUsers(t, database, ctx); n != 1 {
		t.Fatalf("flagged rows=%d, want 1（归一后恰一个保护入口）", n)
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
	if n := countFlaggedUsers(t, database, ctx); n != 1 {
		t.Fatalf("flagged rows=%d, want 1（归一后恰一个保护入口）", n)
	}
}
