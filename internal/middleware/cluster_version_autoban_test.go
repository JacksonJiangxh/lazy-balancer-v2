package middleware

// D1（历史·R74C）：global_config 触发器 OF 清单补自动封禁六列——
// 主端 PUT /security/autoban 保存（六列 UPDATE）不 bump cluster_version 时，
// 稳态变更经 304 门滞留主节点、永不传播到从节点（从端升主后按陈旧默认值
// 运行）。钉六列各自的 OF 成员资格（镜像 历史问题 自动备份组钉测形态）。

import "testing"

func TestClusterVersionTrigger_autobanSettingsBump(t *testing.T) {
	database := newClusterVersionTestDB(t)
	if err := installClusterVersionTriggers(database); err != nil {
		t.Fatal(err)
	}
	if _, err := database.Exec("UPDATE global_config SET is_master=1,cluster_version=0 WHERE id=1"); err != nil {
		t.Fatal(err)
	}
	for i, stmt := range []string{
		"UPDATE global_config SET autoban_enabled=1 WHERE id=1",
		"UPDATE global_config SET autoban_threshold=42 WHERE id=1",
		"UPDATE global_config SET autoban_window_minutes=13 WHERE id=1",
		"UPDATE global_config SET autoban_duration='24h' WHERE id=1",
		"UPDATE global_config SET autoban_scope='blocked' WHERE id=1",
		"UPDATE global_config SET autoban_dry_run=0 WHERE id=1",
	} {
		if _, err := database.Exec(stmt); err != nil {
			t.Fatal(err)
		}
		if got := clusterVersion(t, database); got != i+1 {
			t.Fatalf("%q should bump cluster_version to %d, got %d", stmt, i+1, got)
		}
	}
	// 从端写入不 bump（WHEN is_master 守卫——快照 apply 形态）
	if _, err := database.Exec("UPDATE global_config SET is_master=0 WHERE id=1"); err != nil {
		t.Fatal(err)
	}
	if _, err := database.Exec("UPDATE global_config SET autoban_threshold=77 WHERE id=1"); err != nil {
		t.Fatal(err)
	}
	if got := clusterVersion(t, database); got != 6 {
		t.Fatalf("slave write must not bump, got %d", got)
	}
}
