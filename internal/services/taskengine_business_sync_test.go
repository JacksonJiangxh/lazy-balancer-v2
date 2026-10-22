package services

import (
	"testing"

	"lazy-balancer-v2/internal/db"
)

// setAutoBackupEnabledForTest 是业务开关写侧的测试专用组合：生产写侧唯一
// 入口是 SetAutoBackupEnabledTx（调用方事务）+ SyncAutoBackupTaskLoop，本 helper
// 只在本测试里把两步拼成「自开事务」形态（测试消费的旧入口已删除）。
func setAutoBackupEnabledForTest(enabled bool) error {
	tx, err := db.DB.Begin()
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback() }()
	if err := SetAutoBackupEnabledTx(tx, enabled); err != nil {
		return err
	}
	if err := tx.Commit(); err != nil {
		return err
	}
	SyncAutoBackupTaskLoop(enabled)
	return nil
}

// 业务开关写侧 → 引擎 LoopOn：四个规则库/备份任务逐一直测，
// 与 crawler/autoban 的既有钉共同覆盖全部六个业务驱动任务。
func TestBusinessSetters_syncEngineLoop(t *testing.T) {
	cases := []struct {
		id  string
		set func(bool) error
	}{
		{id: "threat", set: SetThreatAutoUpdate},
		{id: "crs", set: SetCRSAutoUpdate},
		{id: "ip2region", set: SetIP2RegionAutoUpdate},
		{id: "auto-backup", set: setAutoBackupEnabledForTest},
	}
	for _, tc := range cases {
		t.Run(tc.id, func(t *testing.T) {
			te := newWireTestEngine(t)
			loopOn := func() bool {
				meta, ok := te.Lookup(tc.id)
				if !ok {
					t.Fatalf("%s 未注册", tc.id)
				}
				return meta.LoopOn
			}
			if err := tc.set(false); err != nil {
				t.Fatal(err)
			}
			if loopOn() {
				t.Errorf("%s 禁用后 LoopOn=true", tc.id)
			}
			if err := tc.set(true); err != nil {
				t.Fatal(err)
			}
			if !loopOn() {
				t.Errorf("%s 启用后 LoopOn=false", tc.id)
			}
		})
	}
}
