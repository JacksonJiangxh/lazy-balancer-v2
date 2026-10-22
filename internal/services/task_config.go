package services

import (
	"fmt"

	"lazy-balancer-v2/internal/db"
)

// setGlobalTaskAutoUpdate 写任务级自动更新总闸（global_config 列前缀隔离），
// 并直接驱动对应 StartLoop/StopLoop（业务开关是调度唯一事实源）。
func setGlobalTaskAutoUpdate(prefix string, enabled bool) error {
	if _, err := db.DB.Exec(`UPDATE global_config SET `+prefix+`_auto_update=?, updated_at=datetime('now') WHERE id=1`, enabled); err != nil {
		return fmt.Errorf("更新规则库自动更新开关: %w", err)
	}
	id := prefix
	if prefix == "crawler" {
		id = "crawlerbot-update"
	}
	syncTaskLoop(id, enabled)
	return nil
}

// globalTaskAutoUpdateEnabled 读任务级总闸（读错 fail-closed=视为关）。
// 与 AutoBackupEnabled 同族口径：读错必须留痕，否则库故障与「用户关闭」在
// 任务面完全同形（静默停摆、零失败行）。
func globalTaskAutoUpdateEnabled(prefix string) bool {
	if db.DB == nil {
		return false
	}
	var v int
	key := "schedule-read-" + prefix + "-auto-update"
	if err := db.DB.QueryRow(`SELECT COALESCE(` + prefix + `_auto_update,1) FROM global_config WHERE id=1`).Scan(&v); err != nil {
		logScheduleReadFailure(key, err)
		return false
	}
	logScheduleReadRecovered(key)
	return v != 0
}
