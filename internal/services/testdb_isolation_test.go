package services

// 测试用 DB 夹具：一个用例一个临时库，退出时把全局句柄还原到用例前的身份。
//
// 三处状态必须一起还原：db.DB / db.MetricsDB / db.AuditDB（同步侧读取）以及
// db.SetDB 注册的原子句柄（后台刷新循环经 db.GetDB 读取）。db.Close 内部会
// 调 SetDB(nil)，只写回三个包级变量的旧写法会让清理后仍在跑的后台循环看到
// nil 句柄——与 tz_test 的夹具同理。

import (
	"database/sql"
	"testing"

	"lazy-balancer-v2/internal/db"
)

// setupIsolatedDB 初始化临时库并把全部全局句柄在 t.Cleanup 中还原，
// 返回新库句柄（调用方不需要时可直接忽略返回值）。
func setupIsolatedDB(t *testing.T) *sql.DB {
	t.Helper()
	oldDB, oldMetricsDB, oldAuditDB, oldCurrent := db.DB, db.MetricsDB, db.AuditDB, db.GetDB()
	if err := db.Initialize(t.TempDir()); err != nil {
		t.Fatalf("initialize test database: %v", err)
	}
	database := db.DB
	t.Cleanup(func() {
		_ = db.Close()
		db.DB, db.MetricsDB, db.AuditDB = oldDB, oldMetricsDB, oldAuditDB
		db.SetDB(oldCurrent)
	})
	return database
}
