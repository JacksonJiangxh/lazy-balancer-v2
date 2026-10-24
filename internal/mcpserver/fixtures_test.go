package mcpserver_test

import (
	"database/sql"

	"lazy-balancer-v2/internal/db"
)

// restoreMCPDatabaseHandles 复位夹具数据库句柄的单源序列（与包内同名 helper
// 同语义，两个测试包各自持有一份）：db.Close() 会 SetDB(nil)，只还原三个
// 包级变量会让 db.GetDB() 与 db.DB 在测试间分叉。
func restoreMCPDatabaseHandles(oldDB, oldMetricsDB, oldAuditDB *sql.DB) {
	db.DB, db.MetricsDB, db.AuditDB = oldDB, oldMetricsDB, oldAuditDB
	db.SetDB(oldDB)
}
