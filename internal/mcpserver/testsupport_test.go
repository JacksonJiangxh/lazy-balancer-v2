package mcpserver

import (
	"database/sql"

	"lazy-balancer-v2/internal/db"
)

// restoreMCPDatabaseHandles 复位夹具数据库句柄的单源序列：db.Close() 会
// SetDB(nil)，只还原三个包级变量会让 db.GetDB() 与 db.DB 在测试间分叉
// （后续依赖 GetDB() 的用例读到 nil，表现为顺序依赖假红）。
func restoreMCPDatabaseHandles(oldDB, oldMetricsDB, oldAuditDB *sql.DB) {
	db.DB, db.MetricsDB, db.AuditDB = oldDB, oldMetricsDB, oldAuditDB
	db.SetDB(oldDB)
}
