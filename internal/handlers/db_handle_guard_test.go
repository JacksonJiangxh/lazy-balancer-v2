package handlers

import (
	"database/sql"
	"testing"

	"lazy-balancer-v2/internal/db"
)

// 本文件只剩 handlers 包内的**句柄生命周期** helper。
//
// 句柄守卫（计数/结算/上限断言）已上提为跨包单源 internal/testsupport
// （CheckDBHandleGoroutines，JJC-20261115-003-B3）：handlers 与 middleware
// 各自复制一份判据时，任何一处修补都会漏掉另一处。守卫的判别力自证也随之
// 迁到 testsupport/dbhandle_test.go（同包可调私有函数）。
//
// 留在本包的理由：下面两个 helper 依赖 handlers 的测试库约定
// （db.InitializeAuditDB 覆盖包级 db.AuditDB、单用例二次 Initialize 覆盖三
// 句柄），跨包复用没有收益。

// initAuditDBForTest 统一测试审计库的生命周期：InitializeAuditDB 成功路径
// 直接覆盖包级 db.AuditDB 且不关旧值（生产进程单次调用无碍），测试必须
// 显式关闭本轮新句柄再恢复入场前的句柄——只恢复不关即每调用泄漏 1 个
// 未关闭 *sql.DB（opener+cleaner 协程常驻到进程结束，见 testsupport/dbhandle.go
// 的守卫说明）。
func initAuditDBForTest(t *testing.T, dataDir string) {
	t.Helper()
	previous := db.AuditDB
	if err := db.InitializeAuditDB(dataDir); err != nil {
		t.Fatalf("initialize test audit database: %v", err)
	}
	current := db.AuditDB
	t.Cleanup(func() {
		db.AuditDB = previous
		if current != nil && current != previous {
			_ = current.Close()
		}
	})
}

// closeSupersededTestDBHandles 关闭被新一轮 Initialize 覆盖掉的包级句柄。
// 单用例内二次 Initialize（迁移回归测试）必须显式关闭上一轮三句柄，否则
// 它们被覆盖后不可达、永不 Close（见本文件顶部说明）。
func closeSupersededTestDBHandles(database *sql.DB, metrics *sql.DB, audit *sql.DB) {
	for _, handle := range []*sql.DB{database, metrics, audit} {
		if handle != nil {
			_ = handle.Close()
		}
	}
}
