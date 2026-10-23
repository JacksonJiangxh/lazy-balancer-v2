package services

import (
	"bytes"
	"log"
	"strings"
	"testing"

	"lazy-balancer-v2/internal/db"
)

func initScheduleTestDB(t *testing.T) {
	t.Helper()
	oldDB, oldMetricsDB, oldAuditDB := db.DB, db.MetricsDB, db.AuditDB
	oldCurrent := db.GetDB()
	if err := db.Initialize(t.TempDir()); err != nil {
		t.Fatalf("initialize database: %v", err)
	}
	t.Cleanup(func() {
		_ = db.Close()
		db.DB, db.MetricsDB, db.AuditDB = oldDB, oldMetricsDB, oldAuditDB
		// 后台循环句柄（db.GetDB）同样复位——Close 只置 nil，不还原旧值。
		db.SetDB(oldCurrent)
	})
	isolateMetricsState(t)
}

// 版本表族排程保存必须事务化——INSERT 初始化行与
// UPDATE 排程要么同时生效、要么同时回滚，不得留「行已建、排程未生效、
// next_update 为空」的中间态。
func TestSetVersionTableSchedule_isAtomicOnUpdateFailure(t *testing.T) {
	initScheduleTestDB(t)
	useShanghaiLocation(t)
	if _, err := db.DB.Exec(`CREATE TRIGGER reject_crs_schedule BEFORE UPDATE ON security_crs_version
		BEGIN SELECT RAISE(ABORT, 'boom'); END`); err != nil {
		t.Fatalf("create trigger: %v", err)
	}
	if _, err := db.DB.Exec(`DELETE FROM security_crs_version`); err != nil {
		t.Fatalf("clear version row: %v", err)
	}

	// When：UPDATE 被触发器拒绝
	err := SetCRSSchedule(allWeek(), "04:00")

	// Then：报错且初始化行随事务回滚（不得留下「行已建、排程未生效」形态）
	if err == nil {
		t.Fatal("SetCRSSchedule error=nil, want 触发器拒绝后报错")
	}
	var count int
	if qerr := db.DB.QueryRow("SELECT COUNT(*) FROM security_crs_version").Scan(&count); qerr != nil {
		t.Fatalf("count rows: %v", qerr)
	}
	if count != 0 {
		t.Fatalf("version rows=%d, want 0（INSERT 必须随事务回滚）", count)
	}

	// 回归形状：去掉触发器后同一调用成功且排程生效。
	if _, err := db.DB.Exec("DROP TRIGGER reject_crs_schedule"); err != nil {
		t.Fatalf("drop trigger: %v", err)
	}
	if err := SetCRSSchedule(allWeek(), "04:30"); err != nil {
		t.Fatalf("SetCRSSchedule: %v", err)
	}
	var hhmm string
	if err := db.DB.QueryRow("SELECT schedule_time FROM security_crs_version WHERE id=1").Scan(&hhmm); err != nil {
		t.Fatalf("read schedule_time: %v", err)
	}
	if hhmm != "04:30" {
		t.Fatalf("schedule_time=%q, want 04:30", hhmm)
	}
}

// 自动更新开关的两步写必须事务化（与排程保存同构）：INSERT 成功而 UPDATE
// 失败会留「行已建、auto_update=1、next_update 空」的中间态——开关显示已开、
// 任务永不触发，且失败只经一次 handler 响应留痕。
func TestSetVersionTableAutoUpdate_rollsBackOnUpdateFailure(t *testing.T) {
	initScheduleTestDB(t)
	useShanghaiLocation(t)
	if _, err := db.DB.Exec(`CREATE TRIGGER reject_crs_auto_update BEFORE UPDATE ON security_crs_version
		BEGIN SELECT RAISE(ABORT, 'boom'); END`); err != nil {
		t.Fatalf("create trigger: %v", err)
	}
	if _, err := db.DB.Exec(`DELETE FROM security_crs_version`); err != nil {
		t.Fatalf("clear version row: %v", err)
	}

	// When：UPDATE 被触发器拒绝
	err := SetCRSAutoUpdate(true)

	// Then：报错且初始化行随事务回滚（不得留空 next_update 的中间态）
	if err == nil {
		t.Fatal("SetCRSAutoUpdate error=nil, want 触发器拒绝后报错")
	}
	var count int
	if qerr := db.DB.QueryRow("SELECT COUNT(*) FROM security_crs_version").Scan(&count); qerr != nil {
		t.Fatalf("count rows: %v", qerr)
	}
	if count != 0 {
		t.Fatalf("version rows=%d, want 0（INSERT 必须随事务回滚）", count)
	}

	// 回归形状：去掉触发器后同一调用成功且槽位已武装。
	if _, err := db.DB.Exec("DROP TRIGGER reject_crs_auto_update"); err != nil {
		t.Fatalf("drop trigger: %v", err)
	}
	if err := SetCRSAutoUpdate(true); err != nil {
		t.Fatalf("SetCRSAutoUpdate: %v", err)
	}
	var next string
	if err := db.DB.QueryRow("SELECT COALESCE(next_update,'') FROM security_crs_version WHERE id=1").Scan(&next); err != nil {
		t.Fatalf("read next_update: %v", err)
	}
	if next == "" {
		t.Fatal("开启自动更新后 next_update 必须已落槽（空槽=任务永不触发）")
	}
}

// 排程读取失败必须留痕（首报 warn）且不得 panic——
// 此前三处读错误全部静默，库不可读时自动更新静默停摆且排障零信号。
func TestScheduleReaders_logReadFailure(t *testing.T) {
	initScheduleTestDB(t)
	var logs bytes.Buffer
	originalWriter := log.Writer()
	log.SetOutput(&logs)
	t.Cleanup(func() { log.SetOutput(originalWriter) })

	if _, err := db.DB.Exec("DROP TABLE security_crs_version"); err != nil {
		t.Fatalf("drop table: %v", err)
	}
	if _, err := db.DB.Exec("DROP TABLE security_threat_sources"); err != nil {
		t.Fatalf("drop threat sources: %v", err)
	}

	// When：版本表/任务级排程读取全部命中错误
	days, hhmm := versionTableSchedule("security_crs_version")
	if len(days) == 0 || hhmm == "" {
		t.Fatalf("版本表读失败应回落默认排程, got %v %q", days, hhmm)
	}
	crawlerDays, crawlerHHMM := globalTaskSchedule("does_not_exist")
	if len(crawlerDays) == 0 || crawlerHHMM == "" {
		t.Fatalf("任务级排程读失败应回落默认排程, got %v %q", crawlerDays, crawlerHHMM)
	}

	// Then：失败留痕（含表/列名，首报一条）
	if !strings.Contains(logs.String(), "读取任务排程失败") {
		t.Fatalf("logs=%q, want 含「读取任务排程失败」", logs.String())
	}

	// 畸形形状：nil 库守卫——不得 panic，返回默认排程。
	db.DB = nil
	if days, hhmm := globalTaskSchedule("threat"); len(days) == 0 || hhmm == "" {
		t.Fatalf("nil 库应返回默认排程, got %v %q", days, hhmm)
	}
	if _, hhmm := versionTableSchedule("security_crs_version"); hhmm == "" {
		t.Fatalf("nil 库版本表排程应回落默认, got %q", hhmm)
	}
}
