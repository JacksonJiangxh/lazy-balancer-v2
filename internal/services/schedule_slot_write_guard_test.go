package services

// 写路径的排程读取必须是严格形态：一次瞬时读失败不得按读侧 fail-soft 的默认
// 排程（每天 04:00）算出下一槽并落库——用户的「星期几 + HH:MM」会被覆盖成
// 未选择的日子，且下次越档真的执行一轮后才自愈。
//
// 注入形态：把排程列改名，SELECT 该列失败而既有列的 UPDATE 仍成功（关闭整个
// 库连接会把 UPDATE 一起打掉，无法区分「没写槽」与「整条写都失败」）。
// 覆盖写面：版本表槽推进（失败/取消）、版本表成功落库、威胁源成功、爬虫源失败。

import (
	"sync"
	"testing"
	"time"

	"lazy-balancer-v2/internal/db"
)

// injectScheduleReadFailure 让指定表的排程列读不出来，返回恢复函数（幂等）。
func injectScheduleReadFailure(t *testing.T, table, column string) func() {
	t.Helper()
	renamed := column + "_unreadable"
	if _, err := db.DB.Exec(`ALTER TABLE ` + table + ` RENAME COLUMN ` + column + ` TO ` + renamed); err != nil {
		t.Fatalf("注入排程读失败（%s.%s）: %v", table, column, err)
	}
	var once sync.Once
	restore := func() {
		once.Do(func() {
			if _, err := db.DB.Exec(`ALTER TABLE ` + table + ` RENAME COLUMN ` + renamed + ` TO ` + column); err != nil {
				t.Errorf("恢复排程列（%s.%s）: %v", table, column, err)
			}
		})
	}
	t.Cleanup(restore)
	return restore
}

// threatSourceStatus 读威胁源状态列（本文件只需状态与槽两列）。
func threatSourceStatus(t *testing.T, id int) string {
	t.Helper()
	var status string
	if err := db.DB.QueryRow(`SELECT COALESCE(update_status,'') FROM security_threat_sources WHERE id=?`, id).Scan(&status); err != nil {
		t.Fatal(err)
	}
	return status
}

// crawlerSourceSlot 读爬虫源排程槽。
func crawlerSourceSlot(t *testing.T, name string) string {
	t.Helper()
	var slot string
	if err := db.DB.QueryRow(`SELECT COALESCE(next_update,'') FROM security_crawler_sources WHERE name=?`, name).Scan(&slot); err != nil {
		t.Fatal(err)
	}
	return slot
}

// Given 版本表槽已过期。When 排程列读不出来且失败落库路径推进槽。
// Then next_update 保持原值（不得写成默认排程的下一槽）；读恢复后正常推进。
func TestVersionTableSlotAdvance_scheduleReadFailureKeepsExistingSlot(t *testing.T) {
	newClusterTestService(t)
	seedCRSVersionRow(t, "v4.30.0", true)
	expired := expiredSlot()
	setCRSSlot(t, expired)

	restore := injectScheduleReadFailure(t, "security_crs_version", "schedule_days")
	advanceVersionSlotIfDue("security_crs_version")
	if got := crsNextUpdate(t); got != expired {
		t.Fatalf("排程不可读时 next_update=%q, want 保持原值 %q（不得按默认排程回写）", got, expired)
	}

	restore()
	advanceVersionSlotIfDue("security_crs_version")
	assertFutureSlot(t, "读恢复后的 CRS 槽", crsNextUpdate(t))
}

// Given 版本表槽已过期且 auto 开启。When 排程列读不出来且成功落库路径写状态。
// Then 状态列照常落库、next_update 保持原值；读恢复后推进到未来槽。
func TestVersionTableSlotSuccess_scheduleReadFailureKeepsExistingSlot(t *testing.T) {
	m := newTestCRSManager(t)
	seedCRSVersionRow(t, "v4.30.0", true)
	expired := expiredSlot()
	setCRSSlot(t, expired)

	restore := injectScheduleReadFailure(t, "security_crs_version", "schedule_time")
	m.recordLatestSkip("auto")
	_, status, _, _, _, nextUpdate, _ := crsVersionRow(t)
	if status != string(CRSStatusSuccess) {
		t.Fatalf("update_status=%q, want success（排程不可读不得阻断状态落库）", status)
	}
	if nextUpdate != expired {
		t.Fatalf("排程不可读时 next_update=%q, want 保持原值 %q", nextUpdate, expired)
	}

	restore()
	m.recordLatestSkip("auto")
	assertFutureSlot(t, "读恢复后的 CRS 槽", crsNextUpdate(t))
}

// Given 威胁源槽已过期。When 任务级排程列读不出来且源成功状态落库。
// Then 源状态落库（success）、槽保持原值；读恢复后推进到未来槽。
func TestThreatSourceSuccess_scheduleReadFailureKeepsExistingSlot(t *testing.T) {
	overrideWafDirForTest(t)
	newClusterTestService(t)
	setupThreatTest(t, nil, nil, nil)
	expired := expiredSlot()
	if _, err := db.DB.Exec(`UPDATE security_threat_sources SET next_update=? WHERE update_enabled=1`, expired); err != nil {
		t.Fatal(err)
	}
	var id int
	if err := db.DB.QueryRow(`SELECT id FROM security_threat_sources WHERE update_enabled=1 ORDER BY id LIMIT 1`).Scan(&id); err != nil {
		t.Fatal(err)
	}

	restore := injectScheduleReadFailure(t, "global_config", "threat_schedule_days")
	finished := time.Now().UTC().Format(crsTimeLayout)
	if err := markSourceSuccess(id, 2, finished, "auto"); err != nil {
		t.Fatalf("markSourceSuccess: %v", err)
	}
	if status := threatSourceStatus(t, id); status != "success" {
		t.Fatalf("update_status=%q, want success（排程不可读不得阻断状态落库）", status)
	}
	if got := threatSourceSlot(t, id); got != expired {
		t.Fatalf("排程不可读时 next_update=%q, want 保持原值 %q", got, expired)
	}

	restore()
	if err := markSourceSuccess(id, 2, finished, "auto"); err != nil {
		t.Fatalf("markSourceSuccess（读恢复）: %v", err)
	}
	assertFutureSlot(t, "读恢复后的威胁源槽", threatSourceSlot(t, id))
}

// Given 爬虫源槽已过期。When 任务级排程列读不出来且源失败状态落库。
// Then 源状态落库（failed）、槽保持原值；读恢复后推进到未来槽。
func TestCrawlerSourceFailed_scheduleReadFailureKeepsExistingSlot(t *testing.T) {
	newClusterTestService(t)
	if err := ensureCrawlerSources(); err != nil {
		t.Fatal(err)
	}
	const source = "googlebot"
	if _, err := db.DB.Exec(`UPDATE security_crawler_sources SET update_enabled=1, next_update=? WHERE name=?`, expiredSlot(), source); err != nil {
		t.Fatal(err)
	}
	expired := crawlerSourceSlot(t, source)

	restore := injectScheduleReadFailure(t, "global_config", "crawler_schedule_time")
	if err := markCrawlerSourceFailed(source, "auto", "解析失败"); err != nil {
		t.Fatalf("markCrawlerSourceFailed: %v", err)
	}
	if got := crawlerSourceStatus(t, source); got != "failed" {
		t.Fatalf("update_status=%q, want failed（排程不可读不得阻断状态落库）", got)
	}
	if got := crawlerSourceSlot(t, source); got != expired {
		t.Fatalf("排程不可读时 next_update=%q, want 保持原值 %q", got, expired)
	}

	restore()
	if err := markCrawlerSourceFailed(source, "auto", "解析失败"); err != nil {
		t.Fatalf("markCrawlerSourceFailed（读恢复）: %v", err)
	}
	assertFutureSlot(t, "读恢复后的爬虫源槽", crawlerSourceSlot(t, source))
}
