package services

// 写路径的排程读取必须是严格形态：一次瞬时读失败不得按读侧 fail-soft 的默认
// 排程（每天 04:00）算出下一槽并落库——用户的「星期几 + HH:MM」会被覆盖成
// 未选择的日子，且下次越档真的执行一轮后才自愈。
//
// 成功路径更进一步：状态列照常落库、槽保持原值，同时把「槽未推进」作为错误
// 上报（Run 体按失败返回），否则引擎会把本槽记入消费水位——业务槽停在过去
// 且没有下一轮可以自愈（自动更新静默停摆）。
//
// 注入形态：把排程列改名，SELECT 该列失败而既有列的 UPDATE 仍成功（关闭整个
// 库连接会把 UPDATE 一起打掉，无法区分「没写槽」与「整条写都失败」）。
// 覆盖写面：版本表槽推进（失败/取消）、版本表成功落库、威胁/爬虫源成功/失败、
// 以及引擎侧「失败轮不消费槽→退避重投→读恢复后推进」的端到端链。

import (
	"context"
	"errors"
	"sync"
	"testing"
	"time"

	"lazy-balancer-v2/internal/db"
	"lazy-balancer-v2/internal/taskengine"
)

// injectColumnRename 把列改名使引用该列的语句失败（用于区分「哪一条写入
// 失败」：排程列读取走的是 schedule_days/schedule_time，改 message/finished_at
// 之类状态列不会连带打掉排程读取），返回恢复函数（幂等）。
func injectColumnRename(t *testing.T, table, column string) func() {
	t.Helper()
	renamed := column + "_unavailable"
	if _, err := db.DB.Exec(`ALTER TABLE ` + table + ` RENAME COLUMN ` + column + ` TO ` + renamed); err != nil {
		t.Fatalf("注入列不可用（%s.%s）: %v", table, column, err)
	}
	var once sync.Once
	restore := func() {
		once.Do(func() {
			if _, err := db.DB.Exec(`ALTER TABLE ` + table + ` RENAME COLUMN ` + renamed + ` TO ` + column); err != nil {
				t.Errorf("恢复列（%s.%s）: %v", table, column, err)
			}
		})
	}
	t.Cleanup(restore)
	return restore
}

// injectScheduleReadFailure 让指定表的排程列读不出来，返回恢复函数（幂等）。
func injectScheduleReadFailure(t *testing.T, table, column string) func() {
	return injectColumnRename(t, table, column)
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
// Then 状态列照常落库、next_update 保持原值，且本轮被标记为「排程槽未推进」
// （Run 体据此按失败返回，引擎退避重投）；读恢复后推进到未来槽并清除标记。
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
	if err := m.ScheduleSlotError(); !errors.Is(err, errScheduleSlotNotAdvanced) {
		t.Fatalf("ScheduleSlotError()=%v, want 排程槽未推进（成功轮不推进槽却回 success 会被引擎消费本槽）", err)
	}

	restore()
	m.recordLatestSkip("auto")
	if err := m.ScheduleSlotError(); err != nil {
		t.Fatalf("读恢复后不应再报排程槽未推进: %v", err)
	}
	assertFutureSlot(t, "读恢复后的 CRS 槽", crsNextUpdate(t))
}

// Given 威胁源槽已过期。When 任务级排程列读不出来且源成功状态落库。
// Then 源状态落库（success）、槽保持原值，且 writer 返回「排程槽未推进」错误
// （本轮按失败返回，引擎退避重投）；读恢复后推进到未来槽。
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
	if err := markSourceSuccess(id, 2, finished, "auto"); !errors.Is(err, errScheduleSlotNotAdvanced) {
		t.Fatalf("markSourceSuccess err=%v, want 排程槽未推进（成功轮不推进槽却回 success 会被引擎消费本槽）", err)
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

// Given 爬虫源槽已过期。When 任务级排程列读不出来且源成功状态落库。
// Then 源状态落库（success）、槽保持原值，且 writer 返回「排程槽未推进」错误；
// 读恢复后推进到未来槽。
func TestCrawlerSourceSuccess_scheduleReadFailureKeepsExistingSlot(t *testing.T) {
	newClusterTestService(t)
	if err := ensureCrawlerSources(); err != nil {
		t.Fatal(err)
	}
	const source = "googlebot"
	if _, err := db.DB.Exec(`UPDATE security_crawler_sources SET update_enabled=1, next_update=? WHERE name=?`, expiredSlot(), source); err != nil {
		t.Fatal(err)
	}
	expired := crawlerSourceSlot(t, source)

	restore := injectScheduleReadFailure(t, "global_config", "crawler_schedule_days")
	if err := markCrawlerSourceSuccess(source, "auto", 3); !errors.Is(err, errScheduleSlotNotAdvanced) {
		t.Fatalf("markCrawlerSourceSuccess err=%v, want 排程槽未推进", err)
	}
	if got := crawlerSourceStatus(t, source); got != "success" {
		t.Fatalf("update_status=%q, want success（排程不可读不得阻断状态落库）", got)
	}
	if got := crawlerSourceSlot(t, source); got != expired {
		t.Fatalf("排程不可读时 next_update=%q, want 保持原值 %q", got, expired)
	}

	restore()
	if err := markCrawlerSourceSuccess(source, "auto", 3); err != nil {
		t.Fatalf("markCrawlerSourceSuccess（读恢复）: %v", err)
	}
	assertFutureSlot(t, "读恢复后的爬虫源槽", crawlerSourceSlot(t, source))
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

// Given 威胁源成功落库路径（真实 writer）遇上排程读取失败。
// When 引擎按过期槽投递自动轮，失败退避后再次投递。
// Then 失败轮不消费本槽——排程读恢复后同一槽仍能投递并成功推进；旧形态
// （把 no-op 槽当 success）会让引擎把过期槽写进 schedDoneSlot，此后 tick 的
// 「槽 > 已消费水位」门永久拒绝该槽（自动更新静默停摆，无自愈路径）。
func TestEngine_ThreatScheduleReadFailureRetriesSameSlot(t *testing.T) {
	newClusterTestService(t)
	setupThreatTest(t, nil, nil, nil)
	expired := expiredSlot()
	if _, err := db.DB.Exec(`UPDATE security_threat_sources SET update_enabled=1, next_update=?`, expired); err != nil {
		t.Fatal(err)
	}
	var id int
	if err := db.DB.QueryRow(`SELECT id FROM security_threat_sources WHERE update_enabled=1 ORDER BY id LIMIT 1`).Scan(&id); err != nil {
		t.Fatal(err)
	}

	restore := injectScheduleReadFailure(t, "global_config", "threat_schedule_days")

	e := taskengine.NewEngine(taskengine.Options{TickInterval: 20 * time.Millisecond})
	t.Cleanup(e.Stop)
	e.Register(taskengine.Descriptor{
		ID: "threat", Family: "security", Name: "威胁情报库更新",
		Kind: taskengine.KindScheduled, RunsOn: taskengine.RoleMasterOnly,
		NextSlotFn: func() time.Time {
			if !ThreatAutoUpdateEnabled() {
				return time.Time{}
			}
			return parseUTCSlot(earliestThreatNextUpdate())
		},
		EnabledFn: func() bool { return ThreatAutoUpdateEnabled() },
		Run: func(rc taskengine.RunContext) error {
			// 真实成功落库路径：排程不可读时返回「槽未推进」，本轮按失败上报。
			return markSourceSuccess(id, 2, time.Now().UTC().Format(crsTimeLayout), rc.Trigger)
		},
	})
	e.SetRole(true)
	e.StartLoop("threat")

	waitRun := func(want string, deadline time.Duration) {
		t.Helper()
		end := time.Now().Add(deadline)
		for time.Now().Before(end) {
			if run := e.LatestRun("threat"); run != nil && run.Status == want {
				return
			}
			time.Sleep(10 * time.Millisecond)
		}
		run := e.LatestRun("threat")
		if run == nil {
			t.Fatalf("%v 内无任何运行记录, want 终态 %s", deadline, want)
		}
		t.Fatalf("%v 内最新运行 status=%s（message=%s）, want %s", deadline, run.Status, run.Message, want)
	}

	// 第一次自动轮：排程不可读 → 失败（不得以 success 消费本槽）。
	waitRun("failed", 3*time.Second)
	if got := threatSourceSlot(t, id); got != expired {
		t.Fatalf("排程不可读时 next_update=%q, want 保持原值 %q", got, expired)
	}

	// 排程读恢复后，同一过期槽仍会被重投（未消费）并推进到未来槽。
	restore()
	waitRun("success", 6*time.Second)
	assertFutureSlot(t, "读恢复后的威胁源槽", threatSourceSlot(t, id))
	if m, ok := e.Lookup("threat"); !ok || !m.LoopOn {
		t.Fatalf("恢复轮后调度开关应为开启（失败退避不得等同停调）: ok=%v", ok)
	}
}

// ip2RegionRowStatusSlot 读 IP2Region 状态列与排程槽（不碰 message/finished_at，
// 以便在状态列被注入不可用期间断言）。
func ip2RegionRowStatusSlot(t *testing.T) (status, slot string) {
	t.Helper()
	if err := db.DB.QueryRow(`SELECT COALESCE(update_status,''), COALESCE(next_update,'') FROM security_ip2region_version WHERE id=1`).Scan(&status, &slot); err != nil {
		t.Fatal(err)
	}
	return status, slot
}

// Given 版本表成功轮的状态行 UPDATE 本身失败（状态列不可写，排程读取正常）。
// When 「已是最新」成功轮落库。
// Then 本轮按「排程槽未推进」上报（不得以 success 收尾），状态列与槽都保持
// 原值；写恢复后同一路径成功落库并推进槽。
func TestVersionTableSlotSuccess_stateWriteFailureReportsUnadvancedSlot(t *testing.T) {
	m := newTestCRSManager(t)
	seedCRSVersionRow(t, "v4.30.0", true)
	expired := expiredSlot()
	setCRSSlot(t, expired)

	restore := injectColumnRename(t, "security_crs_version", "message")
	m.recordLatestSkip("auto")
	var status string
	if err := db.DB.QueryRow(`SELECT COALESCE(update_status,'') FROM security_crs_version WHERE id=1`).Scan(&status); err != nil {
		t.Fatal(err)
	}
	if status == string(CRSStatusSuccess) {
		t.Fatalf("update_status=%q：状态行写入失败却落了 success（引擎会把过期槽记入消费水位）", status)
	}
	if got := crsNextUpdate(t); got != expired {
		t.Fatalf("状态行写入失败时 next_update=%q, want 保持原值 %q", got, expired)
	}
	if err := m.ScheduleSlotError(); !errors.Is(err, errScheduleSlotNotAdvanced) {
		t.Fatalf("ScheduleSlotError()=%v, want 排程槽未推进（写失败必须并入同一失败通道）", err)
	}

	restore()
	m.recordLatestSkip("auto")
	if err := m.ScheduleSlotError(); err != nil {
		t.Fatalf("写恢复后不应再报排程槽未推进: %v", err)
	}
	_, status, _, _, _, _, _ = crsVersionRow(t)
	if status != string(CRSStatusSuccess) {
		t.Fatalf("update_status=%q, want success", status)
	}
	assertFutureSlot(t, "写恢复后的 CRS 槽", crsNextUpdate(t))
}

// Given IP2Region 真实成功轮的状态行 UPDATE 失败。When 一轮手动更新跑完
// （下载/安装/重载全部成功）。
// Then 本轮按「排程槽未推进」上报，状态列保持原值、槽不推进；写恢复后同一次
// 更新成功落库并推进槽。
func TestVersionTableSlotSuccess_ip2RegionStateWriteFailureReportsUnadvancedSlot(t *testing.T) {
	m := newTestIP2RegionManager(t)
	seedIP2RegionVersionRow(t, "v3.0.0", true)
	expired := expiredSlot()
	if _, err := db.DB.Exec(`UPDATE security_ip2region_version SET next_update=? WHERE id=1`, expired); err != nil {
		t.Fatal(err)
	}
	m.fetchLatestTag = func(context.Context) (string, error) { return "v3.1.0", nil }
	m.downloadXDB = fakeIP2RegionDownload(t, true)
	m.reloader = func() error { return nil }

	restore := injectColumnRename(t, "security_ip2region_version", "message")
	m.run("manual", nil)
	status, slot := ip2RegionRowStatusSlot(t)
	if status == string(IP2RegionStatusSuccess) {
		t.Fatalf("update_status=%q：状态行写入失败却落了 success（引擎会把过期槽记入消费水位）", status)
	}
	if slot != expired {
		t.Fatalf("状态行写入失败时 next_update=%q, want 保持原值 %q", slot, expired)
	}
	if err := m.ScheduleSlotError(); !errors.Is(err, errScheduleSlotNotAdvanced) {
		t.Fatalf("ScheduleSlotError()=%v, want 排程槽未推进（写失败必须并入同一失败通道）", err)
	}

	restore()
	m.run("manual", nil)
	if err := m.ScheduleSlotError(); err != nil {
		t.Fatalf("写恢复后不应再报排程槽未推进: %v", err)
	}
	status, slot = ip2RegionRowStatusSlot(t)
	if status != string(IP2RegionStatusSuccess) {
		t.Fatalf("update_status=%q, want success", status)
	}
	assertFutureSlot(t, "写恢复后的 IP2Region 槽", slot)
}

// Given IP2Region「已是最新」轮的状态行 UPDATE 失败。When 一轮手动更新跑完。
// Then 同假成功轮一律按排程槽未推进上报，槽保持原值；写恢复后成功推进槽。
func TestVersionTableSlotSuccess_ip2RegionLatestSkipStateWriteFailure(t *testing.T) {
	m := newTestIP2RegionManager(t)
	seedIP2RegionVersionRow(t, "v3.0.0", true)
	expired := expiredSlot()
	if _, err := db.DB.Exec(`UPDATE security_ip2region_version SET next_update=? WHERE id=1`, expired); err != nil {
		t.Fatal(err)
	}
	m.fetchLatestTag = func(context.Context) (string, error) { return "v3.0.0", nil }

	restore := injectColumnRename(t, "security_ip2region_version", "message")
	m.run("manual", nil)
	status, slot := ip2RegionRowStatusSlot(t)
	if status == string(IP2RegionStatusSuccess) {
		t.Fatalf("update_status=%q：状态行写入失败却落了 success", status)
	}
	if slot != expired {
		t.Fatalf("状态行写入失败时 next_update=%q, want 保持原值 %q", slot, expired)
	}
	if err := m.ScheduleSlotError(); !errors.Is(err, errScheduleSlotNotAdvanced) {
		t.Fatalf("ScheduleSlotError()=%v, want 排程槽未推进", err)
	}

	restore()
	m.run("manual", nil)
	if err := m.ScheduleSlotError(); err != nil {
		t.Fatalf("写恢复后不应再报排程槽未推进: %v", err)
	}
	status, slot = ip2RegionRowStatusSlot(t)
	if status != string(IP2RegionStatusSuccess) {
		t.Fatalf("update_status=%q, want success", status)
	}
	assertFutureSlot(t, "写恢复后的 IP2Region 槽", slot)
}

// Given 版本表成功轮的状态行写入持续失败（写路径读排程正常）。
// When 引擎按过期槽投递自动轮。
// Then 失败轮不消费本槽（过期槽不得进 schedDoneSlot）；写恢复后同一槽仍会
// 被投递、成功推进到未来槽——吞错按 success 收尾的形态会让 tick 的
// 「槽 > 消费水位」门永久拒绝该槽（自动更新静默停摆，无自愈路径）。
func TestEngine_VersionTableStateWriteFailureRetriesSameSlot(t *testing.T) {
	m := newTestCRSManager(t)
	seedCRSVersionRow(t, "v4.30.0", true)
	expired := expiredSlot()
	setCRSSlot(t, expired)

	restore := injectColumnRename(t, "security_crs_version", "message")

	e := taskengine.NewEngine(taskengine.Options{TickInterval: 20 * time.Millisecond})
	t.Cleanup(e.Stop)
	e.Register(taskengine.Descriptor{
		ID: "crs", Family: "security", Name: "CRS 规则库更新",
		Kind: taskengine.KindScheduled, RunsOn: taskengine.RoleMasterOnly,
		NextSlotFn: func() time.Time {
			if !versionTableAutoUpdateEnabled("security_crs_version") {
				return time.Time{}
			}
			return parseUTCSlot(versionTableNextUpdate("security_crs_version"))
		},
		EnabledFn: func() bool { return versionTableAutoUpdateEnabled("security_crs_version") },
		Run: func(rc taskengine.RunContext) error {
			// 真实成功落库路径：状态行写失败时以「槽未推进」上报。
			m.recordLatestSkip(rc.Trigger)
			return m.ScheduleSlotError()
		},
	})
	e.SetRole(true)
	e.StartLoop("crs")

	waitRun := func(want string, deadline time.Duration) {
		t.Helper()
		end := time.Now().Add(deadline)
		for time.Now().Before(end) {
			if run := e.LatestRun("crs"); run != nil && run.Status == want {
				return
			}
			time.Sleep(10 * time.Millisecond)
		}
		run := e.LatestRun("crs")
		if run == nil {
			t.Fatalf("%v 内无任何运行记录, want 终态 %s", deadline, want)
		}
		t.Fatalf("%v 内最新运行 status=%s（message=%s）, want %s", deadline, run.Status, run.Message, want)
	}

	// 第一次自动轮：状态行写失败 → 失败（不得以 success 消费本槽）。
	waitRun("failed", 3*time.Second)
	if got := crsNextUpdate(t); got != expired {
		t.Fatalf("状态行写失败时 next_update=%q, want 保持原值 %q", got, expired)
	}

	// 写恢复后，同一过期槽仍会被重投（未消费）并推进到未来槽。
	restore()
	waitRun("success", 6*time.Second)
	assertFutureSlot(t, "写恢复后的 CRS 槽", crsNextUpdate(t))
	if info, ok := e.Lookup("crs"); !ok || !info.LoopOn {
		t.Fatalf("恢复轮后调度开关应为开启（失败退避不得等同停调）: ok=%v", ok)
	}
}
