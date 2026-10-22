package services

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"sync"
	"sync/atomic"
	"testing"

	"lazy-balancer-v2/internal/db"
	"lazy-balancer-v2/internal/taskengine"
)

// 爬虫族成功写路径复核（与威胁族同构）：下载/解析完成到 upsert/收敛之间存在
// 降级窗口——现有循环只在源间顶部复核角色，首源（或唯一启用源）写库不经过
// 任何复核。

// crawlerGateFixture 单源（googlebot）更新测试基座：其余源禁用，种子 3 条
// 既有快照（收缩/扩张门不参与两条目新响应的判定——googlebot 无官方段声明）。
func crawlerGateFixture(t *testing.T, hook func()) (previous []string) {
	t.Helper()
	newClusterTestService(t)
	oldFile := crawlerIPListFile
	crawlerIPListFile = filepath.Join(t.TempDir(), "crawler-ip-lists.json")
	t.Cleanup(func() { crawlerIPListFile = oldFile })

	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		if hook != nil {
			hook()
		}
		_, _ = w.Write([]byte(`{"prefixes":[{"ipv4Prefix":"10.11.0.0/24"},{"ipv4Prefix":"10.12.0.0/24"}]}`))
	}))
	t.Cleanup(ts.Close)

	if err := ensureCrawlerSources(); err != nil {
		t.Fatalf("seed sources: %v", err)
	}
	if _, err := db.DB.Exec(`UPDATE security_crawler_sources SET update_enabled=0;
		UPDATE security_crawler_sources SET update_enabled=1,url=? WHERE name='googlebot'`, ts.URL); err != nil {
		t.Fatal(err)
	}
	previous = []string{"203.0.113.1/32", "203.0.113.2/32", "203.0.113.3/32"}
	if err := upsertCrawlerIPList("googlebot", previous); err != nil {
		t.Fatalf("seed snapshot: %v", err)
	}
	return previous
}

func crawlerSourceStatus(t *testing.T, name string) string {
	t.Helper()
	var status string
	if err := db.DB.QueryRow(`SELECT update_status FROM security_crawler_sources WHERE name=?`, name).Scan(&status); err != nil {
		t.Fatal(err)
	}
	return status
}

// Given 唯一启用源下载完成前节点已降级（handler 内置 is_master=0）。
// When RunUpdate 走到成功写路径。
// Then 不写名单（旧快照保留）、源行不落 success、整轮返回 ErrTaskSkipped。
func TestCrawlerRunUpdate_demoteAtWriteGate_zeroWrite(t *testing.T) {
	demote := sync.Once{}
	previous := crawlerGateFixture(t, func() {
		demote.Do(func() {
			if _, err := db.DB.Exec(`UPDATE global_config SET is_master=0 WHERE id=1`); err != nil {
				t.Errorf("demote: %v", err)
			}
		})
	})
	t.Cleanup(func() { _, _ = db.DB.Exec(`UPDATE global_config SET is_master=1 WHERE id=1`) })

	err := GetCrawlerUpdateManager().RunUpdate(context.Background(), taskengine.RunContext{Ctx: context.Background(), Trigger: "manual"})

	if !errors.Is(err, taskengine.ErrTaskSkipped) {
		t.Fatalf("err=%v, want ErrTaskSkipped（降级中止不写库）", err)
	}
	if got := crawlerSourceStatus(t, "googlebot"); got == "success" {
		t.Fatal("降级窗口不得落 success 终态（从节点零写）")
	}
	loaded, lerr := loadCrawlerIPListsFromDB()
	if lerr != nil {
		t.Fatal(lerr)
	}
	if got := loaded["googlebot"]; len(got) != len(previous) {
		t.Fatalf("降级窗口写库：名单 %d 条, want %d（旧快照必须保留）", len(got), len(previous))
	}
}

// Given 唯一启用源下载完成前角色读取失败（global_config 行缺失→不可判定）。
// Then 不写库、按失败返回（非 ErrTaskSkipped——不可判定≠降级）。
func TestCrawlerRunUpdate_roleUndecidableAtWriteGate_failsLoudly(t *testing.T) {
	flip := sync.Once{}
	previous := crawlerGateFixture(t, func() {
		flip.Do(func() {
			if _, err := db.DB.Exec(`DELETE FROM global_config WHERE id=1`); err != nil {
				t.Errorf("break role row: %v", err)
			}
		})
	})

	err := GetCrawlerUpdateManager().RunUpdate(context.Background(), taskengine.RunContext{Ctx: context.Background(), Trigger: "manual"})

	if err == nil || errors.Is(err, taskengine.ErrTaskSkipped) {
		t.Fatalf("err=%v, want 普通错误（角色不可判定按失败落定，非降级哨兵）", err)
	}
	if got := crawlerSourceStatus(t, "googlebot"); got == "success" {
		t.Fatal("角色不可判定不得落 success 终态")
	}
	loaded, lerr := loadCrawlerIPListsFromDB()
	if lerr != nil {
		t.Fatal(lerr)
	}
	if got := loaded["googlebot"]; len(got) != len(previous) {
		t.Fatalf("角色不可判定写库：名单 %d 条, want %d（旧快照必须保留）", len(got), len(previous))
	}
}

// 写路径门三态单测（取消支路的确定性覆盖——RunUpdate 级「下载后取消」窗口
// 无法从外部确定性定时，门本体逐支路钉死）：
// 主节点+未取消=放行；已降级=ErrTaskSkipped；角色不可判定=errRunRoleUndecidable；
// 主节点+已取消=ctx.Err。
func TestUpdateRunWriteGate_threeWayAttribution(t *testing.T) {
	newClusterTestService(t)

	if err := updateRunWriteGate(context.Background()); err != nil {
		t.Fatalf("主节点未取消应放行, got %v", err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if err := updateRunWriteGate(ctx); !errors.Is(err, context.Canceled) {
		t.Fatalf("主节点+已取消应回传 ctx.Err, got %v", err)
	}

	if _, err := db.DB.Exec(`UPDATE global_config SET is_master=0 WHERE id=1`); err != nil {
		t.Fatal(err)
	}
	if err := updateRunWriteGate(context.Background()); !errors.Is(err, taskengine.ErrTaskSkipped) {
		t.Fatalf("已降级应回传 ErrTaskSkipped, got %v", err)
	}
	if _, err := db.DB.Exec(`UPDATE global_config SET is_master=1 WHERE id=1`); err != nil {
		t.Fatal(err)
	}

	if _, err := db.DB.Exec(`DELETE FROM global_config WHERE id=1`); err != nil {
		t.Fatal(err)
	}
	if err := updateRunWriteGate(context.Background()); !errors.Is(err, errRunRoleUndecidable) {
		t.Fatalf("角色不可判定应回传 errRunRoleUndecidable, got %v", err)
	}
}

// 基线单轮缓存：N 个启用源的收缩门/扩张门共享一份全量名单读——
// 旧形态每源两次全量读（2N 次），且每源 upsert 各跑一次名单名迁移。
func TestCrawlerRunUpdate_baselineLoadedOncePerRun(t *testing.T) {
	newClusterTestService(t)
	oldFile := crawlerIPListFile
	crawlerIPListFile = filepath.Join(t.TempDir(), "crawler-ip-lists.json")
	t.Cleanup(func() { crawlerIPListFile = oldFile })

	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(`{"prefixes":[{"ipv4Prefix":"10.11.0.0/24"},{"ipv4Prefix":"10.12.0.0/24"}]}`))
	}))
	t.Cleanup(ts.Close)
	if err := ensureCrawlerSources(); err != nil {
		t.Fatal(err)
	}
	// 两个启用源（均无官方段声明口径下的合法小名单）；各种子 3 条既有
	// 快照，让收缩/扩张门走 DB 基线（内置基线 170 条会拦 2 条新响应——
	// 与本测试观测面无关，排除）。
	if _, err := db.DB.Exec(`UPDATE security_crawler_sources SET update_enabled=0;
		UPDATE security_crawler_sources SET update_enabled=1,url=? WHERE name IN ('googlebot','bingbot')`, ts.URL); err != nil {
		t.Fatal(err)
	}
	seed := []string{"203.0.113.1/32", "203.0.113.2/32", "203.0.113.3/32"}
	for _, engine := range []string{"googlebot", "bingbot"} {
		if err := upsertCrawlerIPList(engine, seed); err != nil {
			t.Fatalf("seed %s snapshot: %v", engine, err)
		}
	}

	var loads, migrates atomic.Int64
	oldLoader := crawlerBaselineLoader
	crawlerBaselineLoader = func() (map[string][]string, error) {
		loads.Add(1)
		return oldLoader()
	}
	t.Cleanup(func() { crawlerBaselineLoader = oldLoader })
	oldMigrate := crawlerIPListMigrate
	crawlerIPListMigrate = func() error {
		migrates.Add(1)
		return oldMigrate()
	}
	t.Cleanup(func() { crawlerIPListMigrate = oldMigrate })

	if err := GetCrawlerUpdateManager().RunUpdate(context.Background(), taskengine.RunContext{Ctx: context.Background(), Trigger: "manual"}); err != nil {
		t.Fatalf("RunUpdate: %v", err)
	}
	if got := loads.Load(); got > 1 {
		t.Fatalf("单轮基线全量读 %d 次, want ≤1（每源两次全量读已收敛）", got)
	}
	if got := migrates.Load(); got > 1 {
		t.Fatalf("单轮名单名迁移 %d 次, want ≤1（每源重复迁移已收敛）", got)
	}
}
