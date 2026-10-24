package services

// 集群同步/lbbak 导入在从节点同样执行 xdb 后置重建——派生缓存（地域树/省份）
// 属「本节点只读不变量」的同一写入门，从节点不落盘；读侧缺缓存时按 xdb 在
// 内存重建（进程内记忆化），可用性不受影响。

import (
	"os"
	"path/filepath"
	"testing"

	"lazy-balancer-v2/internal/db"
)

// copyRepositoryXDB 直取仓库固定夹具（与 regionTree 扫描测试同一来源），
// 不用伪造 xdb——伪造文件的 header 段区指针为 0，解析不出地域树。
func copyRepositoryXDB(t *testing.T) string {
	t.Helper()
	src := filepath.Join("..", "..", "caddygeoip", "testdata", "ip2region_v4.xdb")
	data, err := os.ReadFile(src)
	if err != nil {
		t.Fatalf("repository xdb fixture unavailable: %v", err)
	}
	live := filepath.Join(t.TempDir(), "ip2region.xdb")
	if err := os.WriteFile(live, data, 0o644); err != nil {
		t.Fatal(err)
	}
	return live
}

func TestRebuildRegionTreeCacheForSync_slaveWritesNoDerivedCaches(t *testing.T) {
	setupSecurityEnumTestDB(t)
	if _, err := db.DB.Exec(`UPDATE global_config SET is_master=0 WHERE id=1`); err != nil {
		t.Fatalf("set slave role: %v", err)
	}
	live := copyRepositoryXDB(t)
	withIP2RegionPaths(t, live, filepath.Join(filepath.Dir(live), "waf.dist", "ip2region.xdb"))

	RebuildRegionTreeCacheForSync()

	if _, err := os.Stat(live + ".regions.json"); !os.IsNotExist(err) {
		t.Fatalf("从节点不得写地域树派生缓存（stat err=%v）", err)
	}
	if _, err := os.Stat(live + ".provinces.json"); !os.IsNotExist(err) {
		t.Fatalf("从节点不得写省份派生缓存（stat err=%v）", err)
	}
	// 读侧仍可用：缺缓存按 xdb 内存重建。
	tree := GetIP2RegionRegionTree()
	if tree == nil || len(tree.Provinces) < 30 {
		t.Fatalf("从节点读侧未按 xdb 内存重建地域树: %+v", tree)
	}
}

func TestRebuildRegionTreeCacheForSync_masterWritesDerivedCache(t *testing.T) {
	setupSecurityEnumTestDB(t)
	// setupSecurityEnumTestDB 默认主节点。
	live := copyRepositoryXDB(t)
	withIP2RegionPaths(t, live, filepath.Join(filepath.Dir(live), "waf.dist", "ip2region.xdb"))

	RebuildRegionTreeCacheForSync()

	if _, err := os.Stat(live + ".regions.json"); err != nil {
		t.Fatalf("主节点应写地域树派生缓存: %v", err)
	}
}
