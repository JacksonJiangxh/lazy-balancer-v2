package services

// 节点列表的三节哈希按 cluster_version 缓存：同版本内的 UI 轮询不得重复
// 装载三节输入并重算 SHA-256（每次重建=只读事务 + 全量 users/rules/security
// 序列化）；任意配置写推进版本后下一次轮询必须重建（失效键与快照缓存一致）。

import (
	"context"
	"database/sql"
	"testing"
	"time"
)

func TestClusterService_NodesSectionHashesCachedPerVersion(t *testing.T) {
	service, database := newClusterTestService(t)
	resetClusterSectionHashCacheForTest()
	nodeID := insertApprovedClusterNode(t, database, "slave-section-cache")
	ctx := context.Background()

	hashes, err := service.driftGuardSectionHashes(ctx)
	if err != nil {
		t.Fatalf("seed hashes: %v", err)
	}
	if err := service.ReportNode(ctx, nodeID, withSectionHashes(reportForVersion(1), hashes), time.Now()); err != nil {
		t.Fatalf("report node: %v", err)
	}
	if _, err := database.Exec(`UPDATE global_config SET cluster_version=500 WHERE id=1`); err != nil {
		t.Fatal(err)
	}
	resetClusterSectionHashCacheForTest()

	base := clusterSectionHashBuilds.Load()
	for range 3 {
		nodes, err := service.Nodes(ctx, time.Now())
		if err != nil {
			t.Fatalf("list nodes: %v", err)
		}
		if len(nodes) != 1 || len(nodes[0].SectionSync) != len(syncSections) {
			t.Fatalf("nodes=%#v, want section sync attached", nodes)
		}
	}
	if got := clusterSectionHashBuilds.Load() - base; got != 1 {
		t.Fatalf("同版本 3 次节点列表重建三节哈希 %d 次, want 1（按 cluster_version 缓存）", got)
	}

	// 版本推进（任意配置写）→ 下一次轮询必须重建，且结果与直接重建口径一致。
	if _, err := database.Exec(`UPDATE global_config SET cluster_version=501 WHERE id=1`); err != nil {
		t.Fatal(err)
	}
	if _, err := service.Nodes(ctx, time.Now()); err != nil {
		t.Fatalf("list nodes after bump: %v", err)
	}
	if got := clusterSectionHashBuilds.Load() - base; got != 2 {
		t.Fatalf("版本推进后重建次数=%d, want 2（缓存必须随 cluster_version 失效）", got)
	}
}

// 缓存以库句柄为键：服务注销即释放该句柄条目，否则测试/运行期重建 DB 时
// 全局缓存强引用已关闭句柄（同 clusterServices 注册表的句柄回收语义）。
func TestMasterSectionHashes_unregisterReclaimsCacheEntry(t *testing.T) {
	service, database := newClusterTestService(t)
	resetClusterSectionHashCacheForTest()
	if _, err := database.Exec(`UPDATE global_config SET cluster_version=600 WHERE id=1`); err != nil {
		t.Fatal(err)
	}
	if _, _, err := service.masterSectionHashes(context.Background()); err != nil {
		t.Fatalf("build master section hashes: %v", err)
	}
	clusterSectionHashCacheMu.Lock()
	_, cached := clusterSectionHashCache[database]
	clusterSectionHashCacheMu.Unlock()
	if !cached {
		t.Fatal("重建后必须留下句柄缓存条目")
	}
	unregisterClusterService(service)
	clusterSectionHashCacheMu.Lock()
	_, cached = clusterSectionHashCache[database]
	clusterSectionHashCacheMu.Unlock()
	if cached {
		t.Fatal("服务注销后必须回收该句柄的哈希缓存条目")
	}
}

// 未见显式注销的死句柄（库已 Close）在重建时顺手剔除，活跃句柄条目保留。
func TestMasterSectionHashes_prunesDeadHandleEntries(t *testing.T) {
	service, database := newClusterTestService(t)
	resetClusterSectionHashCacheForTest()
	dead, err := sql.Open("sqlite", ":memory:")
	if err != nil {
		t.Fatalf("open throwaway handle: %v", err)
	}
	if err := dead.Ping(); err != nil {
		t.Fatalf("ping throwaway handle: %v", err)
	}
	clusterSectionHashCacheMu.Lock()
	clusterSectionHashCache[dead] = clusterSectionHashCacheEntry{version: 1, hashes: map[string]string{"rules": "dead-handle"}}
	clusterSectionHashCacheMu.Unlock()
	if err := dead.Close(); err != nil {
		t.Fatalf("close throwaway handle: %v", err)
	}
	if _, err := database.Exec(`UPDATE global_config SET cluster_version=700 WHERE id=1`); err != nil {
		t.Fatal(err)
	}
	if _, _, err := service.masterSectionHashes(context.Background()); err != nil {
		t.Fatalf("build master section hashes: %v", err)
	}
	clusterSectionHashCacheMu.Lock()
	_, deadPresent := clusterSectionHashCache[dead]
	_, livePresent := clusterSectionHashCache[database]
	clusterSectionHashCacheMu.Unlock()
	if deadPresent {
		t.Fatal("已关闭句柄的缓存条目必须被回收")
	}
	if !livePresent {
		t.Fatal("活跃句柄的缓存条目不得被回收")
	}
}

// 版本与哈希内容必须来自同一次读取：缓存条目记的版本只能是内容所属事务内
// 读到的版本，否则条目自相矛盾（版本 V 的键挂 V+1 的内容），节点页会把在
// 该写窗口内完成的从节点误报为分区滞后。
func TestMasterSectionHashes_versionTakenFromContentSnapshot(t *testing.T) {
	service, database := newClusterTestService(t)
	resetClusterSectionHashCacheForTest()
	if _, err := database.Exec(`UPDATE global_config SET cluster_version=800 WHERE id=1`); err != nil {
		t.Fatal(err)
	}
	// 版本由 masterSectionHashes 在重建事务内读取——缓存条目记的版本必须是
	// 内容所属的版本（调用方不再传入自己先前读到的过期版本）。
	version, hashes, err := service.masterSectionHashes(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if version != 800 {
		t.Fatalf("masterSectionHashes version=%d, want 800", version)
	}
	clusterSectionHashCacheMu.Lock()
	entry := clusterSectionHashCache[database]
	clusterSectionHashCacheMu.Unlock()
	if entry.version != 800 {
		t.Fatalf("缓存条目版本=%d, want 800（内容所属事务内版本）", entry.version)
	}
	if entry.version != version {
		t.Fatalf("缓存条目版本=%d, want 与返回版本 %d 同值", entry.version, version)
	}
	for key, hash := range hashes {
		if entry.hashes[key] != hash {
			t.Fatalf("缓存条目 %s 哈希=%q, want 与返回哈希 %q 同值", key, entry.hashes[key], hash)
		}
	}

	// 缓存命中路径返回条目自身记录的版本（与内容同源）。
	if _, err := database.Exec(`UPDATE global_config SET cluster_version=801 WHERE id=1`); err != nil {
		t.Fatal(err)
	}
	version, _, err = service.masterSectionHashes(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if version != 801 {
		t.Fatalf("版本推进后 masterSectionHashes version=%d, want 801", version)
	}
	clusterSectionHashCacheMu.Lock()
	entry = clusterSectionHashCache[database]
	clusterSectionHashCacheMu.Unlock()
	if entry.version != 801 {
		t.Fatalf("版本推进后缓存条目版本=%d, want 801", entry.version)
	}
}
