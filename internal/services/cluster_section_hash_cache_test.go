package services

// 节点列表的三节哈希按 cluster_version 缓存：同版本内的 UI 轮询不得重复
// 装载三节输入并重算 SHA-256（每次重建=只读事务 + 全量 users/rules/security
// 序列化）；任意配置写推进版本后下一次轮询必须重建（失效键与快照缓存一致）。

import (
	"context"
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
