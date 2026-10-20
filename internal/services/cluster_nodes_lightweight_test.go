package services

import (
	"context"
	"testing"
	"time"
)

// 节点列表的 per-section 同步状态只消费 users/rules/security 三节
// 哈希，不得走全量快照构建（WAF 全树 tar.gz 哈希 + 全部证书 X.509 解析）。
// 该路径在任意 cluster_version 递增后由 UI 轮询触发，代价与阻塞面都必须与
// 「轻量三节哈希」一致。
func TestClusterService_NodesDoNotBuildFullSnapshotForSectionSync(t *testing.T) {
	service, database := newClusterTestService(t)
	nodeID := insertApprovedClusterNode(t, database, "slave-light")
	ctx := context.Background()
	hashes, err := service.driftGuardSectionHashes(ctx)
	if err != nil {
		t.Fatalf("lightweight hashes: %v", err)
	}
	if err := service.ReportNode(ctx, nodeID, withSectionHashes(reportForVersion(1), hashes), time.Now()); err != nil {
		t.Fatalf("report node: %v", err)
	}

	// 让快照缓存失效：真实触发场景就是任意配置写递增 cluster_version 后的
	// 首次节点列表轮询。清空 WAF 引用缓存，确保「全量构建」可被计数观察到。
	if _, err := database.Exec(`UPDATE global_config SET cluster_version=COALESCE(cluster_version,0)+1 WHERE id=1`); err != nil {
		t.Fatal(err)
	}
	wafFileRefCache.mu.Lock()
	wafFileRefCache.valid = false
	wafFileRefCache.mu.Unlock()
	wafFileRefFullBuilds.Store(0)

	nodes, err := service.Nodes(ctx, time.Now())
	if err != nil {
		t.Fatalf("list nodes: %v", err)
	}
	if len(nodes) != 1 || len(nodes[0].SectionSync) != len(syncSections) {
		t.Fatalf("nodes=%#v, want section sync attached", nodes)
	}
	if got := wafFileRefFullBuilds.Load(); got != 0 {
		t.Fatalf("Nodes() triggered %d full WAF ref build(s), want 0 (lightweight section hashes only)", got)
	}
}
