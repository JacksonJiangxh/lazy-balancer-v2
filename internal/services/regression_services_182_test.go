package services

import (
	"context"

	"lazy-balancer-v2/internal/models"
)

// SnapshotForTest 兼容历史审计测试：当前生产只保留 Snapshot/cachedSnapshot，
// 旧测试需要无 304 门/无签名门禁的完整快照。
func (s *ClusterService) SnapshotForTest(ctx context.Context) (models.ClusterSnapshot, error) {
	return s.buildFullSnapshot(ctx, s.db)
}
