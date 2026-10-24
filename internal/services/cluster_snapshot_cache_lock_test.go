package services

import (
	"testing"
	"time"
)

// 快照缓存的「构建锁」与「发布锁」必须分离：此前单锁覆盖只读事务 + WAF 全树
// 哈希 + X.509 解析，导入/CRS 交换长持 wafFileMu 时首个 Pull 阻塞在构建里、
// 其余从端 Pull 全部排在锁后（集群面瞬间停顿）。本测试钉住「构建进行中字段
// 读写不被阻塞」这一不变量——两把锁被合并回一把即红。

func TestClusterSnapshotCache_buildLockDoesNotBlockFieldReaders(t *testing.T) {
	cache := &clusterSnapshotCache{}
	cache.buildMu.Lock()
	defer cache.buildMu.Unlock()

	readDone := make(chan struct{})
	go func() {
		cache.mu.Lock()
		_ = cache.initialized
		_ = cache.version
		cache.mu.Unlock()
		close(readDone)
	}()
	select {
	case <-readDone:
	case <-time.After(2 * time.Second):
		t.Fatal("构建锁持有期间字段读写被阻塞（发布锁与构建锁不可合并）")
	}
}
