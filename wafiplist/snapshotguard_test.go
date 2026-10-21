package wafiplist

import (
	"testing"
	"time"
)

// 快照代际守卫单源：两个加载器（名单文件 / 爬虫快照）共用同一组判定——
// 这里钉死三条语义，任一侧改为内联比较就绕开本门。
func TestSnapshotGenerationGuard(t *testing.T) {
	base := time.Date(2026, 10, 20, 12, 0, 0, 0, time.UTC)
	newer := base.Add(time.Second)

	cases := []struct {
		name      string
		candidate SnapshotGeneration
		current   SnapshotGeneration
		want      bool
	}{
		{"同代际不算旧", SnapshotGeneration{base, 10, time.Time{}}, SnapshotGeneration{base, 10, time.Time{}}, false},
		{"current mtime 更晚=旧", SnapshotGeneration{base, 10, time.Time{}}, SnapshotGeneration{newer, 10, time.Time{}}, true},
		{"同 mtime current 更大=旧", SnapshotGeneration{base, 10, time.Time{}}, SnapshotGeneration{base, 11, time.Time{}}, true},
		{"candidate 更晚不算旧", SnapshotGeneration{newer, 10, time.Time{}}, SnapshotGeneration{base, 10, time.Time{}}, false},
		{"同 mtime candidate 更大不算旧", SnapshotGeneration{base, 11, time.Time{}}, SnapshotGeneration{base, 10, time.Time{}}, false},
	}
	for _, tc := range cases {
		if got := StaleSnapshotGeneration(tc.candidate, tc.current); got != tc.want {
			t.Errorf("%s: StaleSnapshotGeneration=%v, want %v", tc.name, got, tc.want)
		}
	}

	if !SameSnapshotGeneration(SnapshotGeneration{base, 10, time.Time{}}, SnapshotGeneration{base, 10, base}) {
		t.Error("同 mtime+size 必须判同代际（CommittedAt 不参与代际）")
	}
	if SameSnapshotGeneration(SnapshotGeneration{base, 10, time.Time{}}, SnapshotGeneration{base, 11, time.Time{}}) {
		t.Error("size 不同不得判同代际")
	}

	// 失败降级守卫：成功快照在失败读取开始之后落定 → 不得被降级；
	// 失败读取开始之后没有新成功（CommittedAt 更早/零值）→ 允许覆盖。
	if !StaleFailureDowngrade(SnapshotGeneration{base, 10, base.Add(time.Second)}, base) {
		t.Error("成功快照晚于失败读取开始，失败候选必须被丢弃")
	}
	if StaleFailureDowngrade(SnapshotGeneration{base, 10, base}, base.Add(time.Second)) {
		t.Error("成功快照早于失败读取开始，失败候选可以覆盖（TTL 到期后的真实读错）")
	}
	if StaleFailureDowngrade(SnapshotGeneration{base, 10, time.Time{}}, base) {
		t.Error("无 CommittedAt 的快照不参与失败守卫")
	}
}
