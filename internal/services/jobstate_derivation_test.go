package services

import (
	"sort"
	"strings"
	"testing"
)

// 部署生命周期状态集必须由 jobLifecycleByStatus 单源派生：切片与 SQL IN 片段
// 是同一份真源的两个消费形态，新增/重命名状态时不得出现第二处字面量。
func TestDeploymentLifecycleStatusSetDerivedFromLifecycleMap(t *testing.T) {
	want := make([]string, 0, 3)
	for status, lifecycle := range jobLifecycleByStatus {
		if lifecycle == JobLifecycleDownloaded {
			want = append(want, status)
		}
	}
	sort.Strings(want)
	if len(want) == 0 {
		t.Fatal("jobLifecycleByStatus 未定义任何 downloaded 生命周期状态")
	}
	if strings.Join(deploymentLifecycleJobStatuses, ",") != strings.Join(want, ",") {
		t.Fatalf("deploymentLifecycleJobStatuses=%v, want %v（必须由 jobLifecycleByStatus 派生）",
			deploymentLifecycleJobStatuses, want)
	}
	for _, status := range want {
		if !strings.Contains(deploymentLifecycleJobStatusSQL, "'"+status+"'") {
			t.Fatalf("SQL 片段缺状态 %q: %s", status, deploymentLifecycleJobStatusSQL)
		}
	}
	if got := strings.Count(deploymentLifecycleJobStatusSQL, "','") + 1; got != len(want) {
		t.Fatalf("SQL 片段状态数=%d, want %d（%s）", got, len(want), deploymentLifecycleJobStatusSQL)
	}
}
