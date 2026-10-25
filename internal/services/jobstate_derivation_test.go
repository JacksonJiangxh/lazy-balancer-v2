package services

import (
	"os"
	"path/filepath"
	"regexp"
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
		if !strings.Contains(DeploymentLifecycleJobStatusSQL, "'"+status+"'") {
			t.Fatalf("SQL 片段缺状态 %q: %s", status, DeploymentLifecycleJobStatusSQL)
		}
	}
	if got := strings.Count(DeploymentLifecycleJobStatusSQL, "','") + 1; got != len(want) {
		t.Fatalf("SQL 片段状态数=%d, want %d（%s）", got, len(want), DeploymentLifecycleJobStatusSQL)
	}
}

// cleanup 子集与全集的差集只能是 downloaded：补扫 cleanup 分支不带窗口/沉降
// 判据，若把 downloaded 也算进去，downloaded 行会绕过窗口判据被无条件重排。
func TestDeploymentCleanupStatusSetExcludesDownloaded(t *testing.T) {
	want := make([]string, 0, len(deploymentLifecycleJobStatuses))
	for _, status := range deploymentLifecycleJobStatuses {
		if status != "downloaded" {
			want = append(want, status)
		}
	}
	if len(want) == 0 || len(want) == len(deploymentLifecycleJobStatuses) {
		t.Fatalf("cleanup 子集派生不成立：全集=%v 子集=%v", deploymentLifecycleJobStatuses, want)
	}
	if strings.Join(deploymentCleanupJobStatuses, ",") != strings.Join(want, ",") {
		t.Fatalf("deploymentCleanupJobStatuses=%v, want %v", deploymentCleanupJobStatuses, want)
	}
	joined := DeploymentCleanupJobStatusSQL
	if strings.Contains(joined, "'downloaded'") {
		t.Fatalf("cleanup SQL 片段不得含 downloaded: %s", joined)
	}
	for _, status := range want {
		if !strings.Contains(joined, "'"+status+"'") {
			t.Fatalf("cleanup SQL 片段缺状态 %q: %s", status, joined)
		}
	}
}

// 部署生命周期状态集的 SQL 字面量只允许出现在派生点（jobstate.go）。
// 消费点重新写字面量不会报错，只会在状态机扩展时静默漏收：启动/补扫装载的
// CAS 源态集、补扫查询与文案回写都按旧集合求值，任务失去周期通道。
func TestDeploymentLifecycleStatusLiteralOnlyInDerivation(t *testing.T) {
	// 相邻两个生命周期状态被写成 SQL 字面量（'a','b'）即视为第二份集合；
	// 单状态比较（status='downloaded'）仍是合法用法，不在本守卫范围。
	literalSet := regexp.MustCompile(`'(downloaded|cleanup_dns|cleanup_warning)'\s*,\s*'(downloaded|cleanup_dns|cleanup_warning)'`)
	paths, err := filepath.Glob("*.go")
	if err != nil {
		t.Fatalf("glob services sources: %v", err)
	}
	handlerPaths, err := filepath.Glob(filepath.Join("..", "handlers", "cert*.go"))
	if err != nil {
		t.Fatalf("glob handler certificate sources: %v", err)
	}
	paths = append(paths, handlerPaths...)
	for _, path := range paths {
		if strings.HasSuffix(path, "_test.go") || filepath.Base(path) == "jobstate.go" {
			continue
		}
		data, err := os.ReadFile(path)
		if err != nil {
			t.Fatalf("read %s: %v", path, err)
		}
		if match := literalSet.FindString(string(data)); match != "" {
			t.Errorf("%s 重新写死了部署生命周期状态集字面量 %s，必须复用 DeploymentLifecycleJobStatusSQL/DeploymentCleanupJobStatusSQL", path, match)
		}
	}
}
