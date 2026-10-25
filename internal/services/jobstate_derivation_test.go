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
		for _, line := range strings.Split(string(data), "\n") {
			if countDeploymentLifecycleGoLiterals(line) < 2 {
				continue
			}
			t.Errorf("%s 重新写死了部署生命周期状态集（Go 字面量）: %s，必须复用 deploymentLifecycleJobStatuses/JobLifecycle", path, strings.TrimSpace(line))
		}
	}
}

// countDeploymentLifecycleGoLiterals 统计一行里作为 Go 字符串字面量出现的部署
// 生命周期状态个数：`[]string{"downloaded", "cleanup_dns"}` 与
// `status == "downloaded" || status == "cleanup_dns"` 都是第二份集合的形态。
// SQL 片段用单引号包裹，不计入；单状态比较（1 个）是合法用法。
func countDeploymentLifecycleGoLiterals(line string) int {
	count := 0
	for _, status := range []string{"downloaded", "cleanup_dns", "cleanup_warning"} {
		if strings.Contains(line, `"`+status+`"`) {
			count++
		}
	}
	return count
}

// 部署链回写源态集 = 部署生命周期 + downloading（唯一「证书字节已到手、
// downloaded 进度行未落库」的 active 形态）。终态（issued/failed/disabled）在
// 集合外——那是并发胜者已提交的状态，陈旧部署回调不得把成功结果拉回部署生命
// 周期；其余 active 签发态（creating_order/validating…）也在集合外——它们发生在
// 证书字节到手之前，到达部署失败回写的材料只能是陈旧回调的，写回 downloaded 会
// 越权改写正在进行的签发（doesNotDowngradeOutsideDeployableLifecycle 契约）；
// queued/waiting_ca 由队列/CA 退避链维护。
func TestDeploymentPersistenceStatusSetDerivedFromLifecycleMap(t *testing.T) {
	want := append([]string{}, deploymentLifecycleJobStatuses...)
	want = append(want, "downloading")
	sort.Strings(want)
	if strings.Join(deploymentPersistenceJobStatuses, ",") != strings.Join(want, ",") {
		t.Fatalf("deploymentPersistenceJobStatuses=%v, want %v（部署生命周期 + downloading）",
			deploymentPersistenceJobStatuses, want)
	}
	contains := func(status string) bool {
		for _, got := range deploymentPersistenceJobStatuses {
			if got == status {
				return true
			}
		}
		return false
	}
	for _, status := range []string{"downloaded", "cleanup_dns", "cleanup_warning", "downloading"} {
		if !contains(status) {
			t.Fatalf("集合缺 %q（部署链必须能从该状态收敛材料）: %v", status, deploymentPersistenceJobStatuses)
		}
	}
	for _, status := range []string{"issued", "failed", "disabled", "queued", "waiting_ca", "creating_order", "validating", "finalized"} {
		if contains(status) {
			t.Fatalf("集合不得含 %q（终态=并发胜者/在途签发=不得越权改写）: %v", status, deploymentPersistenceJobStatuses)
		}
	}
}
