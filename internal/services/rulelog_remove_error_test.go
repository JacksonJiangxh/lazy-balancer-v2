package services

// RemoveRuleLogFiles 必须回报删除失败：规则访问日志是磁盘残留，删除失败
// （权限/只读挂载/IO）此前被 os.Remove 的返回值丢弃——调用方（DeleteRule /
// 导入清理 / 集群规则替换）无从审计，残留永久不可见。口径与证书任务日志
// RemoveCertJobLogFiles 一致：不存在=成功（nil），其余错误聚合返回。

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestRemoveRuleLogFiles_reportsFailureAggregated(t *testing.T) {
	dir := t.TempDir()
	restore := SetRuleLogDirForTest(dir)
	t.Cleanup(restore)

	for _, name := range []string{"lb_ro.log", "lb_ro.log.1", "lb_ro-20260910T15-04-05.123-size.log"} {
		if err := os.WriteFile(filepath.Join(dir, name), []byte("x"), 0o644); err != nil {
			t.Fatalf("write %s: %v", name, err)
		}
	}
	// 只读目录：三个文件全部删除失败，错误必须聚合回报（首项失败即返回的
	// 实现会让调用方误以为只剩一个问题，且后续文件静默残留）。
	if err := os.Chmod(dir, 0o500); err != nil {
		t.Fatalf("chmod dir: %v", err)
	}
	t.Cleanup(func() { _ = os.Chmod(dir, 0o755) })

	err := RemoveRuleLogFiles("lb_ro")
	if err == nil {
		t.Fatal("只读目录下删除失败必须回报错误（否则残留不可见）")
	}
	if !strings.Contains(err.Error(), "lb_ro") {
		t.Fatalf("error=%v, want 含规则 id（便于定位残留）", err)
	}

	// 恢复可写后重试必须清零（幂等重试通道）。
	if err := os.Chmod(dir, 0o755); err != nil {
		t.Fatalf("restore dir mode: %v", err)
	}
	if err := RemoveRuleLogFiles("lb_ro"); err != nil {
		t.Fatalf("可写目录下重试失败: %v", err)
	}
	if _, statErr := os.Stat(filepath.Join(dir, "lb_ro.log")); !os.IsNotExist(statErr) {
		t.Fatalf("重试后活文件仍存在: %v", statErr)
	}
}

// 回归形状：无日志文件 = 成功（不存在的错误不得外泄为「清理失败」）。
func TestRemoveRuleLogFiles_absentRuleIsSuccess(t *testing.T) {
	restore := SetRuleLogDirForTest(t.TempDir())
	t.Cleanup(restore)
	if err := RemoveRuleLogFiles("lb_absent"); err != nil {
		t.Fatalf("不存在的规则日志应返回 nil: %v", err)
	}
}
