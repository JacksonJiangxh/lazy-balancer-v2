package handlers

import (
	"fmt"
	"os"
	"testing"
)

// 包级全局态泄漏守卫：suite 结束后任何残留都说明某用例的写侧没有对应清理
// （t.Cleanup 已全部执行）。这类残留不会让当前用例失败，只会让后续用例在
// 随机顺序下以完全无关的错误失败——顺序依赖门只能靠排列碰运气，本守卫把它
// 变成确定性失败并点名残留项。
func TestMain(m *testing.M) {
	code := m.Run()

	if code == 0 {
		leaks := make([]string, 0, 5)
		if v := importWindowActive.Load(); v != 0 {
			leaks = append(leaks, fmt.Sprintf("importWindowActive=%d（导入窗口未关闭）", v))
		}
		if configImportBeginAttemptHook != nil {
			leaks = append(leaks, "configImportBeginAttemptHook 未复位")
		}
		if configImportBeforePrelockHook != nil {
			leaks = append(leaks, "configImportBeforePrelockHook 未复位")
		}
		if importPostCommitCleanupHook != nil {
			leaks = append(leaks, "importPostCommitCleanupHook 未复位")
		}
		if txCommitForTest != nil {
			leaks = append(leaks, "txCommitForTest 未复位")
		}
		if txRollbackForTest != nil {
			leaks = append(leaks, "txRollbackForTest 未复位")
		}
		if len(leaks) > 0 {
			fmt.Fprintln(os.Stderr, "全局态泄漏（用例写侧缺少清理）:")
			for _, leak := range leaks {
				fmt.Fprintln(os.Stderr, "  -", leak)
			}
			code = 1
		}
	}

	os.Exit(code)
}
