package middleware

import (
	"fmt"
	"os"
	"testing"

	"lazy-balancer-v2/internal/testsupport"
)

// TestMain 是本包第一个 suite 级入口（此前无 TestMain）：承担两件与用例逻辑
// 无关的横切护栏。
//
//  1. 环境护栏：TMPDIR 被沙箱回收时 t.TempDir() 会级联假红，先收敛成一条显式
//     失败（见 testsupport.EnsureUsableTempDir）。
//  2. DB 句柄守卫：suite 终态的连接池后台协程固定上限断言。**只调用**
//     testsupport.CheckDBHandleGoroutines（跨包单源，JJC-20261115-003-B3）——
//     本包不自留第二份计数/断言实现，判据修补不会两边漂移。middleware 用例
//     自身经 handlers/db 间接开句柄，同型泄漏（Initialize 覆盖包级句柄不关旧值）
//     对本包同样成立，故与 handlers 同口径设门。
func TestMain(m *testing.M) {
	if err := testsupport.EnsureUsableTempDir(); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	code := m.Run()
	os.Exit(testsupport.CheckDBHandleGoroutines(code))
}
