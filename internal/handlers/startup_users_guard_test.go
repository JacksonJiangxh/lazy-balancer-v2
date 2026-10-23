package handlers

// 启动守卫的用户计数查询失败此前与 userCount>0 合并在同一 case：查询失败 →
// 整个「未初始化实例不得覆盖运行配置」守卫被静默跳过且零留痕。守卫失明时
// 保持放行（启动可用性优先，与外来路由探测失败放行同口径），但必须可查。

import (
	"database/sql"
	"strings"
	"testing"

	"lazy-balancer-v2/internal/db"
)

func TestCountStartupUsers_failureIsLoggedAndReportsUnknown(t *testing.T) {
	stub := sql.OpenDB(rowsErrStubConnector{
		match: func(q string) bool { return strings.Contains(q, "FROM users") },
		cols:  1,
	})
	t.Cleanup(func() { _ = stub.Close() })
	logBuf := captureLog(t)

	userCount, known := countStartupUsers(stub)

	if known {
		t.Fatal("查询失败时 known 须为 false（守卫本轮失明，调用方不得据此判定实例未初始化）")
	}
	if userCount != 0 {
		t.Fatalf("查询失败时 userCount=%d, want 0", userCount)
	}
	if !strings.Contains(logBuf.String(), startupUsersLookupFailedLabel) {
		t.Fatalf("查询失败未留痕, log=%q", logBuf.String())
	}
}

func TestCountStartupUsers_returnsCountWithoutWarning(t *testing.T) {
	newMetricsTestDatabase(t)
	logBuf := captureLog(t)

	userCount, known := countStartupUsers(db.DB)
	if !known {
		t.Fatal("正常库查询须 known=true")
	}
	var want int
	if err := db.DB.QueryRow("SELECT COUNT(*) FROM users").Scan(&want); err != nil {
		t.Fatalf("查询用户数: %v", err)
	}
	if userCount != want {
		t.Fatalf("userCount=%d, want %d", userCount, want)
	}
	if strings.Contains(logBuf.String(), startupUsersLookupFailedLabel) {
		t.Fatalf("正常查询不应留痕守卫失明, log=%q", logBuf.String())
	}
}
