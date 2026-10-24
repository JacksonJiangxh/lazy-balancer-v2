package mcpserver_test

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"lazy-balancer-v2/internal/mcpserver"
)

// docs/mcp.zh-CN.md 的「工具权限」表此前把 3 个读探测 POST 整体算作非管理员
// 可用，实际只有 parse_certificate 挂在非管理员可过的路由组（preview_config/
// validate_import 属 admin 组，调用恒 403 且不出现在 tools/list）。本测试把
// 该行与生产装配派生的「非管理员恒 403」集合机械对账：探测工具在真实路由
// 集合下不可用时，文档必须在含「管理员」的独立子句里点名它；可用时不得带
// 该限定。
func TestMCPDocsNonAdminPermissionRowMatchesRouteSet(t *testing.T) {
	// Given：真实装配——middleware.SetupRouter 在注册期注入生产派生的集合
	_ = newAPIDocTestRouter(t)
	visible := mcpserver.NonAdminVisibleToolNamesForTest()
	probes := mcpserver.ReadOnlyProbeToolNamesForTest()
	if len(probes) != 3 {
		t.Fatalf("只读探测集=%v, want 3 项（探测集形态变化须同步文档口径）", probes)
	}
	// 前提核验：集合确实被注入且 admin 组探测工具在其中（否则对账无意义）
	if _, ok := visible["preview_config"]; ok {
		t.Fatal("前提失效：preview_config 对非管理员可见——SetupRouter 未注入恒 403 集合？")
	}

	row := nonAdminPermissionRow(t)
	if strings.Contains(row, "上述读探测 POST") {
		t.Fatalf("非管理员权限行仍用「上述读探测 POST」整体指代（3 个中仅 1 个可用）: %q", row)
	}
	// 去掉行首「| 非管理员用户 Key |」标签再按子句切分——标签本身含
	// 「管理员」三字，会把第一个子句误判为「需管理员」。
	body := strings.TrimSuffix(strings.TrimPrefix(row, "| 非管理员用户 Key |"), "|")

	// When/Then：逐个探测工具与文档子句对账
	for _, name := range probes {
		clause, found := permissionRowClause(body, name)
		if !found {
			t.Errorf("非管理员权限行未点名探测工具 %s: %q", name, row)
			continue
		}
		_, callable := visible[name]
		requiresAdmin := strings.Contains(clause, "管理员")
		switch {
		case callable && requiresAdmin:
			t.Errorf("文档把可用工具 %s 放进「需管理员」子句: %q", name, clause)
		case !callable && !requiresAdmin:
			t.Errorf("文档未标注 %s 需管理员属主（实际调用恒 403 且不可见）: %q", name, clause)
		}
	}
}

// nonAdminPermissionRow 返回「工具权限」表中非管理员用户 Key 那一行原文。
func nonAdminPermissionRow(t *testing.T) string {
	t.Helper()
	body, err := os.ReadFile(filepath.Join("..", "..", "docs", "mcp.zh-CN.md"))
	if err != nil {
		t.Fatalf("读 docs/mcp.zh-CN.md: %v", err)
	}
	for _, line := range strings.Split(string(body), "\n") {
		if strings.HasPrefix(line, "| 非管理员用户 Key |") {
			return line
		}
	}
	t.Fatal("docs/mcp.zh-CN.md 缺少「非管理员用户 Key」权限行")
	return ""
}

// permissionRowClause 在权限行内按「；」切分子句，返回点名该工具（反引号
// 包裹或裸名）的第一个子句。子句是最小口径单位：同一子句内的限定词作用于
// 其点名的全部工具。
func permissionRowClause(row, tool string) (string, bool) {
	tokens := []string{"`" + tool + "`", tool}
	for _, clause := range strings.Split(row, "；") {
		for _, token := range tokens {
			if strings.Contains(clause, token) {
				return clause, true
			}
		}
	}
	return "", false
}
