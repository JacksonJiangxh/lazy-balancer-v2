package mcpserver

import (
	"database/sql"
	"sort"

	"lazy-balancer-v2/internal/apipath"
	"lazy-balancer-v2/internal/db"
)

// 测试专用导出（export_test 惯例）：{param}→:param 路径还原单一实现——
// 生产与测试共用 internal/apipath.ToGin（历史三份同形实现已收敛）。
var GinPathForTest = apipath.ToGin

// RestoreDBForTest 复位夹具数据库句柄的单源序列：db.Close() 会 SetDB(nil)，
// 只还原三个包级变量会让 db.GetDB() 与 db.DB 在测试间分叉（后续依赖
// GetDB() 的用例读到 nil，表现为顺序依赖假红）。包内与外部测试包共用
// （mcpserver_test 经 mcpserver.RestoreDBForTest 调用）。
func RestoreDBForTest(oldDB, oldMetricsDB, oldAuditDB *sql.DB) {
	db.DB, db.MetricsDB, db.AuditDB = oldDB, oldMetricsDB, oldAuditDB
	db.SetDB(oldDB)
}

// NonAdminVisibleToolNamesForTest 按当前注入的「非管理员恒 403」路由集派生
// 非管理员属主 Key 在 tools/list 能看到（且真能调用）的工具集合——与
// serveWithToolVisibility 同一判据。外部测试包用它把文档权限表与生产路由
// 集合机械对账。
func NonAdminVisibleToolNamesForTest() map[string]struct{} {
	visible := make(map[string]struct{}, len(tools))
	for _, spec := range tools {
		if isForbiddenForNonAdminTool(spec) {
			continue
		}
		visible[spec.name] = struct{}{}
	}
	return visible
}

// ReadOnlyProbeToolNamesForTest 返回只读探测 POST 工具名（升序）：文档权限表
// 对账按探测集动态取面，新增探测工具自动进入对账范围。
func ReadOnlyProbeToolNamesForTest() []string {
	names := make([]string, 0, len(ReadOnlyProbeTools))
	for name := range ReadOnlyProbeTools {
		names = append(names, name)
	}
	sort.Strings(names)
	return names
}

// DocEndpointForTest 是「仅 REST 可用的能力」表中的一条端点（方法 + 路径原文）。
type DocEndpointForTest struct {
	Method string
	Path   string
}

// RestOnlyDocEndpointsForTest 暴露文档表端点清单：外部测试包用它与 SetupRouter
// 的真实路由表反向对账（表内端点必须仍注册）。解析实现与包内正向对账共用。
func RestOnlyDocEndpointsForTest() ([]DocEndpointForTest, error) {
	section, err := restOnlyDocSectionText()
	if err != nil {
		return nil, err
	}
	var endpoints []DocEndpointForTest
	for _, match := range docEndpointPattern.FindAllStringSubmatch(section, -1) {
		for _, path := range expandBraceAlternatives(match[2]) {
			endpoints = append(endpoints, DocEndpointForTest{Method: match[1], Path: path})
		}
	}
	return endpoints, nil
}
