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

// NonAdminVisibleToolNamesForTest 派生非管理员属主 Key 在 tools/list 能看到
// （且真能调用）的工具集合——与 serveWithToolVisibility 同一判据：非管理员 Key
// 写侧恒 read_only=1，故可见性 = 非「恒 403 工具」且 isReadOnlyTool（只读轴与
// admin 轴同时生效，两轴缺一即与生产过滤分叉）。
func NonAdminVisibleToolNamesForTest() map[string]struct{} {
	visible := make(map[string]struct{}, len(tools))
	for _, spec := range tools {
		if isForbiddenForNonAdminTool(spec) || !isReadOnlyTool(spec) {
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

// ReadOnlyHiddenToolNamesForTest 返回「GET 但对只读 Key 恒 403」的工具名
// （升序，单源 readOnlyHiddenTools）：人读文档与两份运行时文本必须按集合对账，
// 新增隐藏工具时未登记文本即报红。
func ReadOnlyHiddenToolNamesForTest() []string {
	names := make([]string, 0, len(readOnlyHiddenTools))
	for name := range readOnlyHiddenTools {
		names = append(names, name)
	}
	sort.Strings(names)
	return names
}

// ServerInstructionsForTest 暴露随 initialize 下发的运行时说明文本：外部测试
// 包用它与路由派生集对账——同一权限契约的人读文档修正后，机器可读的两份文本
// （instructions / playbook）也必须同步。
func ServerInstructionsForTest() string { return serverInstructions }

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
