package mcpserver

import "lazy-balancer-v2/internal/apipath"

// 测试专用导出（export_test 惯例）：{param}→:param 路径还原单一实现——
// 生产与测试共用 internal/apipath.ToGin（历史三份同形实现已收敛）。
var GinPathForTest = apipath.ToGin

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
