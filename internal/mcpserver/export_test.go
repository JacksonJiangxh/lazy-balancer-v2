package mcpserver

// 测试专用导出（export_test 惯例）：{param}→:param 路径还原单一实现——
// 历史六维度收敛前，mcp_routes_parity_test.go（mcpserver_test 包）的
// openAPIToGinPath 与 tool_visibility_crosscheck_test.go（本包）的 ginPath
// 是双份同形实现；经本文件导出后外部测试包共享同一实现。
var GinPathForTest = ginPath
