package mcpserver

import "lazy-balancer-v2/internal/apipath"

// 测试专用导出（export_test 惯例）：{param}→:param 路径还原单一实现——
// 生产与测试共用 internal/apipath.ToGin（历史三份同形实现已收敛）。
var GinPathForTest = apipath.ToGin
