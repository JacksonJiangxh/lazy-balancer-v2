package handlers

func init() {
	apiDocRoutes = append(apiDocRoutes, apiDocRoute{
		Method:      "GET",
		Path:        "/mcp/tools",
		Tag:         "MCP",
		Summary:     "MCP 工具注册表",
		Response:    `{"code":0,"message":"查询成功","data":[{"name":"list_rules","description":"列出全部负载均衡规则","method":"GET","path":"/api/v1/rules","read_only":true,"usage":"先了解当前规则全貌（域名/端口/上游/启用状态），所有变更前的现状盘点入口"}]}`,
		Errors:      []string{"401 unauthenticated"},
		Description: "所有已登录用户可读；返回 MCP 工具名称、描述、映射的 REST 请求与读写分类，不含内部路由参数注记（path_args/query_args）；input_schema 按需返回（无参工具省略该字段），usage 恒返回。可见性是双轴叠加，缺一不可见：①read_only 轴——该工具对只读 API Key 可用（GET 且非 export_config/get_caddy_config，或 3 个读探测 POST 工具 parse_certificate/validate_import/preview_config；与 HTTP 方法是否为 GET 不等价）；②admin 轴——工具指向的 REST 路由若对非管理员恒 403（admin 组全部路由，或 business 组未豁免只读白名单的写路由），非管理员 Key 的 tools/list 恒不返回（调用恒 403），该信息不单列字段（tools/list 已是按当前 Key 过滤后的结果）。因此「出现在 tools/list 中」= 当前 Key 的两个轴都满足；文档中的 read_only 仅描述第一轴，非管理员专属工具由第二轴隐藏。",
	})
	apiDocRoutes = append(apiDocRoutes, apiDocRoute{
		Method:      "GET",
		Path:        "/mcp/ops-playbook",
		Tag:         "MCP",
		Summary:     "下载 MCP 操作手册",
		Response:    "\"# Lazy Balancer V2 MCP 操作手册\\n\\n（正文以 text/markdown 附件下载，与 MCP 资源 lazy-balancer://docs/ops-playbook 同源。）\"",
		Errors:      []string{"401 unauthenticated"},
		Description: "所有已登录用户可读；返回 MCP 操作手册 markdown 正文，与 MCP 资源 lazy-balancer://docs/ops-playbook 同一来源。",
	})
}
