package mcpserver_test

import (
	"strings"
	"testing"

	"lazy-balancer-v2/internal/mcpserver"
)

// TestMCPDocsRestOnlyEndpointsExistInRouter 是「仅 REST 可用」表的反向对账：
// 表内每条端点必须仍是 SetupRouter 注册的真实路由。缺这一方向时，路由改名/
// 删除后文档仍教用户走旧路径（404），而正向对账只检查「表里不能列工具已覆盖
// 的端点」——两条方向合起来才是文档自称的双向机械校验。
func TestMCPDocsRestOnlyEndpointsExistInRouter(t *testing.T) {
	router := newAPIDocTestRouter(t)
	registered := make(map[string]struct{}, len(router.Routes()))
	for _, route := range router.Routes() {
		registered[route.Method+" "+route.Path] = struct{}{}
	}

	endpoints, err := mcpserver.RestOnlyDocEndpointsForTest()
	if err != nil {
		t.Fatalf("解析文档表失败: %v", err)
	}
	if len(endpoints) == 0 {
		t.Fatal("「仅 REST 可用的能力」表未解析出任何端点（表格形态被改动？）")
	}
	for _, endpoint := range endpoints {
		// 文档表用相对路径（/rules 等），真实路由表带 /api/v1 前缀。
		docPath := endpoint.Path
		if !strings.HasPrefix(docPath, "/api/v1") {
			docPath = "/api/v1" + docPath
		}
		ginPath := mcpserver.GinPathForTest(docPath)
		if _, ok := registered[endpoint.Method+" "+ginPath]; !ok {
			t.Errorf("文档把 %s %s 列为仅 REST，但路由未注册——路由已改名/删除而文档未同步", endpoint.Method, endpoint.Path)
		}
	}
}
