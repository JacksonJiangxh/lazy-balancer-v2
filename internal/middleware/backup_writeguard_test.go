package middleware

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/gin-gonic/gin"

	"lazy-balancer-v2/internal/mcpserver"
)

// 只读 API Key 的导入导出/备份面收口（2026-09-24 用户裁定：导入导出/备份视为
// 写入操作）：GET /auto-backup/:id/download 下发与 config/export 同级的
// lbbak（私钥+凭证明文），此前 GET 特卡仅覆盖 export，只读 Key 可旁路下载。
// 矩阵钉住整个表面：两敏感 GET + 三个写端点（基线钉），全部 403。

func readOnlyKeyRouter() *gin.Engine {
	gin.SetMode(gin.TestMode)
	router := gin.New()
	router.Use(func(c *gin.Context) {
		c.Set("auth_type", "api_key")
		c.Set("api_key_read_only", true)
		c.Next()
	}, apiKeyReadOnlyGuard())
	router.GET("/api/v1/config/export", noContent)
	router.GET("/api/v1/auto-backup/:id/download", noContent)
	router.POST("/api/v1/config/import", noContent)
	router.POST("/api/v1/auto-backup/run", noContent)
	router.POST("/api/v1/auto-backup/:id/restore", noContent)
	return router
}

func TestAPIKeyReadOnlyGuard_backupSurfaceDenied(t *testing.T) {
	// Given 只读 API Key 上下文
	router := readOnlyKeyRouter()

	cases := []struct {
		name   string
		method string
		path   string
	}{
		// 下载完整备份（含私钥+凭证明文）——修复前放行（本用例的 RED 形状）
		{"备份下载", http.MethodGet, "/api/v1/auto-backup/3/download"},
		// 基线钉（既有正确行为，防回归）
		{"配置导出", http.MethodGet, "/api/v1/config/export"},
		{"配置导入", http.MethodPost, "/api/v1/config/import"},
		{"手动备份", http.MethodPost, "/api/v1/auto-backup/run"},
		{"备份还原", http.MethodPost, "/api/v1/auto-backup/3/restore"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			// When
			recorder := httptest.NewRecorder()
			req := httptest.NewRequest(tc.method, tc.path, nil)
			router.ServeHTTP(recorder, req)

			// Then 一律 403（导入导出/备份=写入操作，只读 Key 禁止）
			if recorder.Code != http.StatusForbidden {
				t.Fatalf("%s %s: status=%d body=%s, want 403", tc.method, tc.path, recorder.Code, recorder.Body.String())
			}
		})
	}
}

// 读写 Key 不受本守卫影响（回归形状：同一表面放行到 handler）。
func TestAPIKeyReadOnlyGuard_backupSurfaceAllowsWritableKey(t *testing.T) {
	gin.SetMode(gin.TestMode)
	router := gin.New()
	router.Use(func(c *gin.Context) {
		c.Set("auth_type", "api_key")
		c.Set("api_key_read_only", false)
		c.Next()
	}, apiKeyReadOnlyGuard())
	router.GET("/api/v1/auto-backup/:id/download", noContent)

	recorder := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/api/v1/auto-backup/3/download", nil)
	router.ServeHTTP(recorder, req)
	if recorder.Code == http.StatusForbidden {
		t.Fatalf("读写 Key 不应被只读守卫拦截: %d", recorder.Code)
	}
}

// sensitiveExportGetRoutes（middleware.go）=写操作同敏感级的导出 GET 单源。
// 本测试把「路由事实」与「敏感名单」机械对账：新增导出/下载 GET 未登记即红，
// 已登记的陈旧键（路由删除/改名）也红，零命中（扫描面失效）同样红。
// 非敏感白名单必须携理由：纯 IP 文本（无凭证材料）才可豁免。
var nonSensitiveExportGetRoutes = map[string]string{
	"GET /api/v1/security/ip-lists/:id/export": "纯 IP 地址文本（名单条目），不含私钥/凭证材料",
}

func TestSensitiveExportGetRouteCoverage(t *testing.T) {
	router := newMiddlewareTestRouter(t)
	registered := map[string]bool{}
	exportLike := map[string]bool{}
	for _, route := range router.Routes() {
		key := route.Method + " " + route.Path
		registered[key] = true
		if route.Method != http.MethodGet {
			continue
		}
		if strings.HasSuffix(route.Path, "/export") || strings.HasSuffix(route.Path, "/download") {
			exportLike[key] = true
		}
	}
	if len(exportLike) == 0 {
		t.Fatal("扫描面失效：路由表中没有任何 GET 导出/下载路由（名字/挂载形式已漂移）")
	}
	// 正向：每条导出/下载 GET 必须已登记敏感度（敏感名单或携理由的白名单）。
	for key := range exportLike {
		if sensitiveExportGetRoutes[strings.TrimPrefix(key, "GET ")] {
			continue
		}
		if _, ok := nonSensitiveExportGetRoutes[key]; ok {
			continue
		}
		t.Fatalf("导出/下载 GET 未登记敏感度: %s（只读 Key 与 step-up 守卫会放行未分类的导出面）", key)
	}
	// 反向：名单键必须是真实注册路由（删除/改名后的陈旧键即红）。
	for path := range sensitiveExportGetRoutes {
		if !registered["GET "+path] {
			t.Fatalf("敏感导出名单指向未注册路由: GET %s", path)
		}
	}
	for key := range nonSensitiveExportGetRoutes {
		if !registered[key] {
			t.Fatalf("非敏感白名单指向未注册路由: %s", key)
		}
		if sensitiveExportGetRoutes[strings.TrimPrefix(key, "GET ")] {
			t.Fatalf("%s 同时出现在敏感与白名单（自相矛盾）", key)
		}
	}
	// 交叉：敏感路由若存在 MCP 工具，其 read_only 必须为 false（否则只读 Key
	// 经 MCP 绕过 REST 侧敏感 GET 卡点）。
	for _, spec := range mcpserver.ListToolSpecs() {
		key := spec.Method + " " + spec.Path
		if !sensitiveExportGetRoutes[strings.TrimPrefix(key, "GET ")] {
			continue
		}
		if spec.ReadOnly {
			t.Fatalf("MCP 工具 %s 指向敏感导出路由 %s，read_only 不得为 true", spec.Name, key)
		}
	}
}
