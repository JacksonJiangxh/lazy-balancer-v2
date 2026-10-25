package middleware

import (
	"net/http"
	"strings"
	"testing"
)

// apiKeyReadOnlyGuard 是只读 API Key 的唯一拦截点（生产装配 v1.Use）：handler
// 内没有第二道只读门——GET /config/export、GET /auto-backup/:id/download（备份
// 含私钥与凭证明文）与全部管理写端点，对「管理员属主的只读 Key」都只靠这一行
// 挂载。此前的守卫用例全部手工注入 context（mcp_test、backup_writeguard_test、
// security_contract_test 等），删除或移动挂载点不会使任何断言失败。
//
// 只有 role=admin + read_only=1 能暴露该回归：非管理员只读 Key 仍会被
// readOnlyGuard 的角色门挡住，本用例按 403 文案区分两个拦截点。
func TestSetupRouter_readOnlyAPIKeyGuardIsMounted(t *testing.T) {
	const (
		adminKey = "lb_sk_mountadm-key"
		userKey  = "lb_sk_mountusr-key"
	)
	router := newMiddlewareTestRouter(t)
	addRouteTestAPIKeyWithReadOnly(t, 301, "romount-admin", "admin", adminKey, true)
	addRouteTestAPIKeyWithReadOnly(t, 302, "romount-user", "user", userKey, true)

	// 管理员属主的只读 Key 打管理写端点：必须由 apiKeyReadOnlyGuard 拦下。
	write := requestWithAPIKey(router, http.MethodPost, "/api/v1/rules", adminKey)
	if write.Code != http.StatusForbidden || !strings.Contains(write.Body.String(), "只读 API 密钥禁止写操作") {
		t.Fatalf("admin read-only key POST /api/v1/rules status=%d body=%q, want 403 只读 API 密钥禁止写操作",
			write.Code, write.Body.String())
	}

	// 敏感导出 GET：只读 Key 的唯一拦截点就是本守卫（handler 只校验主节点）。
	export := requestWithAPIKey(router, http.MethodGet, "/api/v1/config/export", adminKey)
	if export.Code != http.StatusForbidden || !strings.Contains(export.Body.String(), "只读 API Key 不能导出配置备份") {
		t.Fatalf("admin read-only key GET /api/v1/config/export status=%d body=%q, want 403 只读 API Key 不能导出配置备份",
			export.Code, export.Body.String())
	}

	// 读面不受影响（挂载点在位且不越权拦截）。
	read := requestWithAPIKey(router, http.MethodGet, "/api/v1/rules", adminKey)
	if read.Code != http.StatusOK {
		t.Fatalf("admin read-only key GET /api/v1/rules status=%d body=%q, want 200", read.Code, read.Body.String())
	}

	// 双重纵深：非管理员只读 Key 的写请求同样 403，且由本守卫先行拦下——
	// 挂载缺失时会落到 readOnlyGuard 的「非管理员用户只读」，文案不同。
	userWrite := requestWithAPIKey(router, http.MethodPost, "/api/v1/rules", userKey)
	if userWrite.Code != http.StatusForbidden || !strings.Contains(userWrite.Body.String(), "只读 API 密钥禁止写操作") {
		t.Fatalf("user read-only key POST /api/v1/rules status=%d body=%q, want 403 只读 API 密钥禁止写操作",
			userWrite.Code, userWrite.Body.String())
	}
}
