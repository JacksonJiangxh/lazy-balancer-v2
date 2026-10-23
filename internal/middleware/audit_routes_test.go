package middleware

import (
	"net/http"
	"testing"

	"lazy-balancer-v2/internal/services"
)

func TestSetupRouter_writeRoutesHaveExplicitAuditClassification(t *testing.T) {
	// Given
	router := newMiddlewareTestRouter(t)
	intentionalSkip := map[string]struct{}{
		"POST /api/v1/admin-tls/inspect":            {},
		"POST /api/v1/certificates/parse":           {},
		"POST /api/v1/certificates/jobs/current":    {},
		"POST /api/v1/cluster/nodes/report":         {},
		"POST /api/v1/cluster/registration/confirm": {},
		// 服务控制机器接口：handler 全路径（含失败）显式记录「服务控制」审计。
		"POST /api/v1/cluster/service-control": {},
		"POST /api/v1/config/import/validate":  {},
		"POST /api/v1/config/preview":          {},
		// c：/config/validate 已升为 Explicit（handler 记录校验三态）。
		"POST /api/v1/mcp":             {},
		"POST /api/v1/rules/cert-info": {},
		// v2.1.8 MFA：setup/verify-step 为读形态或内部动作（不产生审计；handler
		// 对失败已按认证拒绝/错误路径细分记录）。recovery-codes 已升为 Explicit
		//（handler 显式记录「生成/恢复码」），不再属有意跳过。
		"POST /api/v1/auth/mfa/setup":       {},
		"POST /api/v1/auth/mfa/verify-step": {},
		// 三库手动更新：审计由任务体 defer 单记（2026-09-29 用户裁定 + 历史
		// 收敛——handler 补记已撤、operator 经 RunContext 归人）。
		"POST /api/v1/security/crs/update":         {},
		"POST /api/v1/security/ip2region/update":   {},
		"POST /api/v1/security/threat-lib/update":  {},
		"POST /api/v1/security/crawler-lib/update": {},
		// 大屏流量采集租约：UI 生命周期内部动作，显式 skip。
		"POST /api/v1/security/overview/threat-screen/collector":   {},
		"DELETE /api/v1/security/overview/threat-screen/collector": {},
		// 任务触发：已升 Explicit——12 个可触发族中 7 族
		// 任务体零审计，handler 对非自记族显式补记「触发/任务监控」（自记族
		// 跳过，保 单记裁定），不再属有意跳过。
	}
	writeMethods := map[string]struct{}{
		http.MethodPost: {}, http.MethodPut: {}, http.MethodPatch: {}, http.MethodDelete: {},
	}

	// When
	// 反向对账：intentionalSkip 的每个键必须是真实注册的写路由——路由删除/
	// 改名后旧键恒不命中，跳过声明就成了永不生效的孤儿（后续新增写路由的
	// 分类缺陷被掩盖）。
	registered := map[string]struct{}{}
	for _, route := range router.Routes() {
		registered[route.Method+" "+route.Path] = struct{}{}
	}
	for key := range intentionalSkip {
		if _, ok := registered[key]; !ok {
			t.Fatalf("intentional audit skip 指向未注册路由: %s", key)
		}
	}
	for _, route := range router.Routes() {
		if _, write := writeMethods[route.Method]; !write {
			continue
		}
		key := route.Method + " " + route.Path
		policy := services.ClassifyAuditRoute(route.Method, route.Path)

		// Then
		if _, skipped := intentionalSkip[key]; skipped {
			if policy != services.AuditPolicySkip || !services.IsAuditedWriteRoute(route.Method, route.Path) {
				t.Errorf("intentional audit skip is not explicitly classified: %s", key)
			}
			continue
		}
		if policy == services.AuditPolicySkip {
			t.Errorf("write route has default audit classification: %s", key)
		}
	}
}
