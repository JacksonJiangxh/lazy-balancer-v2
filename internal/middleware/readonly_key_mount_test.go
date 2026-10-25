package middleware

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"

	"lazy-balancer-v2/internal/db"
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

// admin 组的 adminOnly 对敏感导出 GET 的唯一拦截点：非管理员（非只读）Key 打
// GET /config/export 时，apiKeyReadOnlyGuard 不拦（read_only=0），handler 只
// 校验主节点——删掉 admin 组首位 adminOnly 就会把含私钥与凭证明文的完整备份
// 交给任意登录用户。断言 403 文案为 adminOnly 的「需要管理员权限」，与
// readOnlyGuard 的「非管理员用户只读」区分来源。
func TestSetupRouter_adminOnlyProtectsSensitiveExportGet(t *testing.T) {
	const (
		userKey     = "lb_sk_export-user-key"
		readOnlyKey = "lb_sk_export-readonly-key"
	)
	router := newMiddlewareTestRouter(t)
	addClusterRouteTestAPIKey(t, 311, "exportuser", "user", userKey)
	addRouteTestAPIKeyWithReadOnly(t, 312, "exportreadonly", "user", readOnlyKey, true)

	response := requestWithAPIKey(router, http.MethodGet, "/api/v1/config/export", userKey)
	if response.Code != http.StatusForbidden || !strings.Contains(response.Body.String(), "需要管理员权限") {
		t.Fatalf("user key GET /config/export status=%d body=%q, want 403 需要管理员权限（adminOnly 必须前置于导出 handler）",
			response.Code, response.Body.String())
	}

	// 对照组：只读 Key 被更前面的 apiKeyReadOnlyGuard 拦下，文案不同——两个
	// 拦截点都删才可能泄露，文案断言让任一挂载缺失都能定位。
	readOnlyResponse := requestWithAPIKey(router, http.MethodGet, "/api/v1/config/export", readOnlyKey)
	if readOnlyResponse.Code != http.StatusForbidden || !strings.Contains(readOnlyResponse.Body.String(), "只读 API Key 不能导出配置备份") {
		t.Fatalf("read-only key GET /config/export status=%d body=%q, want 403 只读 API Key 不能导出配置备份",
			readOnlyResponse.Code, readOnlyResponse.Body.String())
	}
}

// admin 组级 readOnlyGuard 的从节点否决：mfa_write_guard=0 时 mfaStepUpGuard 不
// 产生 403，从节点 403 只能来自 readOnlyGuard。三个 admin 端点（原始 Caddy 配置
// 覆写/Caddy 启停/服务重启）的 handler 内都没有主从门——删掉组级 readOnlyGuard
// 即让从节点本地覆写运行配置，现有 from-node 用例全部依赖 mfa_write_guard=1 的
// step-up 短路，不会变红。
func TestSetupRouter_adminGroupReadOnlyGuardBlocksSlaveWrites(t *testing.T) {
	router := newMiddlewareTestRouter(t)
	if _, err := db.DB.Exec("UPDATE global_config SET is_master=0, mfa_write_guard=0 WHERE id=1"); err != nil {
		t.Fatalf("set slave node: %v", err)
	}
	if _, err := db.DB.Exec(`INSERT INTO users (id,username,password_hash,role,is_enabled,password_version)
		VALUES (401,'slave-admin','x','admin',1,0)`); err != nil {
		t.Fatalf("seed admin: %v", err)
	}
	token, err := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{
		"user_id": float64(401), "username": "slave-admin", "pwd_ver": float64(0),
		"jti": "slave-admin-jti", "exp": time.Now().Add(time.Hour).Unix(),
	}).SignedString([]byte("test-secret"))
	if err != nil {
		t.Fatalf("sign token: %v", err)
	}

	for _, probe := range []struct{ method, path, body string }{
		{http.MethodPut, "/api/v1/caddy/config", `{}`},
		{http.MethodPost, "/api/v1/caddy/start", `{}`},
		{http.MethodPost, "/api/v1/system/restart", `{}`},
	} {
		request := httptest.NewRequest(probe.method, probe.path, strings.NewReader(probe.body))
		request.Header.Set("Authorization", "Bearer "+token)
		request.Header.Set("Content-Type", "application/json")
		response := httptest.NewRecorder()
		router.ServeHTTP(response, request)
		if response.Code != http.StatusForbidden || !strings.Contains(response.Body.String(), "从节点只读") {
			t.Fatalf("%s %s status=%d body=%q, want 403 从节点只读（admin 组 readOnlyGuard 挂载面）",
				probe.method, probe.path, response.Code, response.Body.String())
		}
	}
}

// 面板管理面 SetTrustedProxies(nil)：X-Forwarded-For 不参与 ClientIP，登录限流
// 桶键恒为 RemoteAddr。旧行为（信任任意代理）下攻击者每次换 XFF 即可换桶，
// 10/min 的登录爆破防线被完全绕过；部署文档把「不信任转发头」写成安全约束，
// 但全仓无一条断言钉住它。
func TestSetupRouter_ignoresForwardedForForLoginRateLimit(t *testing.T) {
	withIsolatedRateLimitBuckets(t)
	router := newMiddlewareTestRouter(t)

	// 同一 RemoteAddr + 10 个不同 XFF：登录桶必须仍按 RemoteAddr 计数。
	for attempt := 0; attempt < 10; attempt++ {
		request := httptest.NewRequest(http.MethodPost, "/api/v1/auth/login", strings.NewReader(`{}`))
		request.RemoteAddr = "198.51.100.77:1234"
		request.Header.Set("X-Forwarded-For", fmt.Sprintf("1.2.3.%d", attempt+1))
		request.Header.Set("Content-Type", "application/json")
		response := httptest.NewRecorder()
		router.ServeHTTP(response, request)
		if response.Code == http.StatusTooManyRequests {
			t.Fatalf("attempt %d 在 10/min 预算内被限流（桶键错误?）", attempt+1)
		}
	}
	request := httptest.NewRequest(http.MethodPost, "/api/v1/auth/login", strings.NewReader(`{}`))
	request.RemoteAddr = "198.51.100.77:1234"
	request.Header.Set("X-Forwarded-For", "1.2.3.99")
	request.Header.Set("Content-Type", "application/json")
	response := httptest.NewRecorder()
	router.ServeHTTP(response, request)
	if response.Code != http.StatusTooManyRequests {
		t.Fatalf("第 11 次 status=%d body=%q, want 429（XFF 轮换不得换桶）", response.Code, response.Body.String())
	}

	// 桶键直接断言：RemoteAddr 桶存在，伪造 XFF 地址无桶。
	loginRateBuckets.Lock()
	_, remoteKeyed := loginRateBuckets.entries["198.51.100.77|login"]
	_, spoofedKeyed := loginRateBuckets.entries["1.2.3.99|login"]
	loginRateBuckets.Unlock()
	if !remoteKeyed {
		t.Fatal("限流桶未按 RemoteAddr 记账（SetTrustedProxies(nil) 语义失效）")
	}
	if spoofedKeyed {
		t.Fatal("X-Forwarded-For 被采信为限流桶键（转发头信任面回退）")
	}
}

// CORS/gzip 的挂载与次序只在自建链验证过（cors_pin_test/gzip_vary_test 用
// gin.New 手工装配）。真实 SetupRouter 的次序：corsMiddleware → gzip →
// 认证链——预检必须在认证前 204 且带 Vary: Origin；错误响应（401）保留
// Vary: Origin（gzip 对 status≥400 不压缩、不 Del("Vary")），否则共享缓存可把
// 某源的 ACAO 复用到另一源的错误响应。
func TestSetupRouter_CORSAndGzipOrderOnRealChain(t *testing.T) {
	router := newMiddlewareTestRouter(t)
	const origin = "https://panel.example.com"

	preflight := httptest.NewRequest(http.MethodOptions, "/api/v1/rules", nil)
	preflight.Header.Set("Origin", origin)
	preflight.Header.Set("Access-Control-Request-Method", http.MethodGet)
	preflightResponse := httptest.NewRecorder()
	router.ServeHTTP(preflightResponse, preflight)
	if preflightResponse.Code != http.StatusNoContent {
		t.Fatalf("preflight status=%d, want 204（CORS 必须先于认证链应答）", preflightResponse.Code)
	}
	if !headerValuesContain(preflightResponse.Header().Values("Vary"), "Origin") {
		t.Fatalf("preflight Vary=%v, want 含 Origin", preflightResponse.Header().Values("Vary"))
	}

	anonymous := httptest.NewRequest(http.MethodGet, "/api/v1/rules", nil)
	anonymous.Header.Set("Origin", origin)
	anonymous.Header.Set("Accept-Encoding", "gzip")
	anonymousResponse := httptest.NewRecorder()
	router.ServeHTTP(anonymousResponse, anonymous)
	if anonymousResponse.Code != http.StatusUnauthorized {
		t.Fatalf("anonymous GET /rules status=%d, want 401", anonymousResponse.Code)
	}
	if !headerValuesContain(anonymousResponse.Header().Values("Vary"), "Origin") {
		t.Fatalf("401 响应 Vary=%v, want 含 Origin（gzip 不得删除 CORS 的 Vary）", anonymousResponse.Header().Values("Vary"))
	}
	if encoding := anonymousResponse.Header().Get("Content-Encoding"); encoding != "" {
		t.Fatalf("401 响应 Content-Encoding=%q, want 空（错误响应不压缩）", encoding)
	}
}
