package middleware

// 公开/机器端点的限流挂载是它们唯一的滥用防线：注册与 service-control 都是
// 匿名可达的写端点（每次无效尝试 = body 读 + 条件 UPDATE/BEGIN IMMEDIATE +
// 审计 INSERT），OIDC 回调失败分支会写审计行，票据登录/MFA 验码走登录桶。
// 此前只有 branding/oidc-status/oidc-login/setup 有 SetupRouter 级断言，其余
// 挂载行被「精简公开块」删除时 41 个 middleware 用例全绿。

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/gin-gonic/gin"
)

func TestSetupRouter_publicEndpointRateLimits(t *testing.T) {
	cases := []struct {
		name    string
		method  string
		path    string
		limit   int
		message string
	}{
		{name: "cluster register", method: http.MethodPost, path: "/api/v1/cluster/register", limit: 30, message: "注册请求过于频繁"},
		{name: "cluster service control", method: http.MethodPost, path: "/api/v1/cluster/service-control", limit: 20, message: "服务控制请求过于频繁"},
		{name: "oidc callback", method: http.MethodGet, path: "/api/v1/auth/oidc/callback", limit: 60, message: "OIDC 回调请求过于频繁"},
		{name: "ticket login", method: http.MethodPost, path: "/api/v1/auth/ticket-login", limit: 10, message: "登录尝试过于频繁"},
		{name: "mfa verify", method: http.MethodPost, path: "/api/v1/auth/mfa/verify", limit: 10, message: "登录尝试过于频繁"},
	}
	for _, test := range cases {
		t.Run(test.name, func(t *testing.T) {
			withIsolatedRateLimitBuckets(t)
			router := newMiddlewareTestRouter(t)
			ip := "198.51.100.201:3456"

			// When：同一 IP 连续 limit 次请求（凭证/请求体非法，限流先于业务判定）。
			for attempt := 1; attempt <= test.limit; attempt++ {
				request := httptest.NewRequest(test.method, test.path, bytes.NewReader([]byte(`{}`)))
				request.RemoteAddr = ip
				request.Header.Set("Content-Type", "application/json")
				response := httptest.NewRecorder()
				router.ServeHTTP(response, request)
				if response.Code == http.StatusTooManyRequests {
					t.Fatalf("attempt %d/%d status=429，预算内被提前限流", attempt, test.limit)
				}
			}

			// Then：第 limit+1 次必须在业务处理前被 429 截断（挂载行删除即失守）。
			request := httptest.NewRequest(test.method, test.path, bytes.NewReader([]byte(`{}`)))
			request.RemoteAddr = ip
			request.Header.Set("Content-Type", "application/json")
			response := httptest.NewRecorder()
			router.ServeHTTP(response, request)
			if response.Code != http.StatusTooManyRequests || !bytes.Contains(response.Body.Bytes(), []byte(test.message)) {
				t.Fatalf("%s 第 %d 次 status=%d body=%q, want 429 含 %q", test.path, test.limit+1, response.Code, response.Body.String(), test.message)
			}
		})
	}
}

// 集群机器限流的 IP 宽桶（300/min/IP）：同一 IP 用不同凭证打散时，凭证桶各
// 计 1 不会触发，唯一防线是 IP 桶。成功响应必须回滚额度（合法节点/NAT 出口
// 不被自己的正常流量打满）；失败（401）保留额度。
func TestClusterMachineRateLimit_ipWideBucketAndSuccessRollback(t *testing.T) {
	t.Run("301 次成功跨越 IP 上限且额度全部回滚", func(t *testing.T) {
		withIsolatedRateLimitBuckets(t)
		database, firstToken := newClusterAuthContractDatabase(t)
		const clientIP = "198.51.100.70"
		const scope = "ip-wide-success"
		tokens := []string{firstToken}
		for index := 1; index < 301; index++ {
			token := fmt.Sprintf("cluster-ip-wide-token-%03d", index)
			hash := sha256.Sum256([]byte(token))
			if _, err := database.Exec("INSERT INTO nodes (id,cluster_token_hash,is_approved) VALUES (?,?,1)",
				1000+index, hex.EncodeToString(hash[:])); err != nil {
				t.Fatalf("insert node %d: %v", index, err)
			}
			tokens = append(tokens, token)
		}
		router := gin.New()
		router.Use(clusterMachineRateLimit(scope, clusterCredentialFromToken))
		router.Use(clusterTokenAuth(database))
		router.GET("/cluster", func(c *gin.Context) { c.Status(http.StatusNoContent) })

		for attempt, token := range tokens {
			request := httptest.NewRequest(http.MethodGet, "/cluster", nil)
			request.RemoteAddr = clientIP + ":1234"
			request.Header.Set("X-Cluster-Token", token)
			response := httptest.NewRecorder()
			router.ServeHTTP(response, request)
			if response.Code != http.StatusNoContent {
				t.Fatalf("attempt %d status=%d body=%s, want 204（成功流量必须回滚 IP 宽桶）",
					attempt+1, response.Code, response.Body.String())
			}
		}
		if count := rateLimitBucketCount(clientIP + "|" + scope + "|ip"); count != 0 {
			t.Fatalf("301 次成功后 IP 桶 count=%d, want 0（成功回滚失效，NAT 出口将误伤合法节点）", count)
		}
	})

	t.Run("第 300 次失败占满 IP 桶，成功流量在边界处回滚", func(t *testing.T) {
		withIsolatedRateLimitBuckets(t)
		database, validToken := newClusterAuthContractDatabase(t)
		const clientIP = "198.51.100.71"
		const scope = "ip-wide-limit"
		router := gin.New()
		router.Use(clusterMachineRateLimit(scope, clusterCredentialFromToken))
		router.Use(clusterTokenAuth(database))
		router.GET("/cluster", func(c *gin.Context) { c.Status(http.StatusNoContent) })
		send := func(token string) *httptest.ResponseRecorder {
			request := httptest.NewRequest(http.MethodGet, "/cluster", nil)
			request.RemoteAddr = clientIP + ":1234"
			request.Header.Set("X-Cluster-Token", token)
			response := httptest.NewRecorder()
			router.ServeHTTP(response, request)
			return response
		}

		// 299 次失败（凭证桶各 1，IP 桶累计 299）。
		for index := range 299 {
			if response := send(fmt.Sprintf("invalid-ip-wide-%03d", index)); response.Code != http.StatusUnauthorized {
				t.Fatalf("failure %d status=%d, want 401", index+1, response.Code)
			}
		}
		// 成功请求占满 300 后必须回滚——否则下一笔失败即被 429（无限证据）。
		if response := send(validToken); response.Code != http.StatusNoContent {
			t.Fatalf("valid request at count=299 status=%d body=%s, want 204", response.Code, response.Body.String())
		}
		if response := send("invalid-ip-wide-299"); response.Code != http.StatusUnauthorized {
			t.Fatalf("failure at count=300 status=%d body=%s, want 401（成功回滚后仍有 1 个额度）", response.Code, response.Body.String())
		}
		// 第 301 次失败：IP 桶满 → 429（删除 ipLimit 分支后此断言必红）。
		if response := send("invalid-ip-wide-300"); response.Code != http.StatusTooManyRequests ||
			!bytes.Contains(response.Body.Bytes(), []byte("集群机器接口请求过于频繁")) {
			t.Fatalf("failure 301 status=%d body=%s, want 429 集群机器接口请求过于频繁", response.Code, response.Body.String())
		}
	})
}

// rateLimitBucketCount 读取指定键当前计数（键不存在返回 0）。
func rateLimitBucketCount(key string) int {
	loginRateBuckets.Lock()
	bucket := loginRateBuckets.entries[key]
	loginRateBuckets.Unlock()
	if bucket == nil {
		return 0
	}
	bucket.mu.Lock()
	defer bucket.mu.Unlock()
	return bucket.count
}
