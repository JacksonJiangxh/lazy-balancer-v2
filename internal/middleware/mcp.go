package middleware

import (
	"net/http"
	"time"

	"github.com/gin-gonic/gin"
)

func mcpAccessGuard() gin.HandlerFunc {
	return func(c *gin.Context) {
		if c.GetString("auth_type") != "api_key" {
			recordAuthenticationRejection(c, "mcp_auth_rejected")
			c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"code": 401, "message": "MCP 仅支持 API 密钥认证"})
			return
		}
		if !c.GetBool("api_key_mcp_enabled") {
			recordAuthenticationRejection(c, "mcp_disabled")
			c.AbortWithStatusJSON(http.StatusForbidden, gin.H{"code": 403, "message": "MCP 功能未开启"})
			return
		}
		c.Next()
	}
}

// loopbackAPIClient 是 MCP 工具内部转发专用的本机回环客户端。转发 base URL
// 恒为明文 http://127.0.0.1:<port>/api/v1（见 SetupRouter），因此不需要 TLS
// 配置——此前挂了 InsecureSkipVerify 的死配置（分支不可达），读者会误判
// 「回环转发存在 TLS 面且已显式豁免」；若未来改 HTTPS，跳过校验必须显式
// 注释「自签回环」并配钉测，不得作为默认继承。
// 重定向在 mcpserver 侧统一关闭（redirectlessClient），此处不重复配置。
func loopbackAPIClient() *http.Client {
	return &http.Client{Timeout: 60 * time.Second}
}
