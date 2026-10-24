// Package apikey 是 API Key 凭据传输形态的单一事实源：REST 认证中间件与 MCP
// 转发侧必须用同一规则从请求头取 Key。两侧各写一份时，认证侧一旦放宽（新增
// 方案名/兼容小写），转发侧仍按旧前缀判定，表现为「Key 有效但 MCP 工具回
// 缺少 API 密钥」——错误文案指向错误方向，排障成本高。
package apikey

import (
	"net/http"
	"strings"
)

// AuthorizationScheme 是 API Key 在 Authorization 头中的方案前缀。它与 JWT 的
// "Bearer <JWT>" 共用 Bearer 方案，靠 lb_sk_ 前缀区分两种凭据类别。
const AuthorizationScheme = "Bearer lb_sk_"

// IsAPIKeyAuthorization 判定 Authorization 头是否为 API Key 形态。
func IsAPIKeyAuthorization(value string) bool {
	return strings.HasPrefix(value, AuthorizationScheme)
}

// FromHeader 按约定顺序提取 API Key：X-API-Key 头优先；否则 Authorization
// 头必须是 "Bearer lb_sk_..." 形态，并去掉 "Bearer " 方案前缀。
// 返回空串表示请求未携带 API Key（JWT 或匿名请求）。
func FromHeader(header http.Header) string {
	if key := header.Get("X-API-Key"); key != "" {
		return key
	}
	authorization := header.Get("Authorization")
	if !IsAPIKeyAuthorization(authorization) {
		return ""
	}
	return strings.TrimPrefix(authorization, "Bearer ")
}
