package mcpserver

// 网关（middleware.SetupRouter）与 MCP 传输层之间的一次性请求元数据通道：
// 请求体与 API Key 身份都已在网关侧解析（限长读取 + 认证查询），这里把结果
// 随 context 传给 tools/list 可见性过滤，避免同一请求体被读两遍、同一 Key
// 被点查两次。缺失（mcpserver 单测/独立挂载）时调用方按原路径回退。

import (
	"context"
	"encoding/json"
)

// RequestMeta 是 JSON-RPC 请求的最小定位信息（method + 原始 id）。
// ID 保留 RawMessage 形态：tools/list 在可见性判定失败时按原 id 回
// 空工具列表，不得把字符串/数字 id 规范化成另一种类型。
type RequestMeta struct {
	Method string
	ID     json.RawMessage
}

type requestMetaKey struct{}

// WithRequestMeta 附加网关已解析的 JSON-RPC 元数据。
func WithRequestMeta(ctx context.Context, meta RequestMeta) context.Context {
	return context.WithValue(ctx, requestMetaKey{}, meta)
}

// RequestMetaFromContext 取回网关注入的元数据；ok=false 表示未注入。
func RequestMetaFromContext(ctx context.Context) (RequestMeta, bool) {
	meta, ok := ctx.Value(requestMetaKey{}).(RequestMeta)
	return meta, ok
}

// apiKeyVisibilityContext 是网关 apiKeyAuth 已解析的 Key 属主属性。
type apiKeyVisibilityContext struct {
	readOnly bool
	admin    bool
}

type apiKeyVisibilityKey struct{}

// WithAPIKeyVisibility 附加网关已解析的 Key 属主属性（只读轴 + 管理员轴）。
// 仅在 apiKeyAuth 真正认证成功（auth_type=api_key）时调用——JWT/未认证请求
// 不携带该值，可见性判定按原路径处理。
func WithAPIKeyVisibility(ctx context.Context, readOnly, admin bool) context.Context {
	return context.WithValue(ctx, apiKeyVisibilityKey{}, apiKeyVisibilityContext{readOnly: readOnly, admin: admin})
}

// APIKeyVisibilityFromContext 取回网关注入的 Key 属主属性；ok=false 表示缺失。
func APIKeyVisibilityFromContext(ctx context.Context) (readOnly, admin, ok bool) {
	value, ok := ctx.Value(apiKeyVisibilityKey{}).(apiKeyVisibilityContext)
	if !ok {
		return false, false, false
	}
	return value.readOnly, value.admin, true
}
