package mcpserver

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"sync/atomic"

	"lazy-balancer-v2/internal/db"
	"lazy-balancer-v2/internal/services"
)

// apiKeyVisibility 是 tools/list 过滤所需的 Key 属主属性。
// 历史修复：role 与 readOnly 由同一次解析返回——admin 组路由对非管理员恒 403，
// 可见性必须同口径隐藏（此前只过滤只读 Key，非管理员属主的写工具全部可见）。
type apiKeyVisibility struct {
	readOnly bool
	admin    bool
	// unknown 表示无身份可判定（未携带 Key / DB 未初始化）——按「不过滤」处理，
	// 与旧实现（resolver 返回错误或非只读时原样透传）一致。
	unknown bool
}

type visibilityResolver func(apiKey string) (apiKeyVisibility, error)

// adminOnlyRoutePaths 是 admin 组路由集合（"METHOD /api/v1/path"，Gin :param
// 形态），由 middleware.SetupRouter 注册期注入（adminOnly 守卫与集合同一处
// 产生，新增 admin 路由自动同步，无需第二份清单）。未注入时（mcpserver 单测/
// 独立使用）不做角色过滤，等价旧行为。
var adminOnlyRoutePaths atomic.Pointer[map[string]struct{}]

// SetAdminOnlyRoutes 注入 admin 组路由集合（装配期一次，拷贝隔离防调用方后续改动）。
func SetAdminOnlyRoutes(routes map[string]struct{}) {
	copied := make(map[string]struct{}, len(routes))
	for key := range routes {
		copied[key] = struct{}{}
	}
	adminOnlyRoutePaths.Store(&copied)
}

// ginPath 将工具规格的 {param} 形态还原为 Gin 的 :param（ginPathToOpenAPI
// 反函数，全替换循环——多参路径逐段转换）。历史起为生产单一实现
// （原位于跨包互检测试文件），外部测试包经 export_test.go 共享。
func ginPath(path string) string {
	for {
		i := strings.IndexByte(path, '{')
		if i < 0 {
			return path
		}
		j := strings.IndexByte(path[i:], '}')
		if j < 0 {
			return path
		}
		path = path[:i] + ":" + path[i+1:i+j] + path[i+j+1:]
	}
}

// toolSpecsByName 是工具名 → 规格的索引（可见性过滤按名称回查能力）。
var toolSpecsByName = func() map[string]toolSpec {
	result := make(map[string]toolSpec, len(tools))
	for _, spec := range tools {
		result[spec.name] = spec
	}
	return result
}()

// isAdminOnlyTool 报告工具指向的 REST 路由是否在 admin 组（非管理员恒 403）。
func isAdminOnlyTool(spec toolSpec) bool {
	routes := adminOnlyRoutePaths.Load()
	if routes == nil || len(*routes) == 0 {
		return false
	}
	_, ok := (*routes)[spec.method+" /api/v1"+ginPath(spec.path)]
	return ok
}

// ReadOnlyProbeTools 只读 Key 可见的读探测 POST 工具清单（REST 白名单
// auditpolicy.go readOnlyWriteRoutes 同口径）——serveWithToolVisibility 与
// 可见性钉测试（server_test.go）共用的单一事实源（历史问题：
// 原工具侧/测试侧两份手工平行清单收敛为一份）。历史问题（历史）：
// test_certificate_config 会写 DNS TXT 验证记录，移出探测集（工具本身保留，
// 管理员仍可用；只读 Key 不可见）。历史问题（历史）：test_ca_provider
// 同理移出——ZeroSSL 缺 EAB 时会真实写 ca_providers.credentials。
var ReadOnlyProbeTools = map[string]struct{}{
	"parse_certificate": {},
	"validate_import":   {},
	"preview_config":    {},
}

// readOnlyHiddenTools 是「GET 但对只读 Key 不可见」的工具（历史修复：export_config
// 走 apiKeyReadOnlyGuard 403，只读 Key 不可见，避免呈现必然 403 的工具）。
// 与 ReadOnlyProbeTools 同为 ListToolSpecs.read_only 元数据与
// serveWithToolVisibility 可见性过滤的单一事实源（历史问题：原仅局部于
// filterReadOnlyTools，public 元数据与可见性过滤各自维护易漂移）。
var readOnlyHiddenTools = map[string]struct{}{"export_config": {}}

// isReadOnlyTool 报告工具对只读 API Key 是否「只读可用」——GET 且非隐藏工具，
// 或读探测 POST 白名单（ReadOnlyProbeTools）。ListToolSpecs.read_only 元数据与
// filterReadOnlyTools 可见性过滤共用本判据（单一事实源，消除能力与可见性漂移）。
func isReadOnlyTool(spec toolSpec) bool {
	if spec.method == http.MethodGet {
		if _, hidden := readOnlyHiddenTools[spec.name]; !hidden {
			return true
		}
	}
	_, probe := ReadOnlyProbeTools[spec.name]
	return probe
}

func serveWithToolVisibility(writer http.ResponseWriter, request *http.Request, next http.Handler, resolver visibilityResolver) {
	requestBody, err := io.ReadAll(request.Body)
	if err != nil {
		next.ServeHTTP(writer, request)
		return
	}
	request.Body = io.NopCloser(bytes.NewReader(requestBody))
	var rpcRequest struct {
		Method string          `json:"method"`
		ID     json.RawMessage `json:"id"`
	}
	if json.Unmarshal(requestBody, &rpcRequest) != nil || rpcRequest.Method != "tools/list" || resolver == nil {
		next.ServeHTTP(writer, request)
		return
	}
	visibility, err := resolver(extractAPIKey(request.Header))
	if err != nil {
		// fail-closed：无法判定 Key 属主时不再原样透传全量工具（旧行为），
		// 改为空 tools 列表 + warn 日志——工具可见性必须由身份决定。
		services.Logf("warn", "mcp tools/list 可见性判定失败，已按 fail-closed 拒绝下发工具列表: %v", err)
		writeEmptyToolsList(writer, rpcRequest.ID)
		return
	}
	if visibility.unknown || (visibility.admin && !visibility.readOnly) {
		// 无身份可判定（未携带 Key / DB 未初始化，mcpserver 独立使用）与
		// 管理员全权 Key 无需过滤。
		next.ServeHTTP(writer, request)
		return
	}
	recorder := newResponseRecorder()
	next.ServeHTTP(recorder, request)
	var filtered []byte
	if visibility.admin {
		// 管理员属主的只读 Key：仅只读约束（admin 组工具可由管理员只读 Key 读取）。
		filtered, err = filterReadOnlyTools(recorder.body.Bytes())
	} else {
		filtered, err = filterTools(recorder.body.Bytes(), func(name string) bool {
			spec, ok := toolSpecsByName[name]
			if !ok || isAdminOnlyTool(spec) {
				return false
			}
			return !visibility.readOnly || isReadOnlyTool(spec)
		})
	}
	if err != nil {
		// 过滤失败同样 fail-closed：不得回退为未过滤原文（过滤器失效的
		// 自然后果是工具全量泄露）。
		services.Logf("warn", "mcp tools/list 过滤失败，已按 fail-closed 拒绝下发工具列表: %v", err)
		writeEmptyToolsList(writer, rpcRequest.ID)
		return
	}
	for name, values := range recorder.header {
		writer.Header()[name] = append([]string(nil), values...)
	}
	writer.WriteHeader(recorder.statusCode)
	_, _ = writer.Write(filtered)
}

// writeEmptyToolsList 以空 tools 列表响应 tools/list（可见性判定失败时的
// fail-closed 终态）：保留 JSON-RPC id 供调用方配对，但不暴露任何未经身份
// 判定的工具。
func writeEmptyToolsList(writer http.ResponseWriter, requestID json.RawMessage) {
	if len(requestID) == 0 {
		requestID = json.RawMessage(`null`)
	}
	envelope := map[string]json.RawMessage{
		"jsonrpc": json.RawMessage(`"2.0"`),
		"id":      requestID,
		"result":  json.RawMessage(`{"tools":[]}`),
	}
	data, err := json.Marshal(envelope)
	if err != nil {
		http.Error(writer, `{"jsonrpc":"2.0","id":null,"result":{"tools":[]}}`, http.StatusOK)
		return
	}
	writer.Header().Set("Content-Type", "application/json")
	writer.WriteHeader(http.StatusOK)
	_, _ = writer.Write(data)
}

// resolveAPIKeyVisibility 解析 Key 属主属性（只读 + 是否管理员）。历史修复：
// 与 middleware 认证共用 db.ResolveAPIKeyIdentity 单源。
func resolveAPIKeyVisibility(apiKey string) (apiKeyVisibility, error) {
	if apiKey == "" || db.DB == nil {
		return apiKeyVisibility{unknown: true}, nil
	}
	identity, err := db.ResolveAPIKeyIdentity(db.DB, apiKey)
	if err != nil {
		return apiKeyVisibility{}, err
	}
	return apiKeyVisibility{readOnly: identity.ReadOnly, admin: identity.IsAdmin()}, nil
}

func filterReadOnlyTools(response []byte) ([]byte, error) {
	return filterTools(response, func(name string) bool {
		spec, ok := toolSpecsByName[name]
		return ok && isReadOnlyTool(spec)
	})
}

// filterTools 按 keep 谓词重建 tools 列表。keep 之外的形状语义见
// filterReadOnlyTools 的历史注释（错误形态原样透传）。
func filterTools(response []byte, keep func(name string) bool) ([]byte, error) {
	// 历史问题:错误形态(含 error 成员)或缺 result/
	// result.tools 的响应原样透传——下方固定结构体重建会把 error 形态改写为
	// 「result.tools:null」假成功,吞掉上游错误信号。
	var envelope struct {
		Error  json.RawMessage `json:"error"`
		Result json.RawMessage `json:"result"`
	}
	if err := json.Unmarshal(response, &envelope); err != nil {
		return nil, fmt.Errorf("解析 tools/list 响应: %w", err)
	}
	// 历史问题(历史修复 评审):显式 "error":null 经 RawMessage 得 4 字节
	// "null",须排除——否则错误判定把正常响应当错误形态透传、跳过过滤。
	if (len(envelope.Error) > 0 && string(envelope.Error) != "null") || len(envelope.Result) == 0 {
		return response, nil
	}
	var resultProbe struct {
		Tools json.RawMessage `json:"tools"`
	}
	if err := json.Unmarshal(envelope.Result, &resultProbe); err != nil || len(resultProbe.Tools) == 0 {
		return response, nil
	}
	// map 保字段重建（历史问题，用户裁定）：result/顶层除 tools 外的字段
	// （如 mcp-go 未来引入的 nextCursor）原样透传，不随过滤重建丢失；键序不保证，
	// JSON-RPC 消费方不依赖键序。
	var doc map[string]json.RawMessage
	if err := json.Unmarshal(response, &doc); err != nil {
		return nil, fmt.Errorf("解析 tools/list 响应: %w", err)
	}
	var result map[string]json.RawMessage
	if err := json.Unmarshal(doc["result"], &result); err != nil {
		return nil, fmt.Errorf("解析 tools/list result: %w", err)
	}
	var toolsArr []json.RawMessage
	if err := json.Unmarshal(result["tools"], &toolsArr); err != nil {
		return nil, fmt.Errorf("解析 tools/list tools: %w", err)
	}
	filtered := make([]json.RawMessage, 0, len(toolsArr))
	for _, rawTool := range toolsArr {
		var tool struct {
			Name string `json:"name"`
		}
		if err := json.Unmarshal(rawTool, &tool); err != nil {
			return nil, fmt.Errorf("解析 MCP 工具: %w", err)
		}
		if keep(tool.Name) {
			filtered = append(filtered, rawTool)
		}
	}
	filteredJSON, err := json.Marshal(filtered)
	if err != nil {
		return nil, fmt.Errorf("序列化 tools 过滤结果: %w", err)
	}
	result["tools"] = filteredJSON
	resultJSON, err := json.Marshal(result)
	if err != nil {
		return nil, fmt.Errorf("序列化 tools/list result: %w", err)
	}
	doc["result"] = resultJSON
	data, err := json.Marshal(doc)
	if err != nil {
		return nil, fmt.Errorf("序列化 tools/list 响应: %w", err)
	}
	return data, nil
}

type responseRecorder struct {
	header     http.Header
	body       bytes.Buffer
	statusCode int
}

func newResponseRecorder() *responseRecorder {
	return &responseRecorder{header: make(http.Header), statusCode: http.StatusOK}
}

func (r *responseRecorder) Header() http.Header {
	return r.header
}

func (r *responseRecorder) WriteHeader(statusCode int) {
	r.statusCode = statusCode
}

func (r *responseRecorder) Write(data []byte) (int, error) {
	return r.body.Write(data)
}
