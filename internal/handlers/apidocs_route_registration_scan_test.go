package handlers

// 路由注册派生扫描器（文档对账共用）：从 middleware.go 源码派生
// 「注册路径 → 末位处理器 + 所挂限流桶」。
//
// 用 go/ast 而非逐行正则：注册实参可跨行、处理器可为内联闭包，行级正则遇到
// 这些形态会整体跳过该注册——被跳过的端点同时逃过派生集合与手工清单两侧
// 校验，形成假绿。AST 遍历对单行/多行/闭包三种形态一视同仁。

import (
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"strconv"
	"strings"
	"testing"
)

type middlewareRouteRegistration struct {
	// handler 是注册末位处理器名（`h.X` 的 X）；无 h.X 的机器接口注册为空串。
	handler string
	// rateLimitKey/rateLimitPerMin 是注册处挂载的限流桶（loginRateLimit 与
	// clusterRateLimit 两个中间件）；未挂限流时 rateLimitPerMin 为 0。
	rateLimitKey       string
	rateLimitPerMin    int
	rateLimitMounted   bool
	rateLimitMessageCN string
}

// loginRateLimitLimit 从 loginRateLimit 的实现体派生限额——文档对账的口径
// 必须与实参同源，不能在测试里再写一个常量副本。
func loginRateLimitLimit(file *ast.File) (int, bool) {
	limit := 0
	for _, decl := range file.Decls {
		fn, ok := decl.(*ast.FuncDecl)
		if !ok || fn.Name.Name != "loginRateLimit" || fn.Body == nil {
			continue
		}
		ast.Inspect(fn.Body, func(n ast.Node) bool {
			call, ok := n.(*ast.CallExpr)
			if !ok {
				return true
			}
			if ident, ok := call.Fun.(*ast.Ident); !ok || ident.Name != "clusterRateLimit" || len(call.Args) < 2 {
				return true
			}
			if lit, ok := call.Args[1].(*ast.BasicLit); ok && lit.Kind == token.INT {
				if value, err := strconv.Atoi(lit.Value); err == nil {
					limit = value
				}
			}
			return true
		})
	}
	return limit, limit > 0
}

func middlewareRouteRegistrations(t *testing.T, source []byte) map[string]middlewareRouteRegistration {
	t.Helper()
	fset := token.NewFileSet()
	file, err := parser.ParseFile(fset, "middleware.go", source, 0)
	if err != nil {
		t.Fatalf("parse middleware.go: %v", err)
	}
	loginLimit, loginLimitKnown := loginRateLimitLimit(file)
	verbs := map[string]bool{"GET": true, "POST": true, "PUT": true, "PATCH": true, "DELETE": true}
	routes := map[string]middlewareRouteRegistration{}
	ast.Inspect(file, func(n ast.Node) bool {
		call, ok := n.(*ast.CallExpr)
		if !ok {
			return true
		}
		selector, ok := call.Fun.(*ast.SelectorExpr)
		if !ok || !verbs[selector.Sel.Name] || len(call.Args) < 2 {
			return true
		}
		pathLiteral, ok := call.Args[0].(*ast.BasicLit)
		if !ok || pathLiteral.Kind != token.STRING {
			return true
		}
		path, err := strconv.Unquote(pathLiteral.Value)
		if err != nil {
			return true
		}
		var registration middlewareRouteRegistration
		for _, arg := range call.Args[1:] {
			// 处理器：实参区里最后一个 h.<Name>（内联闭包里的同样计入）。
			ast.Inspect(arg, func(node ast.Node) bool {
				sel, ok := node.(*ast.SelectorExpr)
				if !ok {
					return true
				}
				if ident, ok := sel.X.(*ast.Ident); ok && ident.Name == "h" {
					registration.handler = sel.Sel.Name
				}
				return true
			})
			// 限流中间件：loginRateLimit() 或 clusterRateLimit(scope, limit, message)。
			middlewareCall, ok := arg.(*ast.CallExpr)
			if !ok {
				continue
			}
			callee, ok := middlewareCall.Fun.(*ast.Ident)
			if !ok {
				continue
			}
			switch callee.Name {
			case "loginRateLimit":
				if !loginLimitKnown {
					continue
				}
				registration.rateLimitMounted = true
				registration.rateLimitKey = "login"
				registration.rateLimitPerMin = loginLimit
			case "clusterRateLimit":
				if len(middlewareCall.Args) < 2 {
					continue
				}
				scopeLiteral, ok := middlewareCall.Args[0].(*ast.BasicLit)
				if !ok {
					continue
				}
				limitLiteral, ok := middlewareCall.Args[1].(*ast.BasicLit)
				if !ok || limitLiteral.Kind != token.INT {
					continue
				}
				scope, err := strconv.Unquote(scopeLiteral.Value)
				if err != nil {
					continue
				}
				limit, err := strconv.Atoi(limitLiteral.Value)
				if err != nil {
					continue
				}
				registration.rateLimitMounted = true
				registration.rateLimitKey = scope
				registration.rateLimitPerMin = limit
				if len(middlewareCall.Args) > 2 {
					if messageLiteral, ok := middlewareCall.Args[2].(*ast.BasicLit); ok {
						if message, err := strconv.Unquote(messageLiteral.Value); err == nil {
							registration.rateLimitMessageCN = message
						}
					}
				}
			}
		}
		routes[selector.Sel.Name+" "+path] = registration
		return true
	})
	return routes
}

func middlewareSourceForTest(t *testing.T) []byte {
	t.Helper()
	source, err := os.ReadFile("../middleware/middleware.go")
	if err != nil {
		t.Fatalf("read middleware.go: %v", err)
	}
	return source
}

// 派生扫描器的鉴别力：闭包形态（/mcp）与多行注册都必须在集合里，且处理器
// 要能穿透闭包被解析出来；旧逐行正则在这两种形态上双双失明（多行注册整个
// 跳过、闭包注册只剩前缀实参解析不到 handler），任何挂在它们上的门都会双盲。
func TestMiddlewareRouteRegistrations_includesClosureAndMultiLineForms(t *testing.T) {
	routes := middlewareRouteRegistrations(t, middlewareSourceForTest(t))
	if len(routes) < 100 {
		t.Fatalf("派生注册数=%d，扫描器疑似退化", len(routes))
	}
	if _, ok := routes["POST /mcp"]; !ok {
		t.Error("缺 POST /mcp：内联闭包注册必须被 AST 扫描器覆盖")
	}
	if registration, ok := routes["GET /auth/setup"]; !ok || registration.handler != "GetSetupStatus" {
		t.Errorf("GET /auth/setup registration=%+v, want handler GetSetupStatus", registration)
	}

	// 合成源码钉两种行级正则必然失明的形态（未来新增注册即此形态）。
	synthetic := []byte(`package middleware

func assemble(v1 *Group, h *Handlers) {
	v1.POST(
		"/multi-line",
		someGuard(),
		h.GatedHandler,
	)
	v1.POST("/closure", guard(), func(c *Context) {
		h.ClosureHandler(c)
	})
	v1.GET("/limited", clusterRateLimit("synthetic", 42, "合成限流"), h.LimitedHandler)
}
`)
	syntheticRoutes := middlewareRouteRegistrations(t, synthetic)
	if got := syntheticRoutes["POST /multi-line"].handler; got != "GatedHandler" {
		t.Errorf("多行注册 handler=%q, want GatedHandler（行级扫描器会整条跳过）", got)
	}
	if got := syntheticRoutes["POST /closure"].handler; got != "ClosureHandler" {
		t.Errorf("闭包注册 handler=%q, want ClosureHandler（行级扫描器在前缀实参处截断）", got)
	}
	limited := syntheticRoutes["GET /limited"]
	if !limited.rateLimitMounted || limited.rateLimitKey != "synthetic" || limited.rateLimitPerMin != 42 {
		t.Errorf("限流挂载解析=%+v, want synthetic/42", limited)
	}
}

// 公开端点限流是运维可见面：凡在 middleware.go 挂 loginRateLimit() /
// clusterRateLimit(...) 的路由，OpenAPI 文档必须登记 429——漏登记时按规格
// 生成的 SDK 会把限流当未知状态（登录页反复点击 SSO 即可触发）。
func TestAPIDocRoutes_rateLimitedRoutesDocument429(t *testing.T) {
	documented := make(map[string]apiDocRoute, len(apiDocRoutes))
	for _, route := range apiDocRoutes {
		documented[route.Method+" "+route.Path] = route
	}
	limited, loginBucketRouted := 0, false
	for key, registration := range middlewareRouteRegistrations(t, middlewareSourceForTest(t)) {
		if !registration.rateLimitMounted {
			continue
		}
		limited++
		if registration.rateLimitKey == "login" {
			loginBucketRouted = true
		}
		route, ok := documented[key]
		if !ok {
			t.Errorf("%s 挂了限流桶 %s（%d/min）但文档无此路由", key, registration.rateLimitKey, registration.rateLimitPerMin)
			continue
		}
		found := false
		for _, routeError := range route.Errors {
			if strings.HasPrefix(routeError, "429") {
				found = true
				break
			}
		}
		if !found {
			t.Errorf("%s 挂限流桶 %s（%d/min，%s），文档 Errors=%v 缺 429", key, registration.rateLimitKey, registration.rateLimitPerMin, registration.rateLimitMessageCN, route.Errors)
		}
	}
	if limited == 0 {
		t.Fatal("限流路由派生为空（扫描器退化 → 本用例恒绿，无鉴别力）")
	}
	if !loginBucketRouted {
		t.Fatal("未能从 middleware.go 的 loginRateLimit 派生限额（实现形态变化，扫描器需跟进）")
	}
}
