package handlers

// business 组 5xx 响应只回固定文案：底层错误（SQL 文本/表列名、文件路径与
// errno、Caddy admin 地址）只进运行日志与操作审计。4xx 配置拒绝类不受此约束
// （cli_validation_gate 等门禁依赖 400 内的 CLI/字段细节）。
// 两路钉：源码级（规则端点全部 5xx 写点不得拼接 err.Error()）+ 行为级
//（真实 DB 故障下响应体不含内部结构）。

import (
	"bytes"
	"go/ast"
	"go/parser"
	"go/printer"
	"go/token"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/gin-gonic/gin"
	"lazy-balancer-v2/internal/db"
)

func TestRuleEndpoint5xxBodiesHideInternalErrors(t *testing.T) {
	fset := token.NewFileSet()
	parsed, err := parser.ParseFile(fset, "rules.go", nil, 0)
	if err != nil {
		t.Fatalf("parse rules.go: %v", err)
	}
	for _, leak := range collect5xxErrorTextLeaks(fset, parsed) {
		t.Errorf("rules.go: 5xx 响应拼接了内部错误文本: %s", leak)
	}

	// 配置域同政策：GetConfig（business 组）与聚合预校验的通用失败分支。
	caddyFile, err := parser.ParseFile(fset, "caddy.go", nil, 0)
	if err != nil {
		t.Fatalf("parse caddy.go: %v", err)
	}
	for _, fn := range caddyFile.Decls {
		decl, ok := fn.(*ast.FuncDecl)
		if !ok || (decl.Name.Name != "GetConfig" && decl.Name.Name != "writeConfigValidationFailure") {
			continue
		}
		for _, leak := range collect5xxErrorTextLeaks(fset, decl) {
			t.Errorf("caddy.go:%s: 5xx 响应拼接了内部错误文本: %s", decl.Name.Name, leak)
		}
	}
}

// 扫描器自检：识别能力本身必须被钉住——若匹配逻辑退化为恒空，上面的门禁
// 就成了假绿。合成三类泄漏形态（c.JSON 5xx / fail 5xx / failEnable 文案）
// 必须全部被捕获。
func TestRuleEndpoint5xxLeakScannerDetectsLeaks(t *testing.T) {
	const source = `package p

func f(c *gin.Context, err error) {
	c.JSON(http.StatusInternalServerError, models.APIResponse{Code: 500, Message: "x: " + err.Error()})
	c.JSON(http.StatusBadGateway, models.APIResponse{Code: 502, Message: fmt.Sprintf("%v", err.Error())})
	fail(http.StatusInternalServerError, "y: "+err.Error())
	failEnable("z: "+err.Error(), err)
	failUpdateWithStatus("w: "+err.Error(), http.StatusInternalServerError, err)
	failCertEnqueue("v: "+err.Error(), err)
	// 4xx 配置拒绝类保留细节，不算泄漏。
	c.JSON(http.StatusBadRequest, models.APIResponse{Code: 400, Message: err.Error()})
}`
	fset := token.NewFileSet()
	parsed, err := parser.ParseFile(fset, "synthetic.go", source, 0)
	if err != nil {
		t.Fatalf("parse synthetic source: %v", err)
	}
	if leaks := collect5xxErrorTextLeaks(fset, parsed); len(leaks) != 6 {
		t.Fatalf("扫描器应捕获 6 处 5xx 泄漏，实际 %d: %v", len(leaks), leaks)
	}
}

// collect5xxErrorTextLeaks 返回 node 内全部 5xx 写点的泄漏源码快照：
//   - c.JSON(<5xx>, ...) 的响应参数；
//   - fail/failInternal/failUpdateWithStatus/failEnable/failEnableWithStatus/
//     failCertEnqueue 的文案参数（这些闭包最终写 c.JSON）。
func collect5xxErrorTextLeaks(fset *token.FileSet, node ast.Node) []string {
	leaks := make([]string, 0)
	ast.Inspect(node, func(n ast.Node) bool {
		call, ok := n.(*ast.CallExpr)
		if !ok {
			return true
		}
		var name string
		var receiver string
		switch fun := call.Fun.(type) {
		case *ast.Ident:
			name = fun.Name
		case *ast.SelectorExpr:
			name = fun.Sel.Name
			if ident, ok := fun.X.(*ast.Ident); ok {
				receiver = ident.Name
			}
		default:
			return true
		}
		switch name {
		case "JSON":
			if receiver != "c" || len(call.Args) < 2 || !isInternalStatusExpr(call.Args[0]) {
				return true
			}
			for _, arg := range call.Args[1:] {
				if mentionsErrorText(fset, arg) {
					leaks = append(leaks, printNode(fset, call))
					break
				}
			}
		case "fail":
			if len(call.Args) >= 2 && isInternalStatusExpr(call.Args[0]) && mentionsErrorText(fset, call.Args[1]) {
				leaks = append(leaks, printNode(fset, call))
			}
		case "failInternal", "failUpdateWithStatus", "failEnable", "failEnableWithStatus", "failCertEnqueue":
			if len(call.Args) > 0 && mentionsErrorText(fset, call.Args[0]) {
				leaks = append(leaks, printNode(fset, call))
			}
		}
		return true
	})
	return leaks
}

func isInternalStatusExpr(expr ast.Expr) bool {
	switch e := expr.(type) {
	case *ast.SelectorExpr:
		return e.Sel.Name == "StatusInternalServerError" || e.Sel.Name == "StatusBadGateway"
	case *ast.BasicLit:
		return e.Kind == token.INT && (e.Value == "500" || e.Value == "502")
	}
	return false
}

func mentionsErrorText(fset *token.FileSet, node ast.Node) bool {
	source := printNode(fset, node)
	return strings.Contains(source, ".Error()")
}

func printNode(fset *token.FileSet, node ast.Node) string {
	var buf bytes.Buffer
	if err := printer.Fprint(&buf, fset, node); err != nil {
		return ""
	}
	return buf.String()
}

// 行为钉：CreateRule 在写路径规则阶段遇到真实 DB 故障（表缺失）时，500 响应
// 只回固定文案——此前会带 "no such table: path_rules"（表名/列名泄露）。
func TestCreateRule_500BodyHidesSQLDetails(t *testing.T) {
	handler := newRuleFeatureTestHandlers(t)
	if _, err := db.DB.Exec(`DROP TABLE path_rules`); err != nil {
		t.Fatalf("drop path_rules: %v", err)
	}
	router := gin.New()
	router.POST("/rules", handler.CreateRule)
	request := httptest.NewRequest(http.MethodPost, "/rules", strings.NewReader(`{"name":"leak","protocol":"http","domain":"leak.example.test","listen_port":19081,"health_check_interval":10,"health_check_timeout":2,"health_check_unhealthy_threshold":3,"health_check_healthy_threshold":2,"upstreams":[{"host":"127.0.0.1","port":9000,"enabled":true}]}`))
	request.Header.Set("Content-Type", "application/json")
	response := httptest.NewRecorder()

	router.ServeHTTP(response, request)

	if response.Code != http.StatusInternalServerError {
		t.Fatalf("status=%d body=%s, want 500", response.Code, response.Body.String())
	}
	body := response.Body.String()
	for _, leak := range []string{"upstreams", "no such table", "SELECT", "sql:"} {
		if strings.Contains(body, leak) {
			t.Fatalf("500 body 泄露内部细节 %q: %s", leak, body)
		}
	}
	if !strings.Contains(body, "写入数据库失败") {
		t.Fatalf("500 body 缺少固定文案: %s", body)
	}
}

// 行为钉：GetConfig 读库失败时响应体不得带表名/SQL 细节。
func TestGetConfig_500BodyHidesSQLDetails(t *testing.T) {
	handler := newRuleFeatureTestHandlers(t)
	if _, err := db.DB.Exec(`DROP TABLE global_config`); err != nil {
		t.Fatalf("drop global_config: %v", err)
	}
	router := gin.New()
	router.GET("/config", handler.GetConfig)
	response := httptest.NewRecorder()

	router.ServeHTTP(response, httptest.NewRequest(http.MethodGet, "/config", nil))

	if response.Code != http.StatusInternalServerError {
		t.Fatalf("status=%d body=%s, want 500", response.Code, response.Body.String())
	}
	body := response.Body.String()
	for _, leak := range []string{"global_config", "no such table", "SELECT", "sql:"} {
		if strings.Contains(body, leak) {
			t.Fatalf("500 body 泄露内部细节 %q: %s", leak, body)
		}
	}
	if !strings.Contains(body, "获取全局配置失败") {
		t.Fatalf("500 body 缺少固定文案: %s", body)
	}
}
