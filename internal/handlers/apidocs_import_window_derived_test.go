package handlers

// 文档与写门的派生一致性（一次成形，杜绝「第 N 次扩张未跟进」）：
//   - 门集合从 handler 源码（rejectWriteDuringImport / rejectNodeWriteDuringImport
//     调用点）与 middleware 路由注册双向派生；
//   - 文档集合是 apidocs 的 importWindowGatedDocRoutes；
//   - 两侧必须相等，且 OpenAPI 输出对每个受门且已登记的端点必须含
//     409 import_in_progress。

import (
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"regexp"
	"sort"
	"strings"
	"testing"
)

func derivedImportWindowGatedRoutes(t *testing.T) map[string]string {
	t.Helper()
	gated := map[string]bool{}
	fset := token.NewFileSet()
	entries, err := os.ReadDir(".")
	if err != nil {
		t.Fatalf("read handlers dir: %v", err)
	}
	for _, entry := range entries {
		name := entry.Name()
		if entry.IsDir() || !strings.HasSuffix(name, ".go") || strings.HasSuffix(name, "_test.go") {
			continue
		}
		file, err := parser.ParseFile(fset, name, nil, 0)
		if err != nil {
			t.Fatalf("parse %s: %v", name, err)
		}
		for _, decl := range file.Decls {
			fn, ok := decl.(*ast.FuncDecl)
			if !ok || fn.Body == nil {
				continue
			}
			hit := false
			ast.Inspect(fn.Body, func(n ast.Node) bool {
				call, ok := n.(*ast.CallExpr)
				if !ok {
					return true
				}
				if id, ok := call.Fun.(*ast.Ident); ok &&
					(id.Name == "rejectWriteDuringImport" || id.Name == "rejectNodeWriteDuringImport") {
					hit = true
					return false
				}
				return true
			})
			if hit {
				gated[fn.Name.Name] = true
			}
		}
	}
	middleware, err := os.ReadFile("../middleware/middleware.go")
	if err != nil {
		t.Fatalf("read middleware.go: %v", err)
	}
	// 两个登记组（adminGroup/business）都是 v1.Group("")，故注册路径即
	// apiDocRoutes 的相对路径。
	routePattern := regexp.MustCompile(`(?m)^\s*\w+\.(GET|POST|PUT|PATCH|DELETE)\("([^"]+)",\s*h\.(\w+)\)`)
	derived := map[string]string{}
	for _, match := range routePattern.FindAllStringSubmatch(string(middleware), -1) {
		if gated[match[3]] {
			derived[match[1]+" "+match[2]] = match[3]
		}
	}
	return derived
}

func TestAPIDocsImportWindow_derivedFromHandlerGates(t *testing.T) {
	derived := derivedImportWindowGatedRoutes(t)
	missing, extra := make([]string, 0), make([]string, 0)
	for key, handler := range derived {
		if _, ok := importWindowGatedDocRoutes[key]; !ok {
			// 未登记文档的受门路由同样必须进集合：集合是派生事实，不是
			// 「只登记已写文档的部分」。
			missing = append(missing, key+" ("+handler+")")
		}
	}
	for key := range importWindowGatedDocRoutes {
		if _, ok := derived[key]; !ok {
			extra = append(extra, key)
		}
	}
	sort.Strings(missing)
	sort.Strings(extra)
	if len(missing) > 0 {
		t.Fatalf("受导入窗口写门约束但未登记的路由（新增门后请同步 importWindowGatedDocRoutes）:\n%s", strings.Join(missing, "\n"))
	}
	if len(extra) > 0 {
		t.Fatalf("登记了导入窗口写门但源码中不存在该门的调用点（死条目）:\n%s", strings.Join(extra, "\n"))
	}
	if len(derived) == 0 {
		t.Fatal("门集合派生为空（扫描器退化 → 本用例恒绿，无鉴别力）")
	}
}

// 派生注入必须在真正给客户端看的 OpenAPI 输出里生效（不是仅内存集合）：
// 取一个此前手工漏登的族（规则写端点 + 集群登记）断言 409 描述存在。
func TestOpenAPIYAML_includesDerivedImportWindowError(t *testing.T) {
	yaml := buildOpenAPIYAML()
	for _, needle := range []string{
		"/rules:",
		"/cluster/register-tokens:",
	} {
		if !strings.Contains(yaml, needle) {
			t.Fatalf("OpenAPI YAML 缺路径 %s", needle)
		}
	}
	if !strings.Contains(yaml, "import_in_progress") {
		t.Fatal("OpenAPI YAML 未包含派生注入的 409 import_in_progress")
	}
	// 逐端点定位：/rules 段内必须出现该码（否则只有别的族命中，注入范围退化）。
	rulesStart := strings.Index(yaml, "  /rules:")
	if rulesStart < 0 {
		t.Fatal("OpenAPI YAML 缺 /rules 段")
	}
	rulesEnd := len(yaml)
	if next := strings.Index(yaml[rulesStart+1:], "\n  /"); next >= 0 {
		rulesEnd = rulesStart + 1 + next
	}
	if !strings.Contains(yaml[rulesStart:rulesEnd], "import_in_progress") {
		t.Fatalf("/rules 段未登记 409 import_in_progress")
	}
}

// restore 端点的错误面：413/400 校验失败/200+partial 都必须可被按文档生成的
// 客户端识别（此前文档只列 500 import_failed，客户端遇 413/400 会走错分支）。
func TestAPIDocRoutes_restoreDocumentsPartialAndBodyLimit(t *testing.T) {
	var route *apiDocRoute
	for i := range apiDocRoutes {
		if apiDocRoutes[i].Method == "POST" && apiDocRoutes[i].Path == "/auto-backup/:id/restore" {
			route = &apiDocRoutes[i]
			break
		}
	}
	if route == nil {
		t.Fatal("文档缺 POST /auto-backup/:id/restore")
	}
	joined := strings.Join(route.Errors, " | ")
	for _, want := range []string{"400 invalid_backup", "413 body_exceeds_128MB"} {
		if !strings.Contains(joined, want) {
			t.Errorf("restore 文档缺 %s: %v", want, route.Errors)
		}
	}
	if !strings.Contains(route.Description, "partial") {
		t.Errorf("restore 描述未说明 200+partial 形态: %q", route.Description)
	}
}
