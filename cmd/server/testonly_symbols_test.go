package main

import (
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"strings"
	"testing"
)

// TestMainPackageHasNoProductionTestOnlyEntryPoints 产品文件（非 *_test.go）
// 不得承载 test-only 入口。本包的具体形态是 runtimeLifecycle.Shutdown()：
// 固定预算的测试辅助（shutdownForTest）若回到产品符号表，会被误当生产入口
// 调用而绕过 shutdown.segment() 的预算派生——正是关停链最危险的回归面。
// 与 internal/services / internal/config 的同型守卫对齐。
func TestMainPackageHasNoProductionTestOnlyEntryPoints(t *testing.T) {
	entries, err := os.ReadDir(".")
	if err != nil {
		t.Fatal(err)
	}
	fset := token.NewFileSet()
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
			if !ok || fn.Recv == nil || fn.Name.Name != "Shutdown" {
				continue
			}
			// 只针对 runtimeLifecycle 方法（生产入口是 ShutdownWithTimeout）。
			receiver := ""
			if len(fn.Recv.List) == 1 {
				switch expr := fn.Recv.List[0].Type.(type) {
				case *ast.StarExpr:
					if ident, ok := expr.X.(*ast.Ident); ok {
						receiver = ident.Name
					}
				case *ast.Ident:
					receiver = expr.Name
				}
			}
			if receiver != "runtimeLifecycle" {
				continue
			}
			t.Errorf("%s:%d 产品文件声明 test-only 入口 runtimeLifecycle.Shutdown——请移到 *_test.go（shutdownForTest）",
				name, fset.Position(fn.Pos()).Line)
		}
	}
}
