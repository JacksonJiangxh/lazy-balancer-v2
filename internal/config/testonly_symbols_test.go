package config

import (
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"strings"
	"testing"
)

// TestConfigPackageHasNoProductionTestOnlyEntryPoints 产品文件（非 *_test.go）
// 不得承载 test-only 入口：这些函数只被测试消费，宿主应是同包测试文件。
// 留在产品文件里会让「生产调用面」判断失真——双入口分叉后，改动只覆盖被测的
// 那条（例如告警出口：生产延迟重放 vs 测试直打 stderr），排障信号静默分家。
// 与 internal/services/testonly_symbols_test.go 同型；本表登记已迁移的入口，
// 搬回产品文件即报错。
func TestConfigPackageHasNoProductionTestOnlyEntryPoints(t *testing.T) {
	testOnly := map[string]bool{
		// 生产唯一加载入口 = LoadCollectWarnings（告警收集后由调用方重放）。
		"Load": true,
		// 生产经 loadOrCreateJWTSecretWith（走 load() 的告警出口）；直调包装
		// 已移至 config_test.go 的 loadOrCreateJWTSecretForTest。
		"loadOrCreateJWTSecret": true,
	}
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
			if !ok || !testOnly[fn.Name.Name] {
				continue
			}
			t.Errorf("%s:%d 产品文件声明 test-only 入口 %s——请移到 *_test.go（同包测试可访问未导出符号）",
				name, fset.Position(fn.Pos()).Line, fn.Name.Name)
		}
	}
}
