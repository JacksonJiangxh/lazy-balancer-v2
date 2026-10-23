package handlers

import (
	"go/ast"
	"go/parser"
	"go/token"
	"reflect"
	"testing"
)

// createRuleFeatures 与 updateRuleFeatures 是同一 ruleFeatureInput 的两条投影
// （创建用请求值，编辑用存量基线 + 指针覆盖）。新增规则字段时若只改一侧，
// Create 落 schema 默认、Update 沿用存量，形成「新建与编辑终态不同」的静默
// 分叉且单侧测试不会变红。本门禁解析源码，断言两侧被赋值的字段集合都等于
// ruleFeatureInput 的完整字段集合——漏一侧即红。
func TestRuleFeatureProjections_assignEveryField(t *testing.T) {
	fset := token.NewFileSet()
	file, err := parser.ParseFile(fset, "rule_features.go", nil, 0)
	if err != nil {
		t.Fatalf("parse rule_features.go: %v", err)
	}
	want := map[string]bool{}
	structType := reflect.TypeOf(ruleFeatureInput{})
	for i := range structType.NumField() {
		want[structType.Field(i).Name] = true
	}
	if len(want) == 0 {
		t.Fatal("ruleFeatureInput 无字段（门禁失效）")
	}
	for _, fnName := range []string{"createRuleFeatures", "updateRuleFeatures"} {
		assigned := assignedFeatureFields(t, file, fnName)
		for field := range want {
			if !assigned[field] {
				t.Errorf("%s 未投影字段 %s（新增字段必须两侧同步）", fnName, field)
			}
		}
		for field := range assigned {
			if !want[field] {
				t.Errorf("%s 投影了 ruleFeatureInput 不存在的字段 %s", fnName, field)
			}
		}
	}
}

// assignedFeatureFields 收集函数体内对 ruleFeatureInput 的赋值字段：
// 复合字面量键（create 的返回、update 的基线）与 `input.Field = …` 覆盖。
func assignedFeatureFields(t *testing.T, file *ast.File, fnName string) map[string]bool {
	t.Helper()
	var fn *ast.FuncDecl
	for _, decl := range file.Decls {
		declFn, ok := decl.(*ast.FuncDecl)
		if ok && declFn.Name.Name == fnName {
			fn = declFn
			break
		}
	}
	if fn == nil || fn.Body == nil {
		t.Fatalf("未找到函数 %s 的函数体", fnName)
	}
	assigned := map[string]bool{}
	ast.Inspect(fn.Body, func(node ast.Node) bool {
		switch typed := node.(type) {
		case *ast.CompositeLit:
			ident, ok := typed.Type.(*ast.Ident)
			if !ok || ident.Name != "ruleFeatureInput" {
				return true
			}
			for _, element := range typed.Elts {
				if kv, ok := element.(*ast.KeyValueExpr); ok {
					if key, ok := kv.Key.(*ast.Ident); ok {
						assigned[key.Name] = true
					}
				}
			}
		case *ast.AssignStmt:
			for _, lhs := range typed.Lhs {
				selector, ok := lhs.(*ast.SelectorExpr)
				if !ok {
					continue
				}
				if base, ok := selector.X.(*ast.Ident); ok && base.Name == "input" {
					assigned[selector.Sel.Name] = true
				}
			}
		}
		return true
	})
	if len(assigned) == 0 {
		t.Fatalf("%s 未识别到任何字段投影（门禁失效）", fnName)
	}
	return assigned
}
