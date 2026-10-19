package services

// A86 历史问题（历史）结构守卫：生产代码中「INSERT INTO lb_rules (」
// 手写字面量唯一豁免=config_import_v1.go（v1 遗留转换器，窄清单语义已裁定
// 维持）；其余站点必须经 LbRuleInsertSQL 单源生成——新增列漏改某一处即
// 「保存成功但与快照/副本不同形」（历史问题 缺陷形态）。

import (
	"go/ast"
	"go/parser"
	"go/token"
	"io/fs"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
)

func TestLbRuleInsertStatements_useSingleSource(t *testing.T) {
	// file → 允许的函数集（比整文件豁免更紧：事实源文件内也只允许生成器本体）。
	allowed := map[string]map[string]bool{
		"handlers/config_import_v1.go":   {"ImportV1Config": true},
		"services/rule_write_columns.go": {"LbRuleInsertSQL": true},
	}
	var violations []string
	root := filepath.Join("..")
	err := filepath.WalkDir(root, func(path string, entry fs.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		if entry.IsDir() || !strings.HasSuffix(path, ".go") || strings.HasSuffix(path, "_test.go") {
			return nil
		}
		fileSet := token.NewFileSet()
		file, parseErr := parser.ParseFile(fileSet, path, nil, 0)
		if parseErr != nil {
			return parseErr
		}
		rel, relErr := filepath.Rel(root, path)
		if relErr != nil {
			return relErr
		}
		rel = filepath.ToSlash(rel)
		for _, declaration := range file.Decls {
			function, ok := declaration.(*ast.FuncDecl)
			if !ok || function.Body == nil {
				continue
			}
			ast.Inspect(function.Body, func(node ast.Node) bool {
				literal, ok := node.(*ast.BasicLit)
				if !ok || literal.Kind != token.STRING {
					return true
				}
				query, unquoteErr := strconv.Unquote(literal.Value)
				if unquoteErr != nil || !strings.Contains(query, "INSERT INTO lb_rules (") {
					return true
				}
				if !allowed[rel][function.Name.Name] {
					position := fileSet.Position(literal.Pos())
					violations = append(violations, position.String()+" in "+function.Name.Name)
				}
				return true
			})
		}
		return nil
	})
	if err != nil {
		t.Fatalf("walk: %v", err)
	}
	if len(violations) > 0 {
		t.Fatalf("手写规则 INSERT 列清单（必须经 LbRuleInsertSQL 单源）:\n%s", strings.Join(violations, "\n"))
	}
}
