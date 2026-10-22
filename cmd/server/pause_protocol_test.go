package main

import (
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
)

// 三方 pause 路径必须同值：main / handlers / entrypoint shell。
func TestCaddyPausePathMatchesEntrypoint(t *testing.T) {
	body, err := os.ReadFile(filepath.Join("..", "..", "docker-entrypoint.sh"))
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(body), "CADDY_PAUSE_FILE="+caddyPauseFilePath) {
		t.Fatalf("entrypoint CADDY_PAUSE_FILE 与 main caddyPauseFilePath 不一致: %s", caddyPauseFilePath)
	}
}

// 测试注释声明「main / handlers / entrypoint 三方同值」，但此前只
// 校验两方——internal/handlers/caddy.go 的 caddyPauseFile 单侧漂移不会被
// 拦截（该不变量已发生过路径同步事故）。此处用 AST 读取 handlers 包常量值，
// 保持第三方机械校验（handlers 不得反向依赖 main，故不能共享常量）。
func TestCaddyPausePathMatchesHandlers(t *testing.T) {
	path := filepath.Join("..", "..", "internal", "handlers", "caddy.go")
	parsed, err := parser.ParseFile(token.NewFileSet(), path, nil, 0)
	if err != nil {
		t.Fatalf("parse %s: %v", path, err)
	}
	got := ""
	found := false
	ast.Inspect(parsed, func(node ast.Node) bool {
		decl, ok := node.(*ast.GenDecl)
		if !ok || decl.Tok != token.VAR {
			return true
		}
		for _, spec := range decl.Specs {
			valueSpec, ok := spec.(*ast.ValueSpec)
			if !ok {
				continue
			}
			for index, name := range valueSpec.Names {
				if name.Name != "caddyPauseFile" || index >= len(valueSpec.Values) {
					continue
				}
				literal, ok := valueSpec.Values[index].(*ast.BasicLit)
				if !ok || literal.Kind != token.STRING {
					continue
				}
				value, err := strconv.Unquote(literal.Value)
				if err != nil {
					t.Fatalf("unquote caddyPauseFile: %v", err)
				}
				got = value
				found = true
			}
		}
		return true
	})
	if !found {
		t.Fatalf("internal/handlers/caddy.go 未找到字符串常量 caddyPauseFile")
	}
	if got != caddyPauseFilePath {
		t.Fatalf("handlers caddyPauseFile=%q 与 main caddyPauseFilePath=%q 不一致", got, caddyPauseFilePath)
	}
}
