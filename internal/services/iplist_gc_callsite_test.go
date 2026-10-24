package services

import (
	"go/ast"
	"go/parser"
	"go/token"
	"strconv"
	"testing"
)

// maybeGCStaleIPListFiles 的语义前提是「整轮渲染已 apply 成功、引用集已落齐」
// ——直调 GC 入口的用例（TestIPListGC_*）无法发现调用点被删或被挪到 apply
// 之前（提前 GC 会删掉本轮即将投影的在役名单）。本钉从 AST 校验调用点归属：
// 必须位于 applyConfigWithOptions 内、且在「Caddy config applied successfully」
// 成功日志之后。
func TestApplyConfigWithOptions_callsIPListGCOnlyAfterSuccessfulApply(t *testing.T) {
	fset := token.NewFileSet()
	file, err := parser.ParseFile(fset, "caddy.go", nil, 0)
	if err != nil {
		t.Fatalf("parse caddy.go: %v", err)
	}
	var body *ast.BlockStmt
	for _, decl := range file.Decls {
		fn, ok := decl.(*ast.FuncDecl)
		if ok && fn.Name.Name == "applyConfigWithOptions" && fn.Body != nil {
			body = fn.Body
			break
		}
	}
	if body == nil {
		t.Fatal("applyConfigWithOptions 未找到（调用点归属无从校验）")
	}
	var gcPos, successPos token.Pos
	ast.Inspect(body, func(node ast.Node) bool {
		call, ok := node.(*ast.CallExpr)
		if !ok {
			return true
		}
		name := ""
		switch fn := call.Fun.(type) {
		case *ast.Ident:
			name = fn.Name
		case *ast.SelectorExpr:
			name = fn.Sel.Name
		}
		if name == "maybeGCStaleIPListFiles" && gcPos == token.NoPos {
			gcPos = call.Pos()
		}
		if name == "Logf" && successPos == token.NoPos {
			for _, arg := range call.Args {
				lit, ok := arg.(*ast.BasicLit)
				if !ok || lit.Kind != token.STRING {
					continue
				}
				if value, _ := strconv.Unquote(lit.Value); value == "Caddy config applied successfully" {
					successPos = call.Pos()
					break
				}
			}
		}
		return true
	})
	if successPos == token.NoPos {
		t.Fatal("成功日志已迁移/删除（apply 成功点无法定位）——GC 前置条件无从推导，请同步本测试")
	}
	if gcPos == token.NoPos {
		t.Fatal("applyConfigWithOptions 未调用 maybeGCStaleIPListFiles：孤儿投影永不回收（磁盘/stat 放大）")
	}
	if gcPos < successPos {
		t.Fatalf("GC 调用(%d)早于 apply 成功日志(%d)——提前 GC 会删除本轮即将投影的在役名单", gcPos, successPos)
	}
}
