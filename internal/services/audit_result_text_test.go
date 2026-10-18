package services

import (
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"testing"
)

// TestAuditResultText_literalArgsCovered（SVC-F1，历史）：审计结果码渲染
// 硬卡控。扫描 internal/ 全部非测试源码中 AuditResultPart 调用的**字面量**实参，
// 断言每个结果码都在 auditResultTextMap 有中文映射——否则失败详情渲染
// 「结果：<英文码>」，与中文口径分裂（"failure"/"storage_corrupted" 曾如此）。
// 新增结果码漏映射时此测试直接红；映射成为唯一事实源（switch → map 收敛）。
// 动态传参（变量/表达式）不在本钉范围——其取值集由各调用点自身约束。
func TestAuditResultText_literalArgsCovered(t *testing.T) {
	root, err := filepath.Abs(filepath.Join("..", "..", "internal"))
	if err != nil {
		t.Fatalf("resolve internal dir: %v", err)
	}
	missing := map[string]string{} // 结果码 → 首处证据位置
	err = filepath.Walk(root, func(path string, info os.FileInfo, walkErr error) error {
		if walkErr != nil || info.IsDir() || !strings.HasSuffix(path, ".go") || strings.HasSuffix(path, "_test.go") {
			return nil
		}
		fset := token.NewFileSet()
		f, perr := parser.ParseFile(fset, path, nil, 0)
		if perr != nil {
			t.Errorf("parse %s: %v", path, perr)
			return nil
		}
		ast.Inspect(f, func(n ast.Node) bool {
			call, ok := n.(*ast.CallExpr)
			if !ok {
				return true
			}
			var name string
			switch fn := call.Fun.(type) {
			case *ast.SelectorExpr:
				name = fn.Sel.Name
			case *ast.Ident:
				name = fn.Name
			}
			if name != "AuditResultPart" || len(call.Args) == 0 {
				return true
			}
			lit, ok := call.Args[0].(*ast.BasicLit)
			if !ok || lit.Kind != token.STRING {
				return true
			}
			value, uerr := strconv.Unquote(lit.Value)
			if uerr != nil {
				return true
			}
			if _, mapped := auditResultTextMap[value]; !mapped {
				if _, seen := missing[value]; !seen {
					missing[value] = fset.Position(call.Pos()).String()
				}
			}
			return true
		})
		return nil
	})
	if err != nil {
		t.Fatalf("walk internal: %v", err)
	}
	if len(missing) == 0 {
		return
	}
	codes := make([]string, 0, len(missing))
	for code := range missing {
		codes = append(codes, code)
	}
	sort.Strings(codes)
	var b strings.Builder
	for _, code := range codes {
		b.WriteString("  ")
		b.WriteString(strconv.Quote(code))
		b.WriteString(" @ ")
		b.WriteString(missing[code])
		b.WriteString("\n")
	}
	t.Fatalf("AuditResultPart 字面量结果码缺中文映射（请在 auditResultTextMap 补齐）:\n%s", b.String())
}

func TestAuditResultText_ticketFailureCodes(t *testing.T) {
	for _, code := range []string{"invalid_ticket", "invalid_signature", "expired", "replay", "user_unavailable", "database_error"} {
		if got := AuditResultText(code); got == code || got == "" {
			t.Fatalf("ticket failure code %q must have a Chinese audit rendering, got %q", code, got)
		}
	}
	if got := AuditResultText("unknown_ticket_reason"); got != "unknown_ticket_reason" {
		t.Fatalf("unknown codes must pass through unchanged, got %q", got)
	}
}

// 历史问题（历史）：handlers/certificates.go 的 auditFailure 是局部闭包，结果码
// 以动态实参进入 AuditResultPart——字面量扫描钉测（literalArgsCovered）天然
// 覆盖不到，"blocked" 由此长期缺映射（审计详情渲染英文码）。本用例钉住该
// 动态入口的取值集在映射内。
func TestAuditResultText_dynamicClosureCodes(t *testing.T) {
	// 动态传入 AuditResultPart 的结果码集合（证书 blocked 路径 + CA 测试 +
	// 用户状态 + 登录票据 reason 的取值域）。
	for _, code := range []string{"blocked", "provider_error", "not_found", "missing_acme_email", "invalid_config", "register_failed", "enabled", "disabled"} {
		if got := AuditResultText(code); got == code {
			t.Fatalf("动态结果码 %q 缺中文映射（渲染会落英文）", code)
		}
	}
	if got := AuditResultText("blocked"); got != "重试被阻止" {
		t.Fatalf("blocked 渲染=%q，want 重试被阻止", got)
	}
}
