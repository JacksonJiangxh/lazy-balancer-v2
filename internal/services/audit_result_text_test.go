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

// TestAuditResultText_literalArgsCovered：审计结果码渲染
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

// 动态实参（变量/表达式）不在字面量扫描范围；新增动态入口必须同步审查
// 其取值域。这里钉住当前动态调用点数量：新增即红，强制补映射/白名单。
func TestAuditResultText_dynamicCallSitesTripwire(t *testing.T) {
	root, err := filepath.Abs(filepath.Join("..", "..", "internal"))
	if err != nil {
		t.Fatal(err)
	}
	dynamic := 0
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
			if _, ok := call.Args[0].(*ast.BasicLit); !ok {
				dynamic++
			}
			return true
		})
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	const want = 9
	if dynamic != want {
		t.Fatalf("AuditResultPart 动态调用点=%d，want %d：新增动态入口必须审查取值域并更新本绊线", dynamic, want)
	}
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

// handlers/certificates.go 的 auditFailure 是局部闭包，结果码
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

// 审计来源码渲染——

// scanAuditSourceLiterals 扫描 internal/ 非测试源码中给定函数的**字面量**首参，
// 返回 字面量 → 首处位置。
func scanAuditSourceLiterals(t *testing.T, funcs map[string]struct{}) map[string]string {
	t.Helper()
	root, err := filepath.Abs(filepath.Join("..", "..", "internal"))
	if err != nil {
		t.Fatalf("resolve internal dir: %v", err)
	}
	found := map[string]string{}
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
			if !ok || len(call.Args) == 0 {
				return true
			}
			var name string
			switch fn := call.Fun.(type) {
			case *ast.SelectorExpr:
				name = fn.Sel.Name
			case *ast.Ident:
				name = fn.Name
			}
			if _, wanted := funcs[name]; !wanted {
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
			if _, seen := found[value]; !seen {
				found[value] = fset.Position(call.Pos()).String()
			}
			return true
		})
		return nil
	})
	if err != nil {
		t.Fatalf("walk internal: %v", err)
	}
	return found
}

// hasASCIILetter 报告 s 是否含 ASCII 字母（区分「内部来源码」与「已中文化
// 字面量」——handlers 侧存在直接传中文展示串的调用点，如「保存前测试」）。
func hasASCIILetter(s string) bool {
	for i := range s {
		c := s[i]
		if (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') {
			return true
		}
	}
	return false
}

// 来源码字面量覆盖钉（与 TestAuditResultText_literalArgsCovered 对称）。
// 扫描 AuditSourcePart 的字面量实参以及两条把首参直接转发给它的链
// （recordSystemReloadAudit / txReloadDetail）——每个含 ASCII 字母的字面量必须
// 在 auditSourceTextMap 有中文映射，否则落 default 渲染英文内部标识
// （runtime_reconcile/runtime_sweep/promote_or_startup 曾如此）。
func TestAuditSourcePart_literalArgsCovered(t *testing.T) {
	found := scanAuditSourceLiterals(t, map[string]struct{}{
		"AuditSourcePart":         {},
		"recordSystemReloadAudit": {},
		"txReloadDetail":          {},
	})
	missing := make([]string, 0, len(found))
	for value, pos := range found {
		if !hasASCIILetter(value) {
			continue // 已中文化的展示串（不经码表）
		}
		if _, ok := auditSourceTextMap[value]; !ok {
			missing = append(missing, strconv.Quote(value)+" @ "+pos)
		}
	}
	if len(missing) > 0 {
		sort.Strings(missing)
		t.Fatalf("来源码缺中文映射（请在 auditSourceTextMap 补齐）:\n  %s", strings.Join(missing, "\n  "))
	}
}

// 动态实参（变量/表达式）不在字面量扫描范围——新增动态入口必须
// 同步审查取值域。这里钉住当前动态调用点数量：新增即红。
func TestAuditSourcePart_dynamicCallSitesTripwire(t *testing.T) {
	root, err := filepath.Abs(filepath.Join("..", "..", "internal"))
	if err != nil {
		t.Fatal(err)
	}
	dynamic := 0
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
			if !ok || len(call.Args) == 0 {
				return true
			}
			var name string
			switch fn := call.Fun.(type) {
			case *ast.SelectorExpr:
				name = fn.Sel.Name
			case *ast.Ident:
				name = fn.Name
			}
			if name != "AuditSourcePart" {
				return true
			}
			if _, ok := call.Args[0].(*ast.BasicLit); !ok {
				dynamic++
			}
			return true
		})
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	// 当前动态入口：recordSystemReloadAudit 内 2 处（失败/成功）、txReloadDetail
	// 1 处（handlers）、renewExpiringCertificates 的 source 变量 1 处。
	const want = 4
	if dynamic != want {
		t.Fatalf("AuditSourcePart 动态调用点=%d，want %d：新增动态入口必须审查取值域并更新本绊线", dynamic, want)
	}
}

// 内部来源码必须渲染中文（映射值不得回显内部码）。
func TestAuditSourcePart_internalCodesRenderChinese(t *testing.T) {
	want := map[string]string{
		"runtime_reconcile":  "来源：运行时对账",
		"runtime_sweep":      "来源：运行时清扫",
		"promote_or_startup": "来源：升主或启动补建",
	}
	for code, expected := range want {
		if got := AuditSourcePart(code); got != expected {
			t.Errorf("AuditSourcePart(%q)=%q, want %q", code, got, expected)
		}
	}
	for code, text := range auditSourceTextMap {
		if strings.Contains(text, code) {
			t.Errorf("映射值 %q → %q 仍含内部来源码（渲染仍中英混杂）", code, text)
		}
		if !strings.HasPrefix(text, "来源：") {
			t.Errorf("映射值 %q → %q 缺「来源：」前缀（详情段口径）", code, text)
		}
	}
	// 动态取值域（certificates.go renewExpiringCertificates / txReloadDetail /
	// recordSystemReloadAudit 调用方）必须在表内。
	for _, code := range []string{
		"renewal", "first_issuance_retry",
		"rule_create", "rule_update", "rule_delete", "rule_enable", "rule_disable",
		"certificate_issued", "crs_update", "threat_update", "ip2region_update", "autoban",
	} {
		if _, ok := auditSourceTextMap[code]; !ok {
			t.Errorf("动态来源码 %q 缺映射（落 default 渲染英文）", code)
		}
	}
	if got := AuditSourcePart("unknown_source_code"); got != "来源：unknown_source_code" {
		t.Errorf("未知来源码必须原样兜底（便于定位漏映射）, got %q", got)
	}
}
