package handlers

import (
	"bytes"
	"go/ast"
	"go/parser"
	"go/printer"
	"go/token"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"

	"github.com/gin-gonic/gin"

	"lazy-balancer-v2/internal/db"
	"lazy-balancer-v2/internal/services"
)

// 规则五端点（创建/更新/删除/启用/禁用）的 Commit 失败分支必须同口径：
// 统一走已提交视图恢复 + 失败审计（Explicit 审计策略下中间件不兜底）。
// 结构钉防「新增/改写端点时漏一处审计」——按 AST 定位每个函数内
// `tx.Commit(); err != nil` 分支，逐分支断言审计与「结果不确定」单源。
func TestRuleEndpoints_commitFailureBranchesRecordAudit(t *testing.T) {
	verbs := map[string]string{
		"CreateRule":  "创建失败",
		"UpdateRule":  "更新失败",
		"DeleteRule":  "删除失败",
		"EnableRule":  "启用失败",
		"DisableRule": "禁用失败",
	}
	source, err := os.ReadFile("rules.go")
	if err != nil {
		t.Fatalf("read rules.go: %v", err)
	}
	fset := token.NewFileSet()
	file, err := parser.ParseFile(fset, "rules.go", source, 0)
	if err != nil {
		t.Fatalf("parse rules.go: %v", err)
	}
	for funcName, verb := range verbs {
		fn := findFuncDecl(file, funcName)
		if fn == nil {
			t.Fatalf("rules.go 缺少函数 %s", funcName)
		}
		branches := txCommitFailureBranches(fn)
		if len(branches) != 1 {
			t.Fatalf("%s 的 tx.Commit 失败分支=%d, want 1", funcName, len(branches))
		}
		branch := branches[0]
		// 审计调用按 AST 实参归属断言：子串匹配会被注释里的同名片段或别处的
		// 同名字面量满足（漏一处审计照样绿），实参位置则必须真的出现在这次
		// recordAudit 调用里。
		audits := branchCalls(branch, "recordAudit")
		if len(audits) != 1 {
			t.Fatalf("%s 的提交失败分支 recordAudit 调用=%d, want 1（Explicit 策略下该场景将零审计）", funcName, len(audits))
		}
		if got := len(audits[0].Args); got != 4 {
			t.Fatalf("%s recordAudit 实参=%d, want 4（c/动词/资源/详情）:\n%s", funcName, got, exprText(fset, audits[0]))
		}
		if got := literalString(audits[0].Args[1]); got != verb {
			t.Fatalf("%s recordAudit 动作实参=%q, want %q", funcName, got, verb)
		}
		if got := literalString(audits[0].Args[2]); got != "负载规则" {
			t.Fatalf("%s recordAudit 资源实参=%q, want 负载规则", funcName, got)
		}
		// 详情必须点明「提交结果不确定」，否则事后判读会把已提交与未提交混为一谈。
		// 两种写法都合法：直接引用单源标签，或经本分支局部变量中转（DeleteRule
		// 收敛为 detail := 前缀 + 恢复失败补充）。
		if detail := exprText(fset, audits[0].Args[3]); !detailMentionsCommitUncertain(fset, branch, detail) {
			t.Fatalf("%s 审计详情既未引用 commitUncertainLabel，也未引用由其派生的局部变量:\n%s", funcName, detail)
		}

		logs := branchCalls(branch, "Logf")
		if len(logs) == 0 {
			t.Fatalf("%s 的提交失败分支缺少服务端日志", funcName)
		}
		// 日志级别与格式串都是实参：改级别、改成空格式都要被判红。
		for _, call := range logs {
			if len(call.Args) < 2 {
				t.Fatalf("%s 的 Logf 实参不足:\n%s", funcName, exprText(fset, call))
			}
			switch level := literalString(call.Args[0]); level {
			case "error", "warn", "info":
			default:
				t.Fatalf("%s 的 Logf 级别=%q, want error/warn/info", funcName, level)
			}
			if format := literalString(call.Args[1]); !strings.Contains(format, "commit") && !strings.Contains(format, "恢复") {
				t.Fatalf("%s 的 Logf 格式串=%q 未点明提交/恢复失败", funcName, format)
			}
		}
	}
}

// CreateRule 的提交失败分支不得无条件删除证书文件：Commit 返回错误无法区分
// 「未提交」与「已提交但确认丢失」，只有按已提交视图的存在性判定才安全。
func TestCreateRule_commitFailureCertCleanupIsConditional(t *testing.T) {
	source, err := os.ReadFile("rules.go")
	if err != nil {
		t.Fatalf("read rules.go: %v", err)
	}
	fset := token.NewFileSet()
	file, err := parser.ParseFile(fset, "rules.go", source, 0)
	if err != nil {
		t.Fatalf("parse rules.go: %v", err)
	}
	fn := findFuncDecl(file, "CreateRule")
	if fn == nil {
		t.Fatal("rules.go 缺少 CreateRule")
	}
	branches := txCommitFailureBranches(fn)
	if len(branches) != 1 {
		t.Fatalf("CreateRule 的 tx.Commit 失败分支=%d, want 1", len(branches))
	}
	// 按 AST 调用归属断言：`services.RemoveCertFiles` 只出现在注释或字符串里也
	// 必须判红/绿分明——这里看的是真实调用表达式。
	cleanups := branchCalls(branches[0], "cleanupUncommittedRuleCertsAfterCommitFailure")
	if len(cleanups) != 1 {
		t.Fatalf("CreateRule 提交失败分支必须恰有一次存在性判定的证书清理调用, got %d:\n%s", len(cleanups), exprText(fset, branches[0]))
	}
	if got := len(cleanups[0].Args); got != 1 {
		t.Fatalf("证书清理调用实参=%d, want 1（caddyID）", got)
	}
	if len(branchCalls(branches[0], "RemoveCertFiles")) != 0 {
		t.Fatalf("CreateRule 提交失败分支不得无条件删除证书文件:\n%s", exprText(fset, branches[0]))
	}
}

// cleanupUncommittedRuleCertsAfterCommitFailure 的行为：已提交视图仍引用该
// 规则时保留证书文件（否则删除即切断运行中规则的证书），规则不存在时才清理。
func TestCleanupUncommittedRuleCertsAfterCommitFailure(t *testing.T) {
	initializeRuleFeatureTestDB(t)
	t.Cleanup(services.SetCertDirForTest(t.TempDir()))
	const caddyID = "lb_commit_uncertain_cert"
	seedStoredHTTPRule(t, caddyID, "commit-uncertain-cert", "uncertain.example.test", 18090, false)

	certPath, keyPath := services.CertFilePaths(caddyID)
	for _, path := range []string{certPath, keyPath} {
		if err := os.WriteFile(path, []byte("PEM"), 0600); err != nil {
			t.Fatalf("seed cert file %s: %v", path, err)
		}
	}

	// 已提交视图引用该规则（提交实际生效的形态）→ 文件必须保留。
	if err := cleanupUncommittedRuleCertsAfterCommitFailure(caddyID); err != nil {
		t.Fatalf("cleanup with committed rule: %v", err)
	}
	for _, path := range []string{certPath, keyPath} {
		if _, statErr := os.Stat(path); statErr != nil {
			t.Fatalf("已提交规则 %s 的证书文件被删除: %v", filepath.Base(path), statErr)
		}
	}

	// 规则确实不存在（未提交形态）→ 清理孤儿文件。
	if _, err := db.DB.Exec("DELETE FROM lb_rules WHERE caddy_id = ?", caddyID); err != nil {
		t.Fatalf("delete rule: %v", err)
	}
	if err := cleanupUncommittedRuleCertsAfterCommitFailure(caddyID); err != nil {
		t.Fatalf("cleanup with missing rule: %v", err)
	}
	for _, path := range []string{certPath, keyPath} {
		if _, statErr := os.Stat(path); !os.IsNotExist(statErr) {
			t.Fatalf("未提交规则的证书文件未被清理: %s stat=%v", filepath.Base(path), statErr)
		}
	}
}

// EnableRule 提交失败必须在操作审计留下「启用失败」行（Explicit 策略下无中间件
// 兜底），且事务回滚后规则仍为禁用态。
func TestEnableRule_commitFailureRecordsAudit(t *testing.T) {
	handler := newRuleFeatureTestHandlers(t)
	const caddyID = "lb_enable_commit_fail"
	seedStoredHTTPRule(t, caddyID, "enable-commit-fail", "enable-fail.example.test", 18091, false)
	// 延迟约束在 COMMIT 阶段才失败（模拟 IO/确认丢失型提交错误）。
	if _, err := db.DB.Exec(`PRAGMA foreign_keys=ON;
		CREATE TABLE commit_parent(id INTEGER PRIMARY KEY);
		CREATE TABLE commit_guard(parent_id INTEGER, FOREIGN KEY(parent_id) REFERENCES commit_parent(id) DEFERRABLE INITIALLY DEFERRED);
		CREATE TRIGGER fail_rule_commit AFTER UPDATE ON lb_rules BEGIN INSERT INTO commit_guard(parent_id) VALUES (999); END`); err != nil {
		t.Fatalf("install deferred commit failure: %v", err)
	}
	gin.SetMode(gin.TestMode)
	router := gin.New()
	router.POST("/rules/:caddy_id/enable", handler.EnableRule)

	response := httptest.NewRecorder()
	router.ServeHTTP(response, httptest.NewRequest(http.MethodPost, "/rules/"+caddyID+"/enable", nil))

	if response.Code != http.StatusInternalServerError {
		t.Fatalf("status=%d body=%s, want 500", response.Code, response.Body.String())
	}
	if !strings.Contains(response.Body.String(), "提交结果不确定") {
		t.Fatalf("响应必须表述提交结果不确定: %s", response.Body.String())
	}
	var enabled int
	if err := db.DB.QueryRow("SELECT COALESCE(enabled,0) FROM lb_rules WHERE caddy_id = ?", caddyID).Scan(&enabled); err != nil {
		t.Fatalf("read rule state: %v", err)
	}
	if enabled != 0 {
		t.Fatalf("提交失败后规则 enabled=%d, want 回滚为 0", enabled)
	}
	var detail string
	if err := db.AuditDB.QueryRow(`SELECT detail FROM audit_log WHERE action='启用失败' ORDER BY id DESC LIMIT 1`).Scan(&detail); err != nil {
		t.Fatalf("读取启用失败审计: %v", err)
	}
	if !strings.Contains(detail, "提交结果不确定") || !strings.Contains(detail, caddyID) {
		t.Fatalf("启用失败审计 detail=%q, want 含规则 %s 与提交结果不确定口径", detail, caddyID)
	}
}

// findFuncDecl 在解析后的文件里按名称查找函数声明。
func findFuncDecl(file *ast.File, name string) *ast.FuncDecl {
	for _, decl := range file.Decls {
		fn, ok := decl.(*ast.FuncDecl)
		if ok && fn.Name.Name == name {
			return fn
		}
	}
	return nil
}

// txCommitFailureBranches 返回函数体内全部 `tx.Commit(); err != nil` 分支体
// （AST 块，按出现顺序）——实参归属断言直接读节点，不经过源码文本。
func txCommitFailureBranches(fn *ast.FuncDecl) []*ast.BlockStmt {
	var branches []*ast.BlockStmt
	if fn.Body == nil {
		return branches
	}
	ast.Inspect(fn.Body, func(node ast.Node) bool {
		ifStmt, ok := node.(*ast.IfStmt)
		if !ok || !isTxCommitFailureIf(ifStmt) {
			return true
		}
		branches = append(branches, ifStmt.Body)
		return true
	})
	return branches
}

// branchCalls 返回函数体/语句块内对 name 的全部调用（`f(...)` 与 `pkg.f(...)`
// 同计）。断言只看真实调用表达式：注释、字符串里的同名片段不构成调用。
func branchCalls(node ast.Node, name string) []*ast.CallExpr {
	var calls []*ast.CallExpr
	ast.Inspect(node, func(candidate ast.Node) bool {
		call, ok := candidate.(*ast.CallExpr)
		if !ok {
			return true
		}
		switch fun := call.Fun.(type) {
		case *ast.Ident:
			if fun.Name == name {
				calls = append(calls, call)
			}
		case *ast.SelectorExpr:
			if fun.Sel.Name == name {
				calls = append(calls, call)
			}
		}
		return true
	})
	return calls
}

// detailMentionsCommitUncertain 报告审计详情是否直接或经本分支局部变量间接
// 引用「提交结果不确定」单源标签。值流不做完整分析：只认 `x := …commitUncertainLabel…`
// 形式的单赋值中转（DeleteRule 的 detail := 前缀 + 恢复失败补充即此形态）。
func detailMentionsCommitUncertain(fset *token.FileSet, branch *ast.BlockStmt, detail string) bool {
	if strings.Contains(detail, "commitUncertainLabel") {
		return true
	}
	found := false
	ast.Inspect(branch, func(node ast.Node) bool {
		assign, ok := node.(*ast.AssignStmt)
		if !ok || len(assign.Lhs) != 1 || len(assign.Rhs) != 1 {
			return true
		}
		source := exprText(fset, assign.Rhs[0])
		if !strings.Contains(source, "commitUncertainLabel") {
			return true
		}
		if ident, ok := assign.Lhs[0].(*ast.Ident); ok && strings.Contains(detail, ident.Name) {
			found = true
		}
		return true
	})
	return found
}

// exprText 打印节点源码（错误信息用）。
func exprText(fset *token.FileSet, node ast.Node) string {
	var buf bytes.Buffer
	if err := printer.Fprint(&buf, fset, node); err != nil {
		return "<print error>"
	}
	return buf.String()
}

// literalString 返回字符串字面量实参的解码值；非字面量（变量/常量/表达式）
// 返回空串——调用方据此判红，避免「实参是变量」被当成命中。
func literalString(expr ast.Expr) string {
	lit, ok := expr.(*ast.BasicLit)
	if !ok || lit.Kind != token.STRING {
		return ""
	}
	value, err := strconv.Unquote(lit.Value)
	if err != nil {
		return ""
	}
	return value
}

// isTxCommitFailureIf 报告 if 语句是否为 `tx.Commit()` 失败分支。两种等价形态：
// `if err := tx.Commit(); err != nil { … }`（规则端点现行写法）与
// `if tx.Commit() != nil { … }`。
func isTxCommitFailureIf(ifStmt *ast.IfStmt) bool {
	if assign, ok := ifStmt.Init.(*ast.AssignStmt); ok && len(assign.Rhs) == 1 && isTxCommitCall(assign.Rhs[0]) {
		binaryExpr, ok := ifStmt.Cond.(*ast.BinaryExpr)
		return ok && binaryExpr.Op == token.NEQ && isNilIdent(binaryExpr.Y)
	}
	binaryExpr, ok := ifStmt.Cond.(*ast.BinaryExpr)
	return ok && binaryExpr.Op == token.NEQ && isNilIdent(binaryExpr.Y) && isTxCommitCall(binaryExpr.X)
}

// isTxCommitCall 报告表达式是否为事务提交调用：`tx.Commit()` 或测试缝单源
// `commitTx(tx)`（提交入口收敛后两者语义相同；分支断言不得因换入口而失效）。
func isTxCommitCall(expr ast.Expr) bool {
	call, ok := expr.(*ast.CallExpr)
	if !ok {
		return false
	}
	if ident, ok := call.Fun.(*ast.Ident); ok {
		if ident.Name != "commitTx" || len(call.Args) != 1 {
			return false
		}
		arg, ok := call.Args[0].(*ast.Ident)
		return ok && arg.Name == "tx"
	}
	selector, ok := call.Fun.(*ast.SelectorExpr)
	if !ok || selector.Sel.Name != "Commit" {
		return false
	}
	recv, ok := selector.X.(*ast.Ident)
	return ok && recv.Name == "tx"
}

// isNilIdent 报告表达式是否为 nil 标识符。
func isNilIdent(expr ast.Expr) bool {
	ident, ok := expr.(*ast.Ident)
	return ok && ident.Name == "nil"
}
