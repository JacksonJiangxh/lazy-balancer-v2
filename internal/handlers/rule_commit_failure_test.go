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
		branches := txCommitFailureBranches(fset, fn)
		if len(branches) != 1 {
			t.Fatalf("%s 的 tx.Commit 失败分支=%d, want 1", funcName, len(branches))
		}
		branch := branches[0]
		for _, want := range []string{"recordAudit(c,", `"` + verb + `"`, `"负载规则"`, "commitUncertainLabel"} {
			if !strings.Contains(branch, want) {
				t.Fatalf("%s 的提交失败分支缺少 %q（Explicit 策略下该场景将零审计）:\n%s", funcName, want, branch)
			}
		}
		if !strings.Contains(branch, "services.Logf(") {
			t.Fatalf("%s 的提交失败分支缺少服务端日志:\n%s", funcName, branch)
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
	branches := txCommitFailureBranches(fset, fn)
	if len(branches) != 1 {
		t.Fatalf("CreateRule 的 tx.Commit 失败分支=%d, want 1", len(branches))
	}
	if !strings.Contains(branches[0], "cleanupUncommittedRuleCertsAfterCommitFailure") {
		t.Fatalf("CreateRule 提交失败分支必须经存在性判定清理证书:\n%s", branches[0])
	}
	if strings.Contains(branches[0], "services.RemoveCertFiles") {
		t.Fatalf("CreateRule 提交失败分支不得无条件删除证书文件:\n%s", branches[0])
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
// 的源码文本（按出现顺序）。
func txCommitFailureBranches(fset *token.FileSet, fn *ast.FuncDecl) []string {
	var branches []string
	if fn.Body == nil {
		return branches
	}
	ast.Inspect(fn.Body, func(node ast.Node) bool {
		ifStmt, ok := node.(*ast.IfStmt)
		if !ok || !isTxCommitFailureIf(ifStmt) {
			return true
		}
		var buf bytes.Buffer
		if err := printer.Fprint(&buf, fset, ifStmt.Body); err != nil {
			return true
		}
		branches = append(branches, buf.String())
		return true
	})
	return branches
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
