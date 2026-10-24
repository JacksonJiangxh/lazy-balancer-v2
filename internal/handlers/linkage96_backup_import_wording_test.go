package handlers

// 导入面文案/口径的四处收敛：
//   - 部分成功响应的阶段描述只出现一次（此前 message/warnings 各拼一次协调器
//     自带的「导入部分失败（…）：」前缀）；
//   - CA 提供商悬挂文案只有一处字面量（单源函数），响应侧不得再手写；
//   - 导入后置归一的「manual 不保留 ACME 引用」与启动迁移/传输归一同一读取口径
//     （COALESCE(tls_source,'manual')），NULL 行不得被漏清。

import (
	"context"
	"errors"
	"go/ast"
	"go/parser"
	"go/token"
	"path/filepath"
	"strconv"
	"strings"
	"testing"

	"lazy-balancer-v2/internal/db"
)

// 部分成功：协调器 Error() 自带动作+阶段前缀，正文必须只取真实原因。
func TestImportPartialSuccess_messageKeepsPhaseOnce(t *testing.T) {
	queueErr := &importCoordinatorError{
		phase:  importPhaseQueue,
		err:    errors.New("query non-terminal certificate jobs: database is locked"),
		action: "导入",
	}
	message := importPartialSuccessMessage("导入", queueErr)
	if got := strings.Count(message, "证书任务恢复失败"); got != 1 {
		t.Fatalf("message 中阶段描述出现 %d 次, want 1: %s", got, message)
	}
	if strings.Contains(message, "导入部分失败") {
		t.Fatalf("message 残留协调器动作前缀（双前缀）: %s", message)
	}
	if !strings.Contains(message, "database is locked") {
		t.Fatalf("message 丢失真实原因: %s", message)
	}
	warning := importPartialSuccessWarning(queueErr)
	if got := strings.Count(warning, "证书任务恢复失败"); got != 1 {
		t.Fatalf("warning 中阶段描述出现 %d 次, want 1: %s", got, warning)
	}
	if !strings.Contains(warning, "database is locked") {
		t.Fatalf("warning 丢失真实原因: %s", warning)
	}
}

// 证书任务 CA 提供商悬挂文案单源：两档字面量只允许出现在
// certJobProviderDanglingWarnings 内（响应/审计/预览都必须调它）。
func TestCertJobProviderDangling_wordingHasSingleSource(t *testing.T) {
	const (
		disabledFragment = "个证书任务的 CA 提供商已禁用"
		missingFragment  = "个证书任务引用的 CA 提供商已不存在"
	)
	// 扫描面=整个 handlers 包的非测试源文件（含 package 级 var/const）：
	// 只解析 config_backup.go 的函数体时，文案被搬到预览/审计写点或抽成
	// 包级常量都会漏扫（漂移无网）。
	paths, err := filepath.Glob("*.go")
	if err != nil {
		t.Fatal(err)
	}
	fset := token.NewFileSet()
	singleSourceHits := 0
	var offenders []string
	scannedFiles := 0
	isFragment := func(value string) bool {
		return strings.Contains(value, disabledFragment) || strings.Contains(value, missingFragment)
	}
	inspectLiterals := func(label string, node ast.Node) {
		ast.Inspect(node, func(n ast.Node) bool {
			lit, ok := n.(*ast.BasicLit)
			if !ok || lit.Kind != token.STRING {
				return true
			}
			value, unquoteErr := strconv.Unquote(lit.Value)
			if unquoteErr != nil {
				value = strings.Trim(lit.Value, `"`)
			}
			if isFragment(value) {
				offenders = append(offenders, label+"："+value)
			}
			return true
		})
	}
	for _, path := range paths {
		if strings.HasSuffix(path, "_test.go") {
			continue
		}
		file, err := parser.ParseFile(fset, path, nil, 0)
		if err != nil {
			t.Fatalf("parse %s: %v", path, err)
		}
		scannedFiles++
		for _, decl := range file.Decls {
			switch d := decl.(type) {
			case *ast.FuncDecl:
				if d.Body == nil {
					continue
				}
				if d.Name.Name == "certJobProviderDanglingWarnings" {
					// 正向控制：单源函数体内必须真的含两档文案，否则扫描面
					// 命中数为零时负向断言（offenders 空）无意义。
					ast.Inspect(d.Body, func(n ast.Node) bool {
						lit, ok := n.(*ast.BasicLit)
						if !ok || lit.Kind != token.STRING {
							return true
						}
						value, _ := strconv.Unquote(lit.Value)
						if isFragment(value) {
							singleSourceHits++
						}
						return true
					})
					continue
				}
				inspectLiterals(path+" "+d.Name.Name, d.Body)
			case *ast.GenDecl:
				inspectLiterals(path+" "+d.Tok.String(), d)
			}
		}
	}
	if scannedFiles == 0 {
		t.Fatal("扫描面为空（handlers 包源文件未读到）")
	}
	if singleSourceHits < 2 {
		t.Fatalf("单源函数 certJobProviderDanglingWarnings 仅命中 %d 条文案（want ≥2，两档各一条）——判据或函数边界失效", singleSourceHits)
	}
	if len(offenders) > 0 {
		t.Fatalf("悬挂文案在单源函数外重复出现（改措辞会漂移）:\n%s", strings.Join(offenders, "\n"))
	}
}

// 导入后置归一：tls_source 为 NULL 的 manual 行必须与启动迁移/传输归一同样
// 清掉死引用（acme_config_id）；acme_dns 行的引用保持不变。
func TestNormalizeRuleRowsForTransport_manualSourceNullClearsACMEReference(t *testing.T) {
	newBackupTestHandlers(t)
	if _, err := db.DB.Exec(`INSERT INTO ca_providers (id,name,provider,directory_url,credentials,enabled)
		VALUES (7,'p7','letsencrypt','https://acme.example/dir','{}',1)`); err != nil {
		t.Fatalf("seed ca provider: %v", err)
	}
	if _, err := db.DB.Exec(`INSERT INTO lb_rules (caddy_id,name,protocol,domain,listen_port,enabled,enable_tls,tls_source,acme_config_id)
		VALUES ('lb_null_manual','null-manual','http','null-manual.example.test',8443,1,1,'manual',7),
		       ('lb_acme_ref','acme-ref','http','acme-ref.example.test',8444,1,1,'acme_dns',7),
		       ('lb_empty_source','empty-source','http','empty-source.example.test',8445,1,1,'',7)`); err != nil {
		t.Fatalf("seed rules: %v", err)
	}
	// 带外/旧备份形态：tls_source 为 NULL 且带 acme 引用。
	if _, err := db.DB.Exec(`UPDATE lb_rules SET tls_source=NULL WHERE caddy_id='lb_null_manual'`); err != nil {
		t.Fatalf("null tls_source: %v", err)
	}
	tx, err := db.DB.Begin()
	if err != nil {
		t.Fatalf("begin: %v", err)
	}
	defer func() { _ = tx.Rollback() }()
	if _, err := normalizeRuleRowsForTransport(context.Background(), tx); err != nil {
		t.Fatalf("normalize rule rows: %v", err)
	}
	if err := tx.Commit(); err != nil {
		t.Fatalf("commit: %v", err)
	}
	readRef := func(caddyID string) int64 {
		t.Helper()
		var ref int64
		if err := db.DB.QueryRow(`SELECT COALESCE(acme_config_id,0) FROM lb_rules WHERE caddy_id=?`, caddyID).Scan(&ref); err != nil {
			t.Fatalf("read acme_config_id for %s: %v", caddyID, err)
		}
		return ref
	}
	if ref := readRef("lb_null_manual"); ref != 0 {
		t.Fatalf("tls_source=NULL 的 manual 行 acme_config_id=%d, want 0（与启动迁移同口径清零）", ref)
	}
	// 正向对照（有意设计，不是遗漏）：tls_source='' 在四个面（写侧读列、值域门、
	// 启动迁移、传输归一）都按空值处理而不等同 manual——COALESCE 只替换 NULL，
	// 故该形态的引用四面一致地保留。
	if ref := readRef("lb_empty_source"); ref != 7 {
		t.Fatalf("tls_source='' 行 acme_config_id=%d, want 7（四面一致：空值不等同 manual）", ref)
	}
	if ref := readRef("lb_acme_ref"); ref != 7 {
		t.Fatalf("acme_dns 行的 acme_config_id=%d, want 7（正向对照：引用必须保留）", ref)
	}
}
