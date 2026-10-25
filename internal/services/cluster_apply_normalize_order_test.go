package services

import (
	"context"
	"go/ast"
	"go/parser"
	"go/token"
	"testing"

	"lazy-balancer-v2/internal/models"
)

// Caddy 数值设置的归一必须无条件执行（在 CaddyConfig 门之前）：装载侧无门
// 归一，apply 侧若受门控，「CaddyConfig=nil + 数值列在场」形态会让主端按归一值
// 计算 users 节哈希、从端保留旧值，哈希恒不等（每轮重放 + 强制重载）。
// 归一本身不改变 nil 门语义（门只决定是否写这些列），故以源码顺序钉住。
func TestUpdateSnapshotSettings_normalizesCaddyNumericsBeforeGate(t *testing.T) {
	fset := token.NewFileSet()
	file, err := parser.ParseFile(fset, "cluster_apply.go", nil, 0)
	if err != nil {
		t.Fatalf("parse cluster_apply.go: %v", err)
	}
	var fn *ast.FuncDecl
	for _, decl := range file.Decls {
		if f, ok := decl.(*ast.FuncDecl); ok && f.Name.Name == "updateSnapshotSettings" {
			fn = f
			break
		}
	}
	if fn == nil || fn.Body == nil {
		t.Fatal("updateSnapshotSettings 未找到")
	}
	normalizeLine, gateLine := 0, 0
	for _, stmt := range fn.Body.List {
		switch node := stmt.(type) {
		case *ast.ExprStmt:
			if call, ok := node.X.(*ast.CallExpr); ok {
				if ident, ok := call.Fun.(*ast.Ident); ok && ident.Name == "normalizeSnapshotCaddyNumericSettings" {
					normalizeLine = fset.Position(node.Pos()).Line
				}
			}
		case *ast.IfStmt:
			if selectorUsesSnapshotCaddyConfig(node.Cond) && gateLine == 0 {
				gateLine = fset.Position(node.Pos()).Line
			}
		}
	}
	if normalizeLine == 0 {
		t.Fatal("updateSnapshotSettings 未调用 normalizeSnapshotCaddyNumericSettings")
	}
	if gateLine == 0 {
		t.Fatal("updateSnapshotSettings 未找到 CaddyConfig 门（if snapshot.CaddyConfig != nil）")
	}
	if normalizeLine > gateLine {
		t.Fatalf("归一在第 %d 行、CaddyConfig 门在第 %d 行——归一必须无条件先行（与装载侧同形）", normalizeLine, gateLine)
	}
}

func selectorUsesSnapshotCaddyConfig(expr ast.Expr) bool {
	binary, ok := expr.(*ast.BinaryExpr)
	if !ok || binary.Op != token.NEQ {
		return false
	}
	for _, side := range []ast.Expr{binary.X, binary.Y} {
		selector, ok := side.(*ast.SelectorExpr)
		if !ok || selector.Sel.Name != "CaddyConfig" {
			continue
		}
		if ident, ok := selector.X.(*ast.Ident); ok && ident.Name == "snapshot" {
			return true
		}
	}
	return false
}

// 归一无条件执行不得改变写入语义：CaddyConfig 缺席（旧主端不携带 caddy 组）时
// 这些列仍保持本地值，不被默认值/nil 语义覆盖。
func TestUpdateSnapshotSettings_nilCaddyConfigStillSkipsCaddyColumns(t *testing.T) {
	_, database := newClusterTestService(t)
	if _, err := database.Exec(`UPDATE global_config SET caddy_log_level='KEEP', http_read_timeout=77 WHERE id=1`); err != nil {
		t.Fatal(err)
	}
	// 手造形态：CaddyConfig 缺席但 Caddy 数值列在场（含非法值，归一应处理）。
	logLevel := "DEBUG"
	readTimeout := -5
	snapshot := models.ClusterSnapshot{BasicSettings: models.ClusterBasicSettings{
		CaddyLogLevel:   &logLevel,
		HTTPReadTimeout: &readTimeout,
	}}

	tx, err := database.BeginTx(context.Background(), nil)
	if err != nil {
		t.Fatalf("begin tx: %v", err)
	}
	defer tx.Rollback()
	if err := updateSnapshotSettings(context.Background(), tx, snapshot); err != nil {
		t.Fatalf("updateSnapshotSettings: %v", err)
	}

	var keptLevel string
	var keptTimeout int
	if err := tx.QueryRow(`SELECT COALESCE(caddy_log_level,''), COALESCE(http_read_timeout,0) FROM global_config WHERE id=1`).Scan(&keptLevel, &keptTimeout); err != nil {
		t.Fatalf("read global_config: %v", err)
	}
	if keptLevel != "KEEP" || keptTimeout != 77 {
		t.Fatalf("caddy 列=(%q,%d), want 保留本地 (KEEP,77)——CaddyConfig 缺席时不得写入", keptLevel, keptTimeout)
	}
}
