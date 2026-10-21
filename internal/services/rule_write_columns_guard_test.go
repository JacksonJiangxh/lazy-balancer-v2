package services

// 历史问题（历史）结构守卫：生产代码中「INSERT INTO lb_rules (」
// 手写字面量唯一豁免=config_import_v1.go（v1 遗留转换器，窄清单语义已裁定
// 维持）；其余站点必须经 LbRuleInsertSQL 单源生成——新增列漏改某一处即
// 「保存成功但与快照/副本不同形」（历史问题 缺陷形态）。

import (
	"go/ast"
	"go/parser"
	"go/token"
	"io/fs"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"testing"
)

// handwrittenRuleInsertPattern 匹配「手写 lb_rules INSERT」的归一化形态。
// 历史问题（历史）：原判定 strings.Contains(query, "INSERT INTO lb_rules (")
// 是字面量、单空格、必须同串——`INSERT INTO lb_rules\n(…`、`INSERT OR REPLACE INTO
// lb_rules`、`INSERT INTO "lb_rules"` 全部静默绕过单源门。匹配前统一做空白折叠
// （strings.Fields 重连）与双引号剥离，再按大小写不敏感模式判定。
var handwrittenRuleInsertPattern = regexp.MustCompile(`(?i)\bINSERT(?:\s+OR\s+(?:REPLACE|IGNORE))?\s+INTO\s+lb_rules\s*\(`)

// isHandwrittenRuleInsert 报告 SQL 文本是否是手写规则 INSERT。
func isHandwrittenRuleInsert(query string) bool {
	normalized := strings.ReplaceAll(query, `"`, "")
	normalized = strings.Join(strings.Fields(normalized), " ")
	return handwrittenRuleInsertPattern.MatchString(normalized)
}

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
				if unquoteErr != nil || !isHandwrittenRuleInsert(query) {
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

// 历史问题（历史）：守卫判定必须先归一化再匹配——换行、多空格、带引号
// 表名、INSERT OR REPLACE/IGNORE 任一形态都不得逃逸（原字面量 Contains 对上述
// 形态静默漏检，新增手写 INSERT 只要换行即可绕过单源门）。
func TestHandwrittenRuleInsertMatcher_normalizesFormattingVariants(t *testing.T) {
	tests := []struct {
		name  string
		query string
		want  bool
	}{
		{name: "canonical", query: "INSERT INTO lb_rules (caddy_id) VALUES (?)", want: true},
		{name: "newline before columns", query: "INSERT INTO lb_rules\n\t(caddy_id) VALUES (?)", want: true},
		{name: "extra spaces", query: "INSERT  INTO   lb_rules   (caddy_id) VALUES (?)", want: true},
		{name: "quoted table", query: `INSERT INTO "lb_rules" (caddy_id) VALUES (?)`, want: true},
		{name: "or replace", query: "INSERT OR REPLACE INTO lb_rules (caddy_id) VALUES (?)", want: true},
		{name: "or ignore lowercase", query: "insert or ignore into lb_rules(caddy_id) values (?)", want: true},
		{name: "other table", query: "INSERT INTO lb_rules_backup (caddy_id) VALUES (?)", want: false},
		{name: "plain select", query: "SELECT * FROM lb_rules WHERE id = ?", want: false},
		{name: "other insert", query: "INSERT INTO upstreams (rule_id) VALUES (?)", want: false},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if got := isHandwrittenRuleInsert(test.query); got != test.want {
				t.Fatalf("isHandwrittenRuleInsert(%q)=%v, want %v", test.query, got, test.want)
			}
		})
	}
}
