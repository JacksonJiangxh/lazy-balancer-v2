package db

// TLS 透传（JJC-20261112-01 S1-a）列登记钉测：
//   - passthrough_upstream 在 newColumnsRegistry（存量库幂等补列通道）
//   - 不进任何死列清单（deadColumnDrops / legacy*DeadColumns——源码钉测，
//     死列清单是迁移函数内局部变量，运行期不可达，故按源码文本钉）
//   - fresh DDL 与存量库迁移后均存在（PRAGMA 实测）
//
// 既有列钉测无先例，本文件为首个列登记钉测；参照 models 包
// TestUpdateRuleRequest_clearSemanticsRegisteredAndDocumented 的源码解析先例。

import (
	"os"
	"strings"
	"testing"
)

func TestPassthroughUpstream_registeredInNewColumnsRegistry(t *testing.T) {
	definition, ok := newColumnsRegistry["lb_rules.passthrough_upstream"]
	if !ok {
		t.Fatalf("lb_rules.passthrough_upstream 未登记 newColumnsRegistry——存量库补列通道缺失，渲染读路径会 no such column")
	}
	if !strings.Contains(definition, "TEXT") || !strings.Contains(definition, "DEFAULT ''") {
		t.Fatalf("登记定义 %q 与 DDL 口径不符（TEXT NOT NULL DEFAULT ''）", definition)
	}
}

func TestPassthroughUpstream_notInDeadColumnLists(t *testing.T) {
	source, err := os.ReadFile("db.go")
	if err != nil {
		t.Fatalf("read db.go: %v", err)
	}
	text := string(source)
	for _, anchor := range []string{"deadColumnDrops := []struct{ table, column string }{", "legacyUpstreamDeadColumns := []string{"} {
		start := strings.Index(text, anchor)
		if start < 0 {
			t.Fatalf("db.go 中找不到死列清单锚点 %q（清单重命名时须同步本钉测）", anchor)
		}
		end := strings.Index(text[start:], "\n\t}\n")
		if end < 0 {
			end = len(text) - start
		}
		block := text[start : start+end]
		if strings.Contains(block, "passthrough_upstream") {
			t.Fatalf("passthrough_upstream 出现在死列清单中——新列绝不能进死列清单（迁移即丢列丢值）")
		}
	}
}

func TestPassthroughUpstream_presentInFreshSchema(t *testing.T) {
	preserveDatabaseHandles(t)
	if err := Initialize(t.TempDir()); err != nil {
		t.Fatalf("initialize fresh database: %v", err)
	}
	rows, err := DB.Query(`SELECT type FROM pragma_table_info('lb_rules') WHERE name = 'passthrough_upstream'`)
	if err != nil {
		t.Fatalf("query pragma: %v", err)
	}
	defer rows.Close()
	if !rows.Next() {
		t.Fatalf("fresh DDL 缺 passthrough_upstream 列")
	}
	rows.Close()
	// 列默认值口径：''（读路径 COALESCE 兜底与 specs 快照导出依赖）。
	var notNull, pk any
	var defaultValue any
	if err := DB.QueryRow(`SELECT "notnull", dflt_value, pk FROM pragma_table_info('lb_rules') WHERE name = 'passthrough_upstream'`).Scan(&notNull, &defaultValue, &pk); err != nil {
		t.Fatalf("query column meta: %v", err)
	}
	if defaultValue == nil {
		t.Fatalf("passthrough_upstream 缺 DEFAULT ''——specs 快照导出 COALESCE 口径与 DDL 默认值须一致")
	}
}

func TestPassthroughUpstream_ensureNewColumnsBackfillsLegacySchema(t *testing.T) {
	preserveDatabaseHandles(t)
	// Given fresh 库删除新列（模拟旧版本存量库形态——避免手写不完整旧
	// schema 触发迁移链其他 no such column 噪音）。
	dir := t.TempDir()
	if err := Initialize(dir); err != nil {
		t.Fatalf("initialize fresh database: %v", err)
	}
	if _, err := DB.Exec(`ALTER TABLE lb_rules DROP COLUMN passthrough_upstream`); err != nil {
		t.Fatalf("simulate legacy schema: %v", err)
	}
	if err := Close(); err != nil {
		t.Fatalf("close database: %v", err)
	}
	// When 真实升级路径（ensureNewColumns 幂等补列 + PK 重建链）。
	if err := Initialize(dir); err != nil {
		t.Fatalf("re-initialize legacy database: %v", err)
	}
	// Then 列回填。
	var exists int
	if err := DB.QueryRow(`SELECT COUNT(*) FROM pragma_table_info('lb_rules') WHERE name = 'passthrough_upstream'`).Scan(&exists); err != nil {
		t.Fatalf("query pragma: %v", err)
	}
	if exists != 1 {
		t.Fatalf("存量库迁移后缺 passthrough_upstream 列——newColumnsRegistry/PK 重建登记失效")
	}
}
