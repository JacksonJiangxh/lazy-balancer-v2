package mcpserver_test

// 只读轴的文本对账：`readOnlyHiddenTools`（export_config/get_caddy_config）是
// tools/list 只读轴的单源，但三份 Agent 可读文本（initialize instructions、
// ops playbook、docs/mcp.zh-CN.md）各自硬编码同一名单，且既有对账只覆盖 admin
// 轴（ReadOnlyProbeTools）。新增「GET 但对只读 Key 恒 403」的工具时，列表会正确
// 隐藏，文本却仍宣称可读——Agent 按文档调用恒 403。
//
// 本测试从导出集合派生名字：隐藏工具必须在每份文本的「除外/隐藏」子句里出现
// （缺名亦红）；反向要求被标「除外」的工具名必须属于该集合（防止文本与过滤单源
// 分叉）。

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"lazy-balancer-v2/internal/mcpserver"
)

func TestMCPReadOnlyAxisTextsMatchHiddenToolSet(t *testing.T) {
	hidden := mcpserver.ReadOnlyHiddenToolNamesForTest()
	if len(hidden) == 0 {
		t.Fatal("只读隐藏集合为空——文本对账无意义（readOnlyHiddenTools 形态变化）")
	}
	hiddenSet := make(map[string]bool, len(hidden))
	for _, name := range hidden {
		hiddenSet[name] = true
	}

	docsBody, err := os.ReadFile(filepath.Join("..", "..", "docs", "mcp.zh-CN.md"))
	if err != nil {
		t.Fatalf("读 docs/mcp.zh-CN.md: %v", err)
	}
	texts := map[string]string{
		"initialize instructions": mcpserver.ServerInstructionsForTest(),
		"ops playbook":            mcpserver.OpsPlaybook(),
		"docs/mcp.zh-CN.md":       string(docsBody),
	}

	// 隐藏标记子句：命名工具与「除外/隐藏/不展示/恒 403」同处一句才是有效登记。
	hiddenMarker := func(clause string) bool {
		for _, marker := range []string{"除外", "隐藏", "不展示", "不在 tools/list", "恒 403"} {
			if strings.Contains(clause, marker) {
				return true
			}
		}
		return false
	}

	for label, text := range texts {
		for _, name := range hidden {
			clauses := probeClauses(text, name)
			if len(clauses) == 0 {
				t.Errorf("%s 未提及只读恒 403 工具 %s（隐藏集合与文本须同步）", label, name)
				continue
			}
			registered := false
			for _, clause := range clauses {
				if hiddenMarker(clause) {
					registered = true
				}
			}
			if !registered {
				t.Errorf("%s 未把 %s 登记为只读不可用（应在「除外/隐藏」子句里）: %q", label, name, clauses[0])
			}
		}

		// 反向：所有被「除外」点名的工具名必须属于派生隐藏集合。
		for _, spec := range mcpserver.ListToolSpecs() {
			if hiddenSet[spec.Name] {
				continue
			}
			for _, clause := range probeClauses(text, spec.Name) {
				if strings.Contains(clause, "除外") {
					t.Errorf("%s 把 %s 标为「除外」，但它不在只读隐藏集合（文本与 readOnlyHiddenTools 分叉）: %q",
						label, spec.Name, clause)
				}
			}
		}
	}
}
