package mcpserver

import (
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
)

// docs/mcp.zh-CN.md 的「仅 REST 可用的能力」表是面向用户/Agent 的能力缺口说明。
// 该表此前自由腐化（CRS/IP2Region 自动更新开关、系统任务 toggle/control 早已
// 有 MCP 工具却仍列在仅 REST 中），读者据此走 REST 多绕一层。本测试把表内
// 「方法 + 路径」与 tools 清单机械对账：表内端点不得被任一工具覆盖。

var docEndpointPattern = regexp.MustCompile("`(GET|POST|PUT|PATCH|DELETE) ([^`]+)`")

// normalizeMCPPath 把两类占位符统一成 *，便于跨清单比较：
// 工具侧 `/system/tasks/{id}/toggle`、文档侧 `/system/tasks/:id/toggle`。
func normalizeMCPPath(path string) string {
	path = strings.TrimSpace(path)
	path = strings.TrimPrefix(path, "/api/v1")
	path = regexp.MustCompile(`\{[^}]*\}`).ReplaceAllString(path, "*")
	path = regexp.MustCompile(`:[A-Za-z_][A-Za-z0-9_]*`).ReplaceAllString(path, "*")
	return path
}

func restOnlyDocSection(t *testing.T) string {
	t.Helper()
	section, err := restOnlyDocSectionText()
	if err != nil {
		t.Fatal(err)
	}
	return section
}

// restOnlyDocSectionText 读「仅 REST 可用的能力」章节原文；抽成无 testing.T
// 的形态供外部测试包经 export_test.go 复用（正向/反向对账共用同一解析）。
func restOnlyDocSectionText() (string, error) {
	body, err := os.ReadFile(filepath.Join("..", "..", "docs", "mcp.zh-CN.md"))
	if err != nil {
		return "", fmt.Errorf("读 docs/mcp.zh-CN.md: %w", err)
	}
	source := string(body)
	start := strings.Index(source, "## 仅 REST 可用的能力")
	if start < 0 {
		return "", fmt.Errorf("docs/mcp.zh-CN.md 缺少「仅 REST 可用的能力」章节")
	}
	section := source[start:]
	if end := strings.Index(section[len("## 仅 REST 可用的能力"):], "\n## "); end >= 0 {
		section = section[:len("## 仅 REST 可用的能力")+end]
	}
	return section, nil
}

func TestMCPDocsRestOnlySectionHasNoCoveredEndpoints(t *testing.T) {
	covered := make(map[string]string, len(tools))
	for _, spec := range tools {
		key := spec.method + " " + normalizeMCPPath(spec.path)
		covered[key] = spec.name
	}

	section := restOnlyDocSection(t)
	matches := docEndpointPattern.FindAllStringSubmatch(section, -1)
	if len(matches) == 0 {
		t.Fatal("「仅 REST 可用的能力」表未解析出任何端点（表格形态被改动？）")
	}
	for _, match := range matches {
		method, rawPath := match[1], match[2]
		// 花括号多值形态（如 /{toggle,control}）逐项展开后比较。
		for _, path := range expandBraceAlternatives(rawPath) {
			key := method + " " + normalizeMCPPath(path)
			if name, ok := covered[key]; ok {
				t.Fatalf("文档把 %s %s 列为「仅 REST」，但工具 %s 已覆盖——两处必须同步", method, path, name)
			}
		}
	}
}

// expandBraceAlternatives 展开单个 `{a,b}` 交替形态；无花括号时原样返回。
func expandBraceAlternatives(path string) []string {
	open := strings.Index(path, "{")
	if open < 0 {
		return []string{path}
	}
	close := strings.Index(path[open:], "}")
	if close < 0 {
		return []string{path}
	}
	close += open
	prefix, suffix := path[:open], path[close+1:]
	var expanded []string
	for _, alt := range strings.Split(path[open+1:close], ",") {
		expanded = append(expanded, prefix+strings.TrimSpace(alt)+suffix)
	}
	return expanded
}
