package mcpserver

import (
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
)

// 规则级 server_tokens_hidden 的三态语义只有一处真相：渲染层
// resolveRuleOverrides（0=跟随全局开关 / 1=隐藏响应 Server 头 /
// 2=显式显示、抵消全局隐藏）。MCP 工具 schema 曾把描述写成
// 「0=显示/1=隐藏版本/2=完全隐藏」——与渲染方向相反：照描述把「完全隐藏」
// 写成 2 会得到公布 Server 头的结果，0 也不会起到显式显示的作用（全局开关
// 打开时它照样隐藏）。
//
// 本测试把 schema 文本与渲染层源码机械对账，双向失效：描述漂移 FAIL，
// 渲染语义变更同样 FAIL（提醒同步描述）。

// resolveRuleOverrides 函数体解析锚点：函数签名与唯一 return 行。
const (
	rendererFuncAnchor  = "func resolveRuleOverrides("
	rendererReturnLine  = "return requestBodyMaxSizeMB, upstreamKeepalive, hideServer, nil"
	rendererHideBranch  = "hideServer = true"
	rendererShowBranch  = "hideServer = false"
	rendererInheritLine = "hideServer = rule.GlobalServerTokensHidden"
)

// rendererServerTokensSemantics 从渲染层源码取三态语义真相。
func rendererServerTokensSemantics(t *testing.T) map[string]string {
	t.Helper()
	body, err := os.ReadFile(filepath.Join("..", "services", "caddy.go"))
	if err != nil {
		t.Fatalf("读 internal/services/caddy.go: %v", err)
	}
	source := string(body)
	start := strings.Index(source, rendererFuncAnchor)
	if start < 0 {
		t.Fatalf("渲染层缺少 %s（函数被改名？）", rendererFuncAnchor)
	}
	end := strings.Index(source[start:], rendererReturnLine)
	if end < 0 {
		t.Fatalf("resolveRuleOverrides 函数体缺少返回行（结构被改动？）")
	}
	fnBody := source[start : start+end]

	if !strings.Contains(fnBody, rendererInheritLine) {
		t.Fatalf("resolveRuleOverrides 缺少 %q（0 值不再跟随全局？）", rendererInheritLine)
	}
	valueOne := rendererBranchBody(fnBody, "rule.ServerTokensHidden == 1")
	if !strings.Contains(valueOne, rendererHideBranch) {
		t.Fatalf("server_tokens_hidden=1 分支未置 hideServer=true：%q", valueOne)
	}
	valueTwo := rendererBranchBody(fnBody, "rule.ServerTokensHidden == 2")
	if !strings.Contains(valueTwo, rendererShowBranch) {
		t.Fatalf("server_tokens_hidden=2 分支未置 hideServer=false：%q", valueTwo)
	}
	return map[string]string{"0": "跟随全局", "1": "隐藏", "2": "显示"}
}

// rendererBranchBody 取指定条件后紧跟的代码块（到右花括号为止）。
func rendererBranchBody(fnBody, condition string) string {
	index := strings.Index(fnBody, condition)
	if index < 0 {
		return ""
	}
	branch := fnBody[index:]
	if brace := strings.Index(branch, "{"); brace >= 0 {
		branch = branch[brace+1:]
	}
	if closeBrace := strings.Index(branch, "}"); closeBrace >= 0 {
		branch = branch[:closeBrace]
	}
	return branch
}

// serverTokensSchemaDescriptionPattern 提取两份规则 schema 里该字段的描述。
var serverTokensSchemaDescriptionPattern = regexp.MustCompile(
	`"server_tokens_hidden":\{"type":"integer","enum":\[0,1,2\],"description":"([^"]*)"\}`)

// serverTokensEntryPattern 解析描述里的「N=含义」片段（含义到 /、；，。 或
// 括号说明为止）。
var serverTokensEntryPattern = regexp.MustCompile(`([012])=([^/、；;，。()（）]+)`)

// classifyServerTokensMeaning 只做三类概念判别，不锁死措辞：
// 显式显示（显示/不隐藏）、隐藏（隐藏且不宣称显示）、跟随全局（提及全局）。
func classifyServerTokensMeaning(meaning string) (string, error) {
	text := strings.TrimSpace(meaning)
	if text == "" {
		return "", fmt.Errorf("含义片段为空")
	}
	switch {
	case strings.Contains(text, "不隐藏"):
		return "显示", nil
	case strings.Contains(text, "显示"):
		return "显示", nil
	case strings.Contains(text, "隐藏"):
		return "隐藏", nil
	case strings.Contains(text, "全局"):
		return "跟随全局", nil
	}
	return "", fmt.Errorf("含义片段 %q 无三态语义关键词（显示/隐藏/全局）", text)
}

// parseServerTokensSemantics 把描述拆成 0/1/2 → 语义 的映射。
func parseServerTokensSemantics(description string) (map[string]string, error) {
	entries := map[string]string{}
	for _, entryMatch := range serverTokensEntryPattern.FindAllStringSubmatch(description, -1) {
		key := entryMatch[1]
		if _, duplicated := entries[key]; duplicated {
			return nil, fmt.Errorf("%s 重复出现", key)
		}
		semantic, err := classifyServerTokensMeaning(entryMatch[2])
		if err != nil {
			return nil, fmt.Errorf("%s: %w", key, err)
		}
		entries[key] = semantic
	}
	if len(entries) != 3 {
		return nil, fmt.Errorf("未覆盖三态（解析到 %v）", entries)
	}
	return entries, nil
}

func TestRuleSchemasServerTokensHiddenMatchRendererSemantics(t *testing.T) {
	want := rendererServerTokensSemantics(t)

	for _, schemaCases := range []struct {
		name   string
		schema string
	}{
		{"create_rule", createRuleSchema},
		{"update_rule", updateRuleSchema},
	} {
		match := serverTokensSchemaDescriptionPattern.FindStringSubmatch(schemaCases.schema)
		if match == nil {
			t.Fatalf("%s 的 server_tokens_hidden 不再是 integer enum[0,1,2] 带描述形态", schemaCases.name)
		}
		description := match[1]
		got, err := parseServerTokensSemantics(description)
		if err != nil {
			t.Fatalf("%s server_tokens_hidden 描述不可解析：%v（描述=%q）", schemaCases.name, err, description)
		}
		for key, wantSemantic := range want {
			if got[key] != wantSemantic {
				t.Errorf("%s server_tokens_hidden=%s 描述语义=%q（want %q），描述=%q——schema 必须与渲染层 resolveRuleOverrides 同口径",
					schemaCases.name, key, got[key], wantSemantic, description)
			}
		}
	}
}

// 反向夹具：曾上线的错误描述必须被判别为「与渲染语义不符」，防止解析器
// 退化成恒真（描述里随便写什么都能通过）。
func TestServerTokensSemanticsRejectReversedDescription(t *testing.T) {
	reversed := "Server 头隐藏级别：0=显示/1=隐藏版本/2=完全隐藏"
	got, err := parseServerTokensSemantics(reversed)
	if err != nil {
		t.Fatalf("错误描述应可解析出三态（语义判别负责否决）：%v", err)
	}
	want := map[string]string{"0": "跟随全局", "1": "隐藏", "2": "显示"}
	mismatches := 0
	for key, wantSemantic := range want {
		if got[key] != wantSemantic {
			mismatches++
		}
	}
	if mismatches != 2 {
		t.Fatalf("错误描述应恰有 2 处语义不符（0 与 2），实际 %d 处：%v", mismatches, got)
	}
	if got["0"] != "显示" || got["2"] != "隐藏" {
		t.Fatalf("错误描述判别=%v，want 0=显示/2=隐藏（方向相反的实证）", got)
	}
}
