package mcpserver

import (
	"regexp"
	"testing"
)

// playbookIdentifierPattern 抓手册里以反引号标注的标识符（工具名、参数名、
// 状态字面量都是这个形态）。
var playbookIdentifierPattern = regexp.MustCompile("`([a-z][a-z0-9_]*)`")

// playbookNonToolIdentifiers 是手册里以反引号标注、但不是工具名的标识符。
// 登记项=参数名/响应字段/任务状态字面量；新增项必须在此说明用途，防止把
// 已改名/删除的工具悄悄塞进白名单掩盖腐化。
var playbookNonToolIdentifiers = map[string]string{
	"caddy_id":     "工具参数：规则 Caddy ID",
	"rule_id":      "工具参数：证书任务的规则过滤",
	"domain":       "工具参数：域名",
	"listen_port":  "工具参数：监听端口",
	"page":         "工具参数：分页页码",
	"page_size":    "工具参数：分页大小",
	"input_schema": "tools/list 响应字段",
	"issued":       "证书任务状态字面量",
	"failed":       "证书任务状态字面量",
}

// TestPlaybookToolMentionsExist 把手册里提到的工具名与真实工具清单对账：
// 工具改名/删除后手册仍教 Agent 调旧名字时，调用只会反复试错（工具不存在 →
// 协议层错误），而没有任何测试会红。
func TestPlaybookToolMentionsExist(t *testing.T) {
	known := make(map[string]struct{}, len(tools))
	for _, spec := range tools {
		known[spec.name] = struct{}{}
	}
	if len(known) == 0 {
		t.Fatal("工具清单为空——tools 可能已重构，请同步本绊线")
	}
	for name, reason := range playbookNonToolIdentifiers {
		if _, isTool := known[name]; isTool {
			t.Errorf("白名单项 %q 其实是工具名（%s）——请从 playbookNonToolIdentifiers 移除", name, reason)
		}
	}

	mentions := playbookIdentifierPattern.FindAllStringSubmatch(opsPlaybook, -1)
	if len(mentions) == 0 {
		t.Fatal("手册未解析出任何反引号标识符（书写形态被改动？）")
	}
	for _, match := range mentions {
		name := match[1]
		if _, allowlisted := playbookNonToolIdentifiers[name]; allowlisted {
			continue
		}
		if _, isTool := known[name]; !isTool {
			t.Errorf("手册提到的工具 %q 不在工具清单内——工具已改名/删除，手册需同步", name)
		}
	}
}
