package services

import "testing"

// CRS 规则索引的 id: 匹配必须限定在动作串（最后一个引号字面量）内，
// 并剥离其内部 msg/tag 单引号内容——否则数据操作数或 msg/tag 文本里的
// "id:9xxxxx" 会生成幻影规则 ID（放行不存在规则的保存 / 混合选组补删真实 ID）。
func TestParseCRSRuleFileContent_noPhantomIDFromOperandOrMsg(t *testing.T) {
	cases := []struct {
		name string
		rule string
		want string
	}{
		{
			name: "数据操作数含 id 字样",
			rule: `SecRule REQUEST_URI "@rx id:999999" "id:942100,phase:2,deny,msg:'x'"
`,
			want: "942100",
		},
		{
			name: "msg 在 id 之前",
			rule: `SecRule ARGS "@rx foo" "msg:'see id:999995',id:942400,phase:2,pass"
`,
			want: "942400",
		},
		{
			name: "tag 含 id 字样",
			rule: `SecRule ARGS "@rx foo" "id:942500,phase:2,pass,msg:'m',tag:'attack-id:999997'"
`,
			want: "942500",
		},
		{
			name: "续行形态",
			rule: `SecRule ARGS "@rx bar" \
    "id:942600,phase:2,deny,msg:'bar id:999994'"
`,
			want: "942600",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			entries := parseCRSRuleFileContent(tc.rule)
			if len(entries) != 1 {
				t.Fatalf("entries=%+v, want 1", entries)
			}
			if entries[0].ID != tc.want {
				t.Fatalf("id=%q, want %q（不得取 msg/tag/操作数里的幻影 id）", entries[0].ID, tc.want)
			}
		})
	}
}

// 回归：普通 CRS 形态（msg 与 id 同处动作串）仍解析出真实 id 与 msg。
func TestParseCRSRuleFileContent_keepsRealRule(t *testing.T) {
	entries := parseCRSRuleFileContent(`SecRule ARGS "@rx <script" "id:941100,phase:2,block,msg:'XSS Attack Detected via libinjection'"
`)
	if len(entries) != 1 || entries[0].ID != "941100" || entries[0].Msg != "XSS Attack Detected via libinjection" {
		t.Fatalf("entries=%+v, want id=941100 msg 原样", entries)
	}
}
