package services

// 自定义规则模式含「反斜杠+双引号」序列（`\"`）的两个面：
//   - 写侧：保存/导入必须拒绝并给出可操作文案（否则管理员只看到引擎原文）；
//   - 发射侧：集群同步/带外旧库的存量脏规则走 customRuleEmissionIssue 同一判据，
//     整条跳过且不得拖垮渲染产物编译。
// 依据是引擎行为而非字符串审美：发射器只转义双引号（coraza 仅反转义 \"），
// 该序列渲染成 `\\"` 时 coraza 先把 `\\` 反转义为一个反斜杠，随后引号提前闭合
// 算子串——本文件的负对照直接钉住这一拒绝（修复前 validateCustomRulePattern
// 对该输入返回 nil，即 RED）。

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/corazawaf/coraza/v3"
	"lazy-balancer-v2/internal/models"
)

func TestValidateCustomRulePattern_rejectsBackslashQuote(t *testing.T) {
	for _, operator := range []string{"regex", "contains", "equals", "starts_with"} {
		t.Run(operator, func(t *testing.T) {
			err := validateCustomRulePattern(operator, `a\"b`)
			if err == nil {
				t.Fatalf("operator=%s：模式 `a\\\"b` 被写侧放行（渲染会产出不可编译的 SecRule）", operator)
			}
			if !strings.Contains(err.Error(), "反斜杠+双引号") {
				t.Fatalf("错误文案未指出具体形态，管理员无法据此修正: %v", err)
			}
			// 尾部序列同样拒绝（旧实现只在「以反斜杠结尾」时拦，`\"` 结尾不命中）。
			if err := validateCustomRulePattern(operator, `a\"`); err == nil {
				t.Fatalf("operator=%s：尾部 `\\\"` 被写侧放行", operator)
			}
		})
	}
	// 合法写法不受影响：直接写引号（发射期转义）、转义反斜杠。
	for _, pattern := range []string{`a"b`, `"key": "value"`, `a\\b`, `C:\\dir`, `\x22`} {
		if err := validateCustomRulePattern("regex", pattern); err != nil {
			t.Fatalf("合法模式 %q 被拒绝: %v", pattern, err)
		}
	}
	if err := validateCustomRulePattern("contains", `C:\\dir`); err != nil {
		t.Fatalf("合法非 regex 模式被拒绝: %v", err)
	}
}

func TestCustomRuleEmissionIssue_rejectsBackslashQuote(t *testing.T) {
	chained := models.CustomRule{
		ID: 1, Name: "链式", Enabled: true, Action: "block",
		Conditions: []models.CustomRuleCondition{{Target: "uri", Operator: "regex", Pattern: `a\"b`}},
	}
	if issue := customRuleEmissionIssue(chained); !strings.Contains(issue, "反斜杠+双引号") {
		t.Fatalf("链式规则的发射守卫未复用写侧判据: issue=%q", issue)
	}
	legacy := models.CustomRule{
		ID: 2, Name: "旧版单目标", Enabled: true, Action: "block",
		Target: "uri", Operator: "contains", Pattern: `a\"b`,
	}
	if issue := customRuleEmissionIssue(legacy); !strings.Contains(issue, "反斜杠+双引号") {
		t.Fatalf("旧版单目标形状的发射守卫未复用写侧判据: issue=%q", issue)
	}
}

func TestEmitCustomRules_skipsBackslashQuoteAndOutputCompiles(t *testing.T) {
	// 存量脏规则（集群同步/带外旧库，绕过写侧校验）只跳过自身；干净规则照常
	// 发射，整份渲染产物仍被引擎接受（单条坏规则不得拖垮整站）。
	policy := &models.SecurityPolicy{
		AnomalyThreshold: 5,
		Mode:             "blocking",
		CustomRules: json.RawMessage(`[
			{"id":21,"name":"脏","enabled":true,"action":"block","target":"uri","operator":"contains","pattern":"a\\\"b"},
			{"id":22,"name":"干净","enabled":true,"action":"block","target":"uri","operator":"contains","pattern":"\"key\""}
		]`),
	}
	directives := mustDirectives(BuildCorazaDirectives(policy, nil, "", true, 0, "lb_test"))
	if strings.Contains(directives, "id:10021") {
		t.Fatalf("含反斜杠+双引号的存量规则未被发射侧跳过:\n%s", directives)
	}
	if !strings.Contains(directives, "id:10022") {
		t.Fatalf("干净规则应照常发射:\n%s", directives)
	}
	compileForEngineGate(t, directives)
}

// 负对照：修复前渲染出的形状（未校验的 `\"` 经 escapeCorazaPattern 变成 `\\"`）
// 必须被引擎拒绝——这是「写侧必须拒绝」的引擎依据；若引擎开始接受该形状，
// 本条会先失败，提示重新评估该判据（而不是静默保留一条无依据的限制）。
func TestEngineGate_backslashQuoteRenderingIsRejected(t *testing.T) {
	rendered := `SecRule REQUEST_URI "@contains a\\"b" "id:10021,phase:1,deny,log"` + "\n"
	if _, err := coraza.NewWAF(coraza.NewWAFConfig().WithDirectives(rendered)); err == nil {
		t.Fatalf("引擎接受了未校验形态的渲染结果，该判据的引擎依据失效:\n%s", rendered)
	}
}
