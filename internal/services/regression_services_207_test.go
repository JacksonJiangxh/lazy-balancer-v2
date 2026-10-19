package services

import (
	"bytes"
	"encoding/json"
	"log"
	"strings"
	"testing"
	"time"

	"lazy-balancer-v2/internal/models"
)

// resetAuditFailureThrottleForTest 清空失败日志限流状态：限流键把数字归一为
// #，其他用例的同类消息会抑制本用例的断言日志（60s 窗口）。
func resetAuditFailureThrottleForTest() {
	auditFailureLogMu.Lock()
	auditFailureLogTimes = map[string]time.Time{}
	auditFailureLogMu.Unlock()
}

// C2-83-01：负 ID 必须在发射侧整条跳过——cr.ID=-9990 发射 id:10（撞 body
// processor），cr.ID<=-10000 产出负 SecRule id，二者均使 coraza 拒绝整份配置。
func TestEmitCustomRules_skipsNegativeIDs(t *testing.T) {
	for _, id := range []int{-1, -9990, -10000, -20000} {
		var sb strings.Builder
		emitCustomRules(&sb, []models.CustomRule{{
			ID:         id,
			Name:       "负ID规则",
			Enabled:    true,
			Action:     "block",
			Score:      5,
			Conditions: []models.CustomRuleCondition{{Target: "uri", Operator: "contains", Pattern: "x"}},
		}}, 0)
		if sb.Len() != 0 {
			t.Fatalf("id=%d 负 ID 规则必须跳过发射，got=%q", id, sb.String())
		}
	}
	// 回归形状：合法 5 位 id 照常发射（id:crID+10000）。
	var sb strings.Builder
	emitCustomRules(&sb, []models.CustomRule{{
		ID:         12345,
		Name:       "合法规则",
		Enabled:    true,
		Action:     "block",
		Score:      5,
		Conditions: []models.CustomRuleCondition{{Target: "uri", Operator: "contains", Pattern: "x"}},
	}}, 0)
	if !strings.Contains(sb.String(), "id:22345") {
		t.Fatalf("合法规则未发射: %q", sb.String())
	}
}

// C2-83-02：行 Scan 失败（行存在但内容不可解析）不得被计入「N 个不存在」。
func TestResolvePolicyCustomRules_scanFailureNotReportedAsDangling(t *testing.T) {
	_, database := newClusterTestService(t)
	// SQLite INTEGER 亲和列可存文本：score='not-a-number' 令 Scan→int 失败。
	res, err := database.Exec(`INSERT INTO security_custom_rules (name, conditions, action, score, enabled)
		VALUES ('脏行', '[]', 'block', 'not-a-number', 1)`)
	if err != nil {
		t.Fatal(err)
	}
	id, _ := res.LastInsertId()

	resetAuditFailureThrottleForTest()
	var buf bytes.Buffer
	oldWriter := log.Writer()
	log.SetOutput(&buf)
	t.Cleanup(func() { log.SetOutput(oldWriter) })

	raw, _ := json.Marshal([]int64{id})
	rules := resolvePolicyCustomRules(raw, nil)
	if len(rules) != 0 {
		t.Fatalf("rules=%+v, want 空（脏行不可解析）", rules)
	}
	logs := buf.String()
	if !strings.Contains(logs, "行扫描失败") {
		t.Fatalf("扫描失败必须留痕，logs=%q", logs)
	}
	if strings.Contains(logs, "不存在") {
		t.Fatalf("扫描失败不得计入「不存在」悬空日志，logs=%q", logs)
	}
}

// C2-83-03：策略内联 IP 名单 JSON 畸形时渲染路径不得静默降级——至少限流
// WARN 留痕（deny ACL / 黑名单方向静默空集即 fail-open）。
func TestMergedACLList_warnsOnMalformedInlineJSON(t *testing.T) {
	resetAuditFailureThrottleForTest()
	var buf bytes.Buffer
	oldWriter := log.Writer()
	log.SetOutput(&buf)
	t.Cleanup(func() { log.SetOutput(oldWriter) })

	p := &models.SecurityPolicy{ID: 8301, IPACLList: `{"not":"a list"`}
	if got := mergedACLList(p); len(got) != 0 {
		t.Fatalf("malformed inline list must degrade to empty set, got=%v", got)
	}
	logs := buf.String()
	if !strings.Contains(logs, "内联 IP 名单 ip_acl_list 解析失败") {
		t.Fatalf("畸形内联名单必须 WARN 留痕，logs=%q", logs)
	}

	buf.Reset()
	p2 := &models.SecurityPolicy{ID: 8302, IPWhitelist: []byte(`[1,2,`)}
	if got := mergedWhitelist(p2); len(got) != 0 {
		t.Fatalf("malformed whitelist must degrade to empty set, got=%v", got)
	}
	if !strings.Contains(buf.String(), "内联 IP 名单 ip_whitelist 解析失败") {
		t.Fatalf("畸形信任名单必须 WARN 留痕，logs=%q", buf.String())
	}
}
