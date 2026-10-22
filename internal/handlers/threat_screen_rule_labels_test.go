package handlers

import (
	"encoding/json"
	"net/http"
	"testing"
	"time"

	"lazy-balancer-v2/internal/db"
)

// 威胁大屏「命中规则」榜应展示可读规则名而非裸 id：事件里 rule_triggered
// 是 coraza SecRule id（阶段 1 预检为合成 id、CRS 为 9xxxxx、自定义规则为
// DB id+10000、限流为 429），直接展示用户无法理解。
func TestGetSecurityThreatScreen_topRulesUseReadableNames(t *testing.T) {
	// Given：四类触发 id 各 1 条事件 + 一条已命名的自定义规则
	setupSecurityPolicyTestDB(t)
	router := newThreatScreenRouter(t, newThreatMetricsServer(t).URL)
	seed := func(minutes int, ip, triggered, msg string) {
		if _, err := db.MetricsDB.Exec(`INSERT INTO security_events (event_time, client_ip, method, uri, event_type, rule_triggered, rule_msg, action, rule_name)
			VALUES (?, ?, 'GET', '/a', 'stage1', ?, ?, 'blocked', '')`,
			utcStringAgo(time.Duration(minutes)*time.Minute), ip, triggered, msg); err != nil {
			t.Fatalf("seed event %s: %v", triggered, err)
		}
	}
	// 计数构造 Top3 顺序：800009 ×4 > 2 ×3 > 10018 ×2 > 930130 ×1
	for i := 0; i < 4; i++ {
		seed(30+i, "93.184.216.7", "800009", "地域拦截命中")
	}
	for i := 0; i < 3; i++ {
		seed(30+i, "93.184.216.8", "2", "IP 黑名单拒绝")
	}
	for i := 0; i < 2; i++ {
		seed(30+i, "93.184.216.9", "10018", "自定义规则命中")
	}
	seed(30, "93.184.216.10", "930130", "PHP Injection")
	if _, err := db.DB.Exec(`INSERT INTO security_custom_rules (id, name, conditions, action, enabled) VALUES (18, '测试-阶段3UA', '[]', 'block', 1)`); err != nil {
		t.Fatalf("seed custom rule: %v", err)
	}

	// When
	recorder := getRequest(t, router, "/security/overview/threat-screen")
	if recorder.Code != http.StatusOK {
		t.Fatalf("status=%d body=%s", recorder.Code, recorder.Body.String())
	}
	var payload threatScreenPayload
	if err := json.Unmarshal(recorder.Body.Bytes(), &payload); err != nil {
		t.Fatal(err)
	}

	// Then
	got := map[string]bool{}
	for _, entry := range payload.Data.TopRules {
		got[entry.Name] = true
	}
	want := []string{
		"地域拦截（策略 #9）",
		"IP 访问控制拦截（#2）",
		"测试-阶段3UA（#10018）",
	}
	for _, name := range want {
		if !got[name] {
			t.Errorf("top_rules 缺少可读标签 %q，实际=%+v", name, payload.Data.TopRules)
		}
	}
	for _, entry := range payload.Data.TopRules {
		if entry.Name == "800009" || entry.Name == "2" || entry.Name == "10018" {
			t.Errorf("top_rules 仍暴露裸 id %q", entry.Name)
		}
	}
	// 第 4 名被 Top3 截断，改用解析器直测 CRS 回退标签（索引目录在测试环境为空）
	if got := describeThreatRuleName("930130"); got != "CRS 规则（#930130）" {
		t.Errorf("CRS 未命中索引时应回退可读标签，got=%q", got)
	}
}
