package services

import "testing"

// 生成式子路由 @id 命名空间：<ruleID>_path_<n>/_geoip/_redirect 与另一条规则
// 主路由 @id 撞名时，Caddy /load 会以 duplicate ID 拒绝整份配置。判定必须与
// 运行配置归属函数同源（RouteIDBelongsToRule）。
func TestRuleIDNamespaceConflict(t *testing.T) {
	cases := []struct {
		name    string
		ruleID  string
		ids     []string
		wantHit string
	}{
		{name: "path route collision", ruleID: "lb_x_path_0", ids: []string{"lb_x", "lb_x_path_0"}, wantHit: "lb_x"},
		{name: "geoip route collision", ruleID: "lb_x_geoip", ids: []string{"lb_x", "lb_x_geoip"}, wantHit: "lb_x"},
		{name: "redirect route collision", ruleID: "lb_x_redirect", ids: []string{"lb_x", "lb_x_redirect"}, wantHit: "lb_x"},
		{name: "multi digit path collision", ruleID: "lb_x_path_12", ids: []string{"lb_x", "lb_x_path_12"}, wantHit: "lb_x"},
		{name: "main rule has no conflict", ruleID: "lb_x", ids: []string{"lb_x", "lb_x_path_0"}, wantHit: ""},
		{name: "non numeric path suffix", ruleID: "lb_x_path", ids: []string{"lb_x", "lb_x_path"}, wantHit: ""},
		{name: "unrelated ids", ruleID: "lb_a", ids: []string{"lb_b", "lb_c_path_0"}, wantHit: ""},
		{name: "self skip", ruleID: "lb_x_path_0", ids: []string{"lb_x_path_0"}, wantHit: ""},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := RuleIDNamespaceConflict(tc.ruleID, tc.ids); got != tc.wantHit {
				t.Fatalf("RuleIDNamespaceConflict(%q, %v)=%q, want %q", tc.ruleID, tc.ids, got, tc.wantHit)
			}
		})
	}
}

// 与路由归属判定同源（防两侧口径漂移）。
func TestRuleIDNamespaceConflict_matchesRouteOwner(t *testing.T) {
	if !RouteIDBelongsToRule("lb_web_path_0", "lb_web") {
		t.Fatal("归属判定应认领生成式路径子路由")
	}
	if RouteIDBelongsToRule("lb_web_path", "lb_web") {
		t.Fatal("非数字后缀不是生成式子路由（裸前缀匹配不得放行）")
	}
	if got := RuleIDNamespaceConflict("lb_web_path", []string{"lb_web"}); got != "" {
		t.Fatalf("RuleIDNamespaceConflict=%q, want 无冲突（与归属判定同源）", got)
	}
}
