package services

// 路由归属判据必须按生成侧已知后缀精确匹配：裸 ruleID+"_" 前缀会把
// 「恰为下划线前缀」的另一条规则主路由混进配置查看框（v1 导入/历史 ID 允许
// 含下划线：lb_web 与 lb_web_path 可并存）。

import "testing"

func TestRouteIDBelongsToRule_suffixWhitelist(t *testing.T) {
	cases := []struct {
		routeID string
		ruleID  string
		want    bool
	}{
		// 主路由
		{"lb_web", "lb_web", true},
		// 生成侧兄弟路由：path_<序号> / geoip / HTTP→HTTPS redirect
		{"lb_web_path_0", "lb_web", true},
		{"lb_web_path_12", "lb_web", true},
		{"lb_web_geoip", "lb_web", true},
		{"lb_web_redirect", "lb_web", true},
		// 另一条规则的主路由恰好以下划线为前缀（历史 ID 形态）
		{"lb_web_path", "lb_web", false},
		{"lb_web_extra", "lb_web", false},
		{"lb_web_path_x", "lb_web", false},
		// 空 / 非归属
		{"", "lb_web", false},
		{"lb_webx", "lb_web", false},
		{"lb_other_path_0", "lb_web", false},
		{"lb_web_path_0", "", false},
	}
	for _, test := range cases {
		if got := RouteIDBelongsToRule(test.routeID, test.ruleID); got != test.want {
			t.Errorf("RouteIDBelongsToRule(%q, %q)=%v, want %v", test.routeID, test.ruleID, got, test.want)
		}
	}
}
