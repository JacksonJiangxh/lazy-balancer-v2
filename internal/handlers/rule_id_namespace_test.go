package handlers

import (
	"strings"
	"testing"
)

// 导入侧的生成式子路由 @id 命名空间保留：规则 ID 取
// <另一规则ID>_path_<n>/_geoip/_redirect 形态时，两条规则渲染出的子路由 @id
// 会与另一条规则的主路由 @id 相同，Caddy /load 以 duplicate ID 整份拒绝
// （事务回滚）。导入必须在字段层点名冲突的两条规则。
func TestValidateV2BackupRules_rejectsGeneratedRouteIDCollision(t *testing.T) {
	cases := []struct {
		name   string
		second string
	}{
		{name: "path", second: "lb_import_probe_path_0"},
		{name: "geoip", second: "lb_import_probe_geoip"},
		{name: "redirect", second: "lb_import_probe_redirect"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			tables := ruleTablesShared()
			colliding := map[string]any{}
			for key, value := range tables["lb_rules"][0] {
				colliding[key] = value
			}
			colliding["caddy_id"] = tc.second
			colliding["name"] = "import-probe-collision"
			tables["lb_rules"] = append(tables["lb_rules"], colliding)

			err := validateV2BackupRules(tables)
			if err == nil {
				t.Fatalf("导入未拒绝 @id 命名空间冲突（%s）", tc.second)
			}
			if !strings.Contains(err.Error(), "命名空间冲突") ||
				!strings.Contains(err.Error(), "lb_import_probe") ||
				!strings.Contains(err.Error(), tc.second) {
				t.Fatalf("err=%v, want 点名冲突的两条规则", err)
			}
		})
	}

	// 正向对照：无冲突的生成式形态 ID 合法（不得过度拒绝单条规则）。
	tables := ruleTablesShared()
	tables["lb_rules"][0]["caddy_id"] = "lb_only_path_0"
	tables["upstreams"][0]["rule_id"] = "lb_only_path_0"
	if err := validateV2BackupRules(tables); err != nil {
		t.Fatalf("无冲突规则被拒绝: %v", err)
	}
}
