package services

// RDB 文件化严格模式（v2.3.4）：引用的威胁库 .iplist 文件缺失时——
// ①渲染跳过该策略（绝不以空条目集静默收窄 ACL 保护面）；
// ②同规则其他未受影响策略照常渲染；
// ③文件恢复后下次渲染自动恢复（无持久状态）。

import (
	"database/sql"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"lazy-balancer-v2/internal/db"
)

// rdbStrictSeedThreatList 播种一条威胁库列表行（system=1, entries 空——
// RDB 后 DB 不再存条目），返回列表 id。
func rdbStrictSeedThreatList(t *testing.T, database *sql.DB, source string) int64 {
	t.Helper()
	name := db.ThreatListNameBySource(source)
	res, err := database.Exec(
		`INSERT INTO security_ip_lists (name, description, entries, system, created_at) VALUES (?,?,?,?,datetime('now'))`,
		name, "", "[]", 1)
	if err != nil {
		t.Fatalf("seed threat list %s: %v", source, err)
	}
	id, err := res.LastInsertId()
	if err != nil {
		t.Fatalf("seed threat list %s last id: %v", source, err)
	}
	return id
}

// rdbStrictBindRefPolicy 播种一条 deny ACL 策略（inline 空 + 引用列表）并绑定规则。
func rdbStrictBindRefPolicy(t *testing.T, database *sql.DB, ruleCaddyID, name string, refsJSON string) {
	t.Helper()
	res, err := database.Exec(`INSERT INTO security_policies
		(name, mode, enabled, ip_acl_enabled, ip_acl_mode, ip_acl_list, ip_acl_list_refs, ip_blacklist)
		VALUES (?,?,?,?,?,?,?,?)`,
		name, "off", 1, 1, "deny", "[]", refsJSON, "[]")
	if err != nil {
		t.Fatalf("seed policy %s: %v", name, err)
	}
	policyID, err := res.LastInsertId()
	if err != nil {
		t.Fatalf("read policy %s id: %v", name, err)
	}
	if _, err := database.Exec(`INSERT INTO security_policy_bindings (rule_caddy_id, policy_id) VALUES (?,?)`, ruleCaddyID, policyID); err != nil {
		t.Fatalf("bind policy %s: %v", name, err)
	}
}

// rdbStrictFindHandler 在路由树内递归查找指定 handler 名。
func rdbStrictFindHandler(v interface{}, want string) bool {
	switch x := v.(type) {
	case map[string]interface{}:
		if h, ok := x["handler"].(string); ok && h == want {
			return true
		}
		for _, vv := range x {
			if rdbStrictFindHandler(vv, want) {
				return true
			}
		}
	case []interface{}:
		for _, vv := range x {
			if rdbStrictFindHandler(vv, want) {
				return true
			}
		}
	}
	return false
}

// Given：deny 策略引用威胁库列表（.iplist 文件缺失）；同规则另一策略无引用。
// When：生成配置。
// Then：未受影响策略照常渲染（geoip 处理器在场）——文件缺失不拖垮整条规则。
func TestRDBStrictRender_threatFileMissingKeepsUnaffectedPolicy(t *testing.T) {
	stubSecurityLibsAvailable(t)
	restoreWaf := OverrideThreatWafDirForTest(t.TempDir()) // 空 waf 目录 → 文件必缺失
	defer restoreWaf()
	_, database := newClusterTestService(t)
	seedHTTPRuleForGeneration(t, database, "lb_rdb1", "rdb1.example.test", 8080)

	listID := rdbStrictSeedThreatList(t, database, "ustc")
	refs, _ := json.Marshal([]int64{listID})
	rdbStrictBindRefPolicy(t, database, "lb_rdb1", "rdb-p1", string(refs))
	mpGenBindPolicy(t, database, "lb_rdb1", "rdb-p2", mpGenPolicySpec{
		mode: "blocking", enabled: true, geoCountries: `["海外"]`,
	})

	rule := mpGenHTTPRule("lb_rdb1", "rdb1.example.test")
	routes, mainRoute := mpGenRoutes(t, database, rule)

	// p2(blocking+geoip)照常渲染：主路由内含其 GeoIP 区域拦截 coraza 指令
	dump, _ := json.Marshal(map[string]interface{}{"routes": routes, "main": mainRoute})
	if !strings.Contains(string(dump), "GeoIP 区域拦截") {
		t.Fatalf("未受影响策略(p2 geoip)必须照常渲染")
	}
	// p1(deny ACL 引用缺失文件)必须被跳过：不得发射 ACL 预检指令
	// （若未跳过，会以空合并集静默收窄——本测试钉住的就是这个不变量）
	if strings.Contains(string(dump), "IP ACL") || strings.Contains(string(dump), "ipListFast") {
		t.Fatalf("引用缺失威胁库的策略(p1)必须被跳过渲染，不得发射 ACL 指令")
	}
}

// Given：.iplist 文件已写盘（模拟更新流程产物）。
// Then：引用策略正常参与渲染（main route 正常生成不 panic）。
func TestRDBStrictRender_threatFilePresentRendersNormally(t *testing.T) {
	stubSecurityLibsAvailable(t)
	wafDir := t.TempDir()
	restoreWaf := OverrideThreatWafDirForTest(wafDir)
	defer restoreWaf()
	_, database := newClusterTestService(t)
	seedHTTPRuleForGeneration(t, database, "lb_rdb2", "rdb2.example.test", 8080)

	listID := rdbStrictSeedThreatList(t, database, "ustc")
	if err := os.WriteFile(filepath.Join(wafDir, "threat-ustc.iplist"), []byte("192.0.2.0/24\n198.51.100.7\n"), 0644); err != nil {
		t.Fatal(err)
	}
	refs, _ := json.Marshal([]int64{listID})
	rdbStrictBindRefPolicy(t, database, "lb_rdb2", "rdb-ok", string(refs))

	rule := mpGenHTTPRule("lb_rdb2", "rdb2.example.test")
	routes, mainRoute := mpGenRoutes(t, database, rule)
	if mainRoute == nil && len(routes) == 0 {
		t.Fatal("路由必须正常生成")
	}
}
