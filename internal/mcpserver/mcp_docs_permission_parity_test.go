package mcpserver_test

import (
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"lazy-balancer-v2/internal/mcpserver"
	"lazy-balancer-v2/internal/services"
)

// docs/mcp.zh-CN.md 的「工具权限」表此前把 3 个读探测 POST 整体算作非管理员
// 可用，实际只有 parse_certificate 挂在非管理员可过的路由组（preview_config/
// validate_import 属 admin 组，调用恒 403 且不出现在 tools/list）。本测试把
// 该行与生产装配派生的「非管理员恒 403」集合机械对账：探测工具在真实路由
// 集合下不可用时，文档必须在含「管理员」的独立子句里点名它；可用时不得带
// 该限定。
func TestMCPDocsNonAdminPermissionRowMatchesRouteSet(t *testing.T) {
	// Given：真实装配——middleware.SetupRouter 在注册期注入生产派生的集合
	_ = newAPIDocTestRouter(t)
	visible := mcpserver.NonAdminVisibleToolNamesForTest()
	probes := mcpserver.ReadOnlyProbeToolNamesForTest()
	if len(probes) != 3 {
		t.Fatalf("只读探测集=%v, want 3 项（探测集形态变化须同步文档口径）", probes)
	}
	// 前提核验：集合确实被注入且 admin 组探测工具在其中（否则对账无意义）
	if _, ok := visible["preview_config"]; ok {
		t.Fatal("前提失效：preview_config 对非管理员可见——SetupRouter 未注入恒 403 集合？")
	}

	row := nonAdminPermissionRow(t)
	if strings.Contains(row, "上述读探测 POST") {
		t.Fatalf("非管理员权限行仍用「上述读探测 POST」整体指代（3 个中仅 1 个可用）: %q", row)
	}
	// 去掉行首「| 非管理员用户 Key |」标签再按子句切分——标签本身含
	// 「管理员」三字，会把第一个子句误判为「需管理员」。
	body := strings.TrimSuffix(strings.TrimPrefix(row, "| 非管理员用户 Key |"), "|")

	// When/Then：逐个探测工具与文档子句对账
	for _, name := range probes {
		clause, found := permissionRowClause(body, name)
		if !found {
			t.Errorf("非管理员权限行未点名探测工具 %s: %q", name, row)
			continue
		}
		_, callable := visible[name]
		requiresAdmin := strings.Contains(clause, "管理员")
		switch {
		case callable && requiresAdmin:
			t.Errorf("文档把可用工具 %s 放进「需管理员」子句: %q", name, clause)
		case !callable && !requiresAdmin:
			t.Errorf("文档未标注 %s 需管理员属主（实际调用恒 403 且不可见）: %q", name, clause)
		}
	}
}

// nonAdminPermissionRow 返回「工具权限」表中非管理员用户 Key 那一行原文。
func nonAdminPermissionRow(t *testing.T) string {
	t.Helper()
	body, err := os.ReadFile(filepath.Join("..", "..", "docs", "mcp.zh-CN.md"))
	if err != nil {
		t.Fatalf("读 docs/mcp.zh-CN.md: %v", err)
	}
	for _, line := range strings.Split(string(body), "\n") {
		if strings.HasPrefix(line, "| 非管理员用户 Key |") {
			return line
		}
	}
	t.Fatal("docs/mcp.zh-CN.md 缺少「非管理员用户 Key」权限行")
	return ""
}

// permissionRowClause 在权限行内按「；」切分子句，返回点名该工具（反引号
// 包裹或裸名）的第一个子句。子句是最小口径单位：同一子句内的限定词作用于
// 其点名的全部工具。
func permissionRowClause(row, tool string) (string, bool) {
	tokens := []string{"`" + tool + "`", tool}
	for _, clause := range strings.Split(row, "；") {
		for _, token := range tokens {
			if strings.Contains(clause, token) {
				return clause, true
			}
		}
	}
	return "", false
}

// 同一权限契约有两处机器可读文本随 initialize / resources/read 下发给 Agent，
// 而人读的 docs/mcp.zh-CN.md 已按 admin 轴修正。只修文档时，非管理员属主的
// Key 仍会按 instructions/手册调用 preview_config、validate_import（恒 403，
// 且根本不在 tools/list），Agent 把「工具不存在/被拒」误判为服务端故障。
// 本测试从生产路由集派生非管理员可见工具，逐文本要求「需管理员」只出现在
// 对非管理员不可用工具的子句里。
func TestMCPRuntimeTextProbeClausesMatchAdminOwnerAxis(t *testing.T) {
	_ = newAPIDocTestRouter(t)
	visible := mcpserver.NonAdminVisibleToolNamesForTest()
	probes := mcpserver.ReadOnlyProbeToolNamesForTest()
	if len(probes) != 3 {
		t.Fatalf("只读探测集=%v, want 3 项（探测集形态变化须同步文本口径）", probes)
	}
	texts := map[string]string{
		"initialize instructions": mcpserver.ServerInstructionsForTest(),
		"ops playbook":            mcpserver.OpsPlaybook(),
	}
	for label, text := range texts {
		for _, probe := range probes {
			clauses := probeClauses(text, probe)
			if len(clauses) == 0 {
				t.Errorf("%s 未提及只读探测工具 %s（探测集与文本须同步）", label, probe)
				continue
			}
			_, callable := visible[probe]
			adminQualified, plain := false, false
			for _, clause := range clauses {
				// 「非管理员」是否定形态，不能当作「需管理员」限定。
				requiresAdmin := strings.Contains(strings.ReplaceAll(clause, "非管理员", ""), "管理员") ||
					strings.Contains(clause, "admin")
				if requiresAdmin {
					adminQualified = true
				} else {
					plain = true
				}
			}
			switch {
			case !callable && !adminQualified:
				t.Errorf("%s 未在「需管理员」子句里点名 %s（实际恒 403 且不在 tools/list）: %q",
					label, probe, clauses[0])
			case callable && !plain:
				t.Errorf("%s 把非管理员可用的 %s 只放进「需管理员」子句: %q", label, probe, clauses[0])
			}
		}
	}
}

// probeClauses 返回文本中所有点名该工具的最细口径子句（按「；」「。」「，」
// 与表格单元格切分）。限定词只作用于其所在子句：同一子句里的工具共享同一
// 限定——「validate_import/preview_config 需 Key 属主为管理员」与「
// parse_certificate 对非管理员开放」必须是两个子句。
func probeClauses(text, tool string) []string {
	var clauses []string
	for _, clause := range strings.FieldsFunc(text, func(r rune) bool {
		switch r {
		case '；', '。', '，', ',', '\n', '|':
			return true
		}
		return false
	}) {
		if strings.Contains(clause, tool) {
			clauses = append(clauses, clause)
		}
	}
	return clauses
}

func TestMCPPlaybookSlavePostExceptionMatchesReadOnlyPolicy(t *testing.T) {
	const slaveContract = "从节点上仅 /cluster/"
	const readOnlyException = "预览/解析/只读查询类 POST 除外"
	var clauses []string
	for _, line := range strings.Split(mcpserver.OpsPlaybook(), "\n") {
		if strings.Contains(line, slaveContract) {
			clauses = append(clauses, line)
			if !strings.Contains(line, readOnlyException) || strings.Contains(line, "测试类 POST") {
				t.Errorf("从节点 POST 例外与只读策略不一致: %q", line)
			}
		}
	}
	if len(clauses) != 2 {
		t.Fatalf("从节点契约出现 %d 处, want 权限表与集群工作流共 2 处", len(clauses))
	}

	for _, route := range []string{
		"POST /api/v1/certificate-configs/test",
		"POST /api/v1/certificate-configs/:id/test",
		"POST /api/v1/ca-providers/:id/test",
	} {
		if services.IsReadOnlyWriteRoute("POST", strings.TrimPrefix(route, "POST ")) {
			t.Errorf("具有写副作用的测试端点不得列入只读豁免: %s", route)
		}
	}
	for _, route := range []string{
		"/api/v1/certificates/parse",
		"/api/v1/config/import/validate",
		"/api/v1/config/preview",
	} {
		if !services.IsReadOnlyWriteRoute(http.MethodPost, route) {
			t.Errorf("只读查询端点缺失既有豁免: POST %s", route)
		}
	}
}
