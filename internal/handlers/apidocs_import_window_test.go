package handlers

// 端点文档与实际写门一致性：用户/API Key 写族均受导入窗口 409 保护，
// 文档必须登记同一错误码；改密端点需要区分「当前密码错误」与「会话失效」，
// 且不得宣称可安全重放。

import (
	"net/http"
	"strings"
	"testing"
)

func TestAPIDocRoutes_userAndAPIKeyWritesDocumentImportWindow(t *testing.T) {
	want := []string{
		"POST /users",
		"PUT /users/:id",
		"PUT /users/:id/status",
		"POST /users/:id/reset-password",
		"DELETE /users/:id",
		"PATCH /users/me",
		"POST /users/me/api-keys",
		"PATCH /users/me/api-keys/:id",
		"DELETE /users/me/api-keys/:id",
		"POST /api-keys",
		"PATCH /api-keys/:id/status",
		"DELETE /api-keys/:id",
	}
	index := map[string]apiDocRoute{}
	for _, route := range apiDocRoutes {
		index[route.Method+" "+route.Path] = route
	}
	for _, key := range want {
		route, ok := index[key]
		if !ok {
			t.Fatalf("文档缺少路由 %s", key)
		}
		documented := false
		for _, entry := range route.Errors {
			// 按错误码子串断言：仅检查「存在 409」会被同表的
			// username_exists / last_admin 蒙混过关。
			if strings.Contains(entry, "import_in_progress") {
				documented = true
				break
			}
		}
		if !documented {
			t.Errorf("%s 文档未登记 409 import_in_progress（实际受导入窗口拒绝）errors=%v", key, route.Errors)
		}
	}
}

// 设置类写端点同样受导入窗口拒绝（rejectWriteDuringImport 先于解析/落库），
// 文档必须登记同一 409——否则按规格生成的客户端会把 409 当未知错误重试。
// 名单只覆盖本单元端点：其余写族由各自单元登记。
func TestAPIDocRoutes_settingsWritesDocumentImportWindow(t *testing.T) {
	want := []string{
		"PUT /admin-tls",
		"PUT /settings/auto-backup",
	}
	index := map[string]apiDocRoute{}
	for _, route := range apiDocRoutes {
		index[route.Method+" "+route.Path] = route
	}
	for _, key := range want {
		route, ok := index[key]
		if !ok {
			t.Fatalf("文档缺少路由 %s", key)
		}
		documented := false
		for _, entry := range route.Errors {
			if strings.Contains(entry, "import_in_progress") {
				documented = true
				break
			}
		}
		if !documented {
			t.Errorf("%s 文档未登记 409 import_in_progress（实际受导入窗口拒绝）errors=%v", key, route.Errors)
		}
	}
}

func TestAPIDocRoutes_currentPasswordConfirmationContract(t *testing.T) {
	var route *apiDocRoute
	for i := range apiDocRoutes {
		if apiDocRoutes[i].Method == http.MethodPatch && apiDocRoutes[i].Path == "/users/me" {
			route = &apiDocRoutes[i]
			break
		}
	}
	if route == nil {
		t.Fatal("文档缺少 PATCH /users/me")
	}
	hasCurrentPasswordWrong := false
	for _, entry := range route.Errors {
		if strings.Contains(entry, "current_password_wrong") {
			hasCurrentPasswordWrong = true
			break
		}
	}
	if !hasCurrentPasswordWrong {
		t.Errorf("PATCH /users/me 缺少 401 current_password_wrong（与会话失效不可区分）errors=%v", route.Errors)
	}

	description := operationDescription(*route)
	if !strings.Contains(description, "不可重放") {
		t.Errorf("PATCH /users/me 描述未声明不可重放语义: %q", description)
	}
	if strings.Contains(description, "可安全重试：相同请求重复调用保持相同目标状态") {
		t.Errorf("PATCH /users/me 仍沿用幂等 PATCH 组文案（改密后旧令牌立即失效）: %q", description)
	}
	// 同组其余 PATCH 端点不受影响，仍为幂等语义。
	for _, key := range []string{"PATCH /users/me/api-keys/:id", "PATCH /api-keys/:id/status"} {
		methodPath := strings.SplitN(key, " ", 2)
		for _, other := range apiDocRoutes {
			if other.Method != methodPath[0] || other.Path != methodPath[1] {
				continue
			}
			if !strings.Contains(operationDescription(other), "可安全重试") {
				t.Errorf("%s 应保持幂等重试文案: %q", key, operationDescription(other))
			}
		}
	}
}
