package mcpserver

// MCP 的 input_schema 是 Agent 唯一构参契约（运行时 schema 校验刻意关闭，
// 见 server.go 的 tool spec 注释）：描述里的长度/字符集若与 handlers 的真实
// 写侧校验不一致，Agent 会按契约生成必被 REST 400 拒绝的参数。此前
// create_user 写「用户名（3-50 字符）」「初始密码（≤72 字符）」，而策略是
// 8-24 个可打印 ASCII + 小写字母开头的用户名——按 schema 生成的 25 位密码
// 或含下划线/大写的用户名 100% 收 400。

import (
	"encoding/json"
	"regexp"
	"strconv"
	"strings"
	"testing"
)

// schemaPropertyDescription 取某个 tool schema 字段的 description。
func schemaPropertyDescription(t *testing.T, tool, schema, property string) string {
	t.Helper()
	var shape struct {
		Properties map[string]struct {
			Description string `json:"description"`
		} `json:"properties"`
	}
	if err := json.Unmarshal([]byte(schema), &shape); err != nil {
		t.Fatalf("%s schema 解析失败: %v", tool, err)
	}
	field, ok := shape.Properties[property]
	if !ok {
		t.Fatalf("%s schema 未声明 %s", tool, property)
	}
	return field.Description
}

func TestUserToolSchemasMatchPasswordAndUsernamePolicy(t *testing.T) {
	authSource := readHandlerSource(t, "auth.go")

	minMatch := regexp.MustCompile(`minPasswordLength = ([0-9]+)`).FindStringSubmatch(authSource)
	maxMatch := regexp.MustCompile(`maxPasswordLength = ([0-9]+)`).FindStringSubmatch(authSource)
	if minMatch == nil || maxMatch == nil {
		t.Fatal("未找到 minPasswordLength/maxPasswordLength（密码策略常量形态变化，扫描器需跟进）")
	}
	minLength, maxLength := minMatch[1], maxMatch[1]

	usernameMatch := regexp.MustCompile("var usernamePolicyRe = regexp.MustCompile\\(`([^`]+)`\\)").FindStringSubmatch(authSource)
	if usernameMatch == nil {
		t.Fatal("未找到 usernamePolicyRe（用户名策略形态变化，扫描器需跟进）")
	}
	usernamePattern := usernameMatch[1]
	allowsUppercase := strings.Contains(usernamePattern, "A-Z")
	allowsDigits := strings.Contains(usernamePattern, "0-9")

	for _, tool := range []struct {
		name   string
		schema string
	}{
		{"create_user", createUserSchema},
		{"update_user", updateUserSchema},
	} {
		password := schemaPropertyDescription(t, tool.name, tool.schema, "password")
		if !strings.Contains(password, minLength) || !strings.Contains(password, maxLength) {
			t.Errorf("%s password 描述=%q，未同时给出策略长度 %s-%s（REST validatePasswordPolicy 会 400）",
				tool.name, password, minLength, maxLength)
		}
		if !strings.Contains(password, "ASCII") {
			t.Errorf("%s password 描述=%q，未说明仅可打印 ASCII（汉字/其他非 ASCII 会被 400）", tool.name, password)
		}
		if strings.Contains(password, "72") {
			t.Errorf("%s password 描述=%q，仍引用 bcrypt 物理上限 72（策略上限 %s 先行拦截，会误导 Agent 生成超长密码）",
				tool.name, password, maxLength)
		}
		if _, err := strconv.Atoi(minLength); err != nil {
			t.Fatalf("minPasswordLength=%q 非数字", minLength)
		}

		username := schemaPropertyDescription(t, tool.name, tool.schema, "username")
		if !strings.Contains(username, "小写字母") {
			t.Errorf("%s username 描述=%q，未说明必须小写字母开头（usernamePolicyRe=%s）", tool.name, username, usernamePattern)
		}
		if allowsDigits && !strings.Contains(username, "数字") {
			t.Errorf("%s username 描述=%q，未说明允许数字（usernamePolicyRe=%s）", tool.name, username, usernamePattern)
		}
		if !allowsUppercase && !strings.Contains(username, "不接受大写") && !strings.Contains(username, "不允许大写") {
			t.Errorf("%s username 描述=%q，未声明不接受大写（usernamePolicyRe=%s）", tool.name, username, usernamePattern)
		}
	}
}
