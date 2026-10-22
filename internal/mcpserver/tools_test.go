package mcpserver

import (
	"encoding/json"
	"net/http"
	"strings"
	"testing"
)

// 通用绊线——pathArgs/queryArgs 是转发器实际取值依据，
// 必须全部出现在该工具的 input_schema.properties 中。
// 同类缺陷此前只靠单工具测试兜底。删除
// bodySchema 豁免——宽松 body 形态同样必须声明路径参数（此前 8 个「按 id
// 更新」工具声明 pathArgs 却让 schema 只留 additionalProperties，Agent 只能
// 凭描述猜 id）。工具统一用 bodySchemaWithID 声明。
func TestEveryToolSchemaCoversPathAndQueryArgs(t *testing.T) {
	checked := 0
	for _, spec := range tools {
		var shape struct {
			Properties map[string]json.RawMessage `json:"properties"`
		}
		if err := json.Unmarshal([]byte(spec.schema), &shape); err != nil {
			t.Errorf("tool %s schema is not valid JSON: %v", spec.name, err)
			continue
		}
		args := make([]string, 0, len(spec.pathArgs)+len(spec.queryArgs))
		args = append(args, spec.pathArgs...)
		args = append(args, spec.queryArgs...)
		for _, arg := range args {
			if _, ok := shape.Properties[arg]; !ok {
				t.Errorf("tool %s (%s %s) declares %q as path/query arg but input_schema lacks it: %s", spec.name, spec.method, spec.path, arg, spec.schema)
			}
			checked++
		}
	}
	if checked == 0 {
		t.Fatal("no path/query args checked——schema 解析形态失效")
	}
}

// 单/少字段写工具的 schema 必须声明 properties/required
// （保留 additionalProperties 兼容性），否则 Agent 只能凭描述猜字段名，错名
// 由 REST 侧返回 400。
func TestSmallWriteToolSchemasDeclareFields(t *testing.T) {
	cases := []struct {
		name       string
		required   []string
		properties []string
	}{
		{"toggle_crs_auto_update", []string{"auto_update"}, []string{"auto_update"}},
		{"toggle_ip2region_auto_update", []string{"auto_update"}, []string{"auto_update"}},
		{"toggle_user_status", []string{"id", "is_enabled"}, []string{"id", "is_enabled"}},
		{"set_cluster_mode", []string{"mode", "master_url", "register_token"}, []string{"mode", "master_url", "register_token", "node_name"}},
		{"update_cluster_settings", nil, []string{"sync_interval", "sync_users", "sync_rules", "sync_security"}},
		{"parse_certificate", []string{"cert_pem", "key_pem"}, []string{"cert_pem", "key_pem"}},
		{"update_node_access_url", []string{"id", "access_url"}, []string{"id", "access_url"}},
		{"update_ca_provider", []string{"id"}, []string{"id", "name", "provider", "credentials", "max_concurrent", "min_interval_ms", "enabled"}},
		{"update_admin_tls", nil, []string{"enabled", "mode", "cert_file", "key_file"}},
		{"inspect_admin_tls", []string{"cert_file", "key_file"}, []string{"cert_file", "key_file"}},
	}
	byName := make(map[string]toolSpec, len(tools))
	for _, spec := range tools {
		byName[spec.name] = spec
	}
	for _, testCase := range cases {
		spec, ok := byName[testCase.name]
		if !ok {
			t.Errorf("tool %s not registered", testCase.name)
			continue
		}
		var shape struct {
			Required             []string                   `json:"required"`
			Properties           map[string]json.RawMessage `json:"properties"`
			AdditionalProperties *bool                      `json:"additionalProperties"`
		}
		if err := json.Unmarshal([]byte(spec.schema), &shape); err != nil {
			t.Errorf("tool %s schema is not valid JSON: %v", testCase.name, err)
			continue
		}
		for _, property := range testCase.properties {
			if _, ok := shape.Properties[property]; !ok {
				t.Errorf("tool %s schema lacks property %q: %s", testCase.name, property, spec.schema)
			}
		}
		for _, required := range testCase.required {
			if !containsString(shape.Required, required) {
				t.Errorf("tool %s schema required=%v, want %q", testCase.name, shape.Required, required)
			}
		}
		if shape.AdditionalProperties == nil || !*shape.AdditionalProperties {
			t.Errorf("tool %s schema additionalProperties=%v, want true（向前兼容）", testCase.name, shape.AdditionalProperties)
		}
	}
}

func TestRuleToolSchemasDeclareNestedItemContracts(t *testing.T) {
	// Given：create/update 两工具的真实 input_schema。
	type schemaNode struct {
		Required   []string                   `json:"required"`
		Properties map[string]json.RawMessage `json:"properties"`
		Items      *schemaNode                `json:"items"`
	}
	for _, testCase := range []struct {
		name   string
		schema string
	}{{"create_rule", createRuleSchema}, {"update_rule", updateRuleSchema}} {
		t.Run(testCase.name, func(t *testing.T) {
			decode := func(raw json.RawMessage) schemaNode {
				t.Helper()
				var node schemaNode
				if len(raw) == 0 {
					return node
				}
				if err := json.Unmarshal(raw, &node); err != nil {
					t.Fatalf("decode schema: %v", err)
				}
				return node
			}
			root := decode(json.RawMessage(testCase.schema))
			property := func(node schemaNode, name string) schemaNode {
				t.Helper()
				raw, ok := node.Properties[name]
				if !ok {
					t.Errorf("schema lacks property %q", name)
					return schemaNode{}
				}
				return decode(raw)
			}
			items := func(node schemaNode) schemaNode {
				t.Helper()
				if node.Items == nil {
					t.Errorf("array schema lacks items")
					return schemaNode{}
				}
				return *node.Items
			}
			require := func(node schemaNode, fields ...string) {
				t.Helper()
				for _, field := range fields {
					if !containsString(node.Required, field) {
						t.Errorf("schema required=%v, want %q", node.Required, field)
					}
				}
			}

			// Then：path_rules 全字段、匹配必填与嵌套上游契约可见。
			pathItems := items(property(root, "path_rules"))
			require(pathItems, "match_type", "path")
			for _, field := range []string{"id", "sort_order", "match_type", "path", "upstream_path", "response_mode", "response_status", "response_body", "response_content_type", "redirect_to", "upstreams"} {
				if _, ok := pathItems.Properties[field]; !ok {
					t.Errorf("path_rules.items lacks property %q", field)
				}
			}
			pathUpstreamItems := items(property(pathItems, "upstreams"))
			require(pathUpstreamItems, "address", "port")
			for _, field := range []string{"address", "port", "weight", "protocol"} {
				if _, ok := pathUpstreamItems.Properties[field]; !ok {
					t.Errorf("path upstream items lacks property %q", field)
				}
			}

			// And：主 upstreams 在 create（回归）与 update（目标）均完整声明。
			upstreamItems := items(property(root, "upstreams"))
			require(upstreamItems, "host", "port")
			for _, field := range []string{"host", "port", "weight", "enabled", "protocol", "max_connections", "origin_domain"} {
				if _, ok := upstreamItems.Properties[field]; !ok {
					t.Errorf("upstreams.items lacks property %q", field)
				}
			}
		})
	}
}

// control_system_task 的 schema enum、handler 接受集
// （taskmonitor.go ControlSystemTask：start/stop/restart）与描述必须一致，
// 并说明与 toggle_system_task 的分工。
func TestControlSystemTaskSchemaMatchesHandlerActionSet(t *testing.T) {
	var shape struct {
		Properties struct {
			Action struct {
				Enum []string `json:"enum"`
			} `json:"action"`
		} `json:"properties"`
	}
	if err := json.Unmarshal([]byte(controlTaskSchema), &shape); err != nil {
		t.Fatalf("parse controlTaskSchema: %v", err)
	}
	want := []string{"start", "stop", "restart"}
	if len(shape.Properties.Action.Enum) != len(want) {
		t.Fatalf("controlTaskSchema enum=%v, want %v", shape.Properties.Action.Enum, want)
	}
	for _, action := range want {
		if !containsString(shape.Properties.Action.Enum, action) {
			t.Errorf("controlTaskSchema enum=%v, want %q", shape.Properties.Action.Enum, action)
		}
	}
	var spec *toolSpec
	for index := range tools {
		if tools[index].name == "control_system_task" {
			spec = &tools[index]
			break
		}
	}
	if spec == nil {
		t.Fatal("control_system_task not registered")
	}
	for _, action := range want {
		if !strings.Contains(spec.description, action) {
			t.Errorf("control_system_task description=%q lacks action %q", spec.description, action)
		}
	}
	if !strings.Contains(spec.description, "toggle_system_task") {
		t.Errorf("control_system_task description=%q lacks toggle_system_task division note", spec.description)
	}
	if strings.Contains(spec.description, "仅 restart") || strings.Contains(spec.description, "action=restart——启停已由调度开关承担") {
		t.Errorf("control_system_task description=%q retains stale restart-only wording", spec.description)
	}
}

func TestMCPToolDescriptionsCurrentContracts(t *testing.T) {
	byName := make(map[string]toolSpec, len(tools))
	for _, spec := range tools {
		byName[spec.name] = spec
	}
	trigger := byName["trigger_system_task"]
	if strings.Contains(trigger.schema, "can_trigger") || !strings.Contains(trigger.schema, "triggerable") {
		t.Errorf("trigger_system_task schema=%s, want DTO field triggerable and no can_trigger", trigger.schema)
	}
	cert := byName["list_certificates"]
	if !strings.Contains(cert.description, "每规则每域名最新") {
		t.Errorf("list_certificates description=%q, want per-rule per-domain latest semantics", cert.description)
	}
	if usage := toolUsage["list_certificates"]; !strings.Contains(usage, "每规则每域名最新") {
		t.Errorf("list_certificates usage=%q, want per-rule per-domain latest semantics", usage)
	}
}

func containsString(values []string, target string) bool {
	for _, value := range values {
		if value == target {
			return true
		}
	}
	return false
}

func TestListToolSpecs_returns_sanitized_independent_copy(t *testing.T) {
	// Given
	first := ListToolSpecs()

	// When
	first[0].Name = "changed_by_caller"
	second := ListToolSpecs()
	encoded, err := json.Marshal(second)

	// Then
	if err != nil {
		t.Fatalf("marshal public tool specs: %v", err)
	}
	if len(second) != len(tools) {
		t.Fatalf("tool count=%d, want %d", len(second), len(tools))
	}
	if second[0].Name == "changed_by_caller" {
		t.Fatal("ListToolSpecs returned caller-mutable registry state")
	}
	if strings.Contains(string(encoded), "path_args") || strings.Contains(string(encoded), "query_args") {
		t.Fatalf("public registry leaks internal fields: %s", encoded)
	}
	for index, spec := range second {
		if spec.Name == "" || spec.Description == "" || spec.Method == "" || !strings.HasPrefix(spec.Path, "/api/v1/") {
			t.Fatalf("tool %d has incomplete public metadata: %+v", index, spec)
		}
		_, probe := ReadOnlyProbeTools[spec.Name]
		_, hidden := readOnlyHiddenTools[spec.Name]
		if wantReadOnly := (spec.Method == http.MethodGet && !hidden) || probe; spec.ReadOnly != wantReadOnly {
			t.Fatalf("tool %s read_only=%v method=%s probe=%v hidden=%v, want %v", spec.Name, spec.ReadOnly, spec.Method, probe, hidden, wantReadOnly)
		}
		if len(spec.InputSchema) > 0 {
			var shape map[string]any
			if err := json.Unmarshal(spec.InputSchema, &shape); err != nil || shape["type"] != "object" {
				t.Fatalf("tool %s input_schema is not a valid JSON schema object: %s", spec.Name, spec.InputSchema)
			}
		}
	}
}

// 高风险写工具的 body 字段契约——运行时 schema 校验刻意关闭，input_schema 是
// Agent 唯一构参契约；零字段契约（裸 additionalProperties）只能靠描述猜名。
// 每工具至少声明高频字段与必填项（additionalProperties:true 保留向前兼容）。
func TestWriteToolSchemasDeclareBodyFields(t *testing.T) {
	cases := []struct {
		name       string
		required   []string
		properties []string
	}{
		{"create_security_policy", []string{"name"}, []string{"name", "mode", "policy_type", "anomaly_threshold", "ip_acl_enabled", "rate_limit_enabled", "geoip_mode", "crs_rule_groups", "custom_rules", "block_page_id", "enabled"}},
		{"update_security_policy", []string{"id"}, []string{"id", "name", "mode", "policy_type", "enabled"}},
		{"create_custom_rule", []string{"name", "conditions", "action", "score"}, []string{"name", "conditions", "action", "score", "enabled"}},
		{"update_custom_rule", []string{"id"}, []string{"id", "name", "conditions", "action", "score", "enabled"}},
		{"create_block_page", []string{"name", "content"}, []string{"name", "content", "content_type", "description"}},
		{"update_block_page", []string{"id"}, []string{"id", "name", "content", "content_type"}},
		{"create_ip_list", []string{"name"}, []string{"name", "description", "category", "entries"}},
		{"update_ip_list", []string{"id"}, []string{"id", "name", "entries"}},
		{"create_certificate_config", []string{"name", "dns_provider"}, []string{"name", "dns_provider", "dns_credentials", "enabled"}},
		{"update_certificate_config", []string{"id"}, []string{"id", "name", "dns_provider", "dns_credentials", "enabled"}},
		{"create_user", []string{"username", "password", "role"}, []string{"username", "password", "role", "display_name"}},
		{"update_user", []string{"id"}, []string{"id", "username", "role", "display_name", "password"}},
		{"create_api_key", []string{"name"}, []string{"name", "expires_at", "mcp_enabled", "read_only", "mcp_ip_whitelist"}},
		{"update_api_key_status", []string{"id"}, []string{"id", "is_enabled", "mcp_enabled", "read_only", "mcp_ip_whitelist"}},
		{"bind_security_policy", []string{"id", "rule_caddy_id"}, []string{"id", "rule_caddy_id"}},
		{"remove_ip_from_list", []string{"id", "value"}, []string{"id", "value"}},
		{"preview_config", nil, []string{"source"}},
		{"import_config", nil, []string{"meta", "config", "tables"}},
		{"validate_import", nil, []string{"meta", "config", "tables"}},
	}
	byName := make(map[string]toolSpec, len(tools))
	for _, spec := range tools {
		byName[spec.name] = spec
	}
	for _, testCase := range cases {
		spec, ok := byName[testCase.name]
		if !ok {
			t.Errorf("tool %s not registered", testCase.name)
			continue
		}
		var shape struct {
			Required   []string                   `json:"required"`
			Properties map[string]json.RawMessage `json:"properties"`
		}
		if err := json.Unmarshal([]byte(spec.schema), &shape); err != nil {
			t.Errorf("tool %s schema is not valid JSON: %v", testCase.name, err)
			continue
		}
		for _, property := range testCase.properties {
			if _, ok := shape.Properties[property]; !ok {
				t.Errorf("tool %s schema lacks property %q", testCase.name, property)
			}
		}
		for _, required := range testCase.required {
			if !containsString(shape.Required, required) {
				t.Errorf("tool %s schema required=%v, want %q", testCase.name, shape.Required, required)
			}
		}
	}
	// 无 body 工具不得再背宽松 body schema——create_register_token 无需请求体。
	if spec := byName["create_register_token"]; spec.schema != emptySchema {
		t.Errorf("create_register_token schema=%s, want emptySchema（handler 不读 body）", spec.schema)
	}
}

// schema 边界与写侧校验对齐（Agent 唯一契约，运行时无校验兜底）：
// update 与 create 同名字段边界对称；枚举/上下限与后端 400 校验一致。
func TestWriteToolSchemaBoundsMatchBackendValidation(t *testing.T) {
	type bounds struct {
		Minimum *float64  `json:"minimum"`
		Maximum *float64  `json:"maximum"`
		Enum    []float64 `json:"enum"`
	}
	node := func(t *testing.T, schema string, path ...string) bounds {
		t.Helper()
		var root map[string]json.RawMessage
		if err := json.Unmarshal([]byte(schema), &root); err != nil {
			t.Fatalf("parse schema: %v", err)
		}
		var current map[string]json.RawMessage
		if err := json.Unmarshal(root["properties"], &current); err != nil || current == nil {
			t.Fatalf("schema lacks top-level properties")
		}
		for i, segment := range path {
			raw, ok := current[segment]
			if !ok {
				t.Fatalf("schema path %v 缺 %q", path[:i+1], segment)
			}
			if i == len(path)-1 {
				var result bounds
				if err := json.Unmarshal(raw, &result); err != nil {
					t.Fatalf("parse bounds: %v", err)
				}
				return result
			}
			var next map[string]json.RawMessage
			if err := json.Unmarshal(raw, &next); err != nil {
				t.Fatalf("parse intermediate: %v", err)
			}
			var props map[string]json.RawMessage
			if err := json.Unmarshal(next["properties"], &props); err == nil && props != nil {
				current = props
				continue
			}
			var items map[string]json.RawMessage
			if err := json.Unmarshal(next["items"], &items); err == nil && items != nil {
				var itemProps map[string]json.RawMessage
				if err := json.Unmarshal(items["properties"], &itemProps); err == nil && itemProps != nil {
					current = itemProps
					continue
				}
				current = items
				continue
			}
			t.Fatalf("schema path %v 在 %q 处无 properties/items", path, segment)
		}
		return bounds{}
	}
	for _, testCase := range []struct {
		name   string
		schema string
		path   []string
		min    float64
		max    float64
	}{
		{"create_rule listen_port", createRuleSchema, []string{"listen_port"}, 1, 65535},
		{"update_rule listen_port", updateRuleSchema, []string{"listen_port"}, 1, 65535},
		{"create_rule upstreams.port", createRuleSchema, []string{"upstreams", "port"}, 1, 65535},
		{"update_rule upstreams.port", updateRuleSchema, []string{"upstreams", "port"}, 1, 65535},
	} {
		got := node(t, testCase.schema, testCase.path...)
		if got.Minimum == nil || *got.Minimum != testCase.min || got.Maximum == nil || *got.Maximum != testCase.max {
			t.Errorf("%s bounds=%+v, want %v-%v", testCase.name, got, testCase.min, testCase.max)
		}
	}
	// server_tokens_hidden ∈ {0,1,2}（rules.go 写侧校验同口径），create/update 对称。
	for _, testCase := range []struct {
		name   string
		schema string
	}{{"create_rule", createRuleSchema}, {"update_rule", updateRuleSchema}} {
		got := node(t, testCase.schema, "server_tokens_hidden")
		if len(got.Enum) != 3 {
			t.Errorf("%s server_tokens_hidden enum=%v, want [0,1,2]", testCase.name, got.Enum)
		}
	}
	// CA 提供商上限（caproviders 写侧 ≤100/≤60000 同口径）。
	if got := node(t, updateCAProviderSchema, "max_concurrent"); got.Maximum == nil || *got.Maximum != 100 {
		t.Errorf("update_ca_provider max_concurrent bounds=%+v, want maximum 100", got)
	}
	if got := node(t, updateCAProviderSchema, "min_interval_ms"); got.Maximum == nil || *got.Maximum != 60000 {
		t.Errorf("update_ca_provider min_interval_ms bounds=%+v, want maximum 60000", got)
	}
	// 大屏坐标经纬度边界（caddy.go 写侧严格校验同口径）。
	if got := node(t, updateConfigSchema, "server_map_lat"); got.Minimum == nil || *got.Minimum != -90 || got.Maximum == nil || *got.Maximum != 90 {
		t.Errorf("update_config server_map_lat bounds=%+v, want -90~90", got)
	}
	if got := node(t, updateConfigSchema, "server_map_lon"); got.Minimum == nil || *got.Minimum != -180 || got.Maximum == nil || *got.Maximum != 180 {
		t.Errorf("update_config server_map_lon bounds=%+v, want -180~180", got)
	}
}

// export_config 是恒失败工具（备份为 lbbak 二进制，MCP 通道不支持）——描述
// 必须明示，Agent 不应把它当可用导出路径反复调用。
func TestExportConfigToolDocumentsAlwaysGuidance(t *testing.T) {
	for _, spec := range tools {
		if spec.name != "export_config" {
			continue
		}
		if !strings.Contains(spec.description, "MCP 通道不支持二进制") {
			t.Errorf("export_config description=%q, want 明示 MCP 通道恒返回下载指引", spec.description)
		}
		return
	}
	t.Fatal("export_config tool not registered")
}
