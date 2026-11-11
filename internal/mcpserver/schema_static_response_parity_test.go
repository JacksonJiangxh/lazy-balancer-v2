package mcpserver

import (
	"encoding/json"
	"fmt"
	"sort"
	"strconv"
	"strings"
	"testing"

	"lazy-balancer-v2/internal/services"
)

// MCP schema ↔ 实现面 parity 钉测（2026-11-11 TASK-2026-1111-01 r2 · 风控官 P1-1）。
//
// 与 internal/handlers/apidocs_static_response_parity_test.go 同族：REST 文档面
// （apidocs）与 MCP 文档面（工具 input_schema）都必须与 services 权威集合同源。
// 两个包互不可见，故各自在自己包内直读真实常量——任一处漂移会在自己那侧变红。
//
// 本文件钉三件事：
//  1. create_rule / update_rule schema 的 response_body.maxLength == handlers 侧
//     staticResponseBodyMaxRunes（此处以包外可核对的固定值 4096 交叉校验：
//     handlers 侧同值由 handlers 包的钉测负责，本文件的职责是「MCP 侧没写错」）；
//  2. schema 文案里声明的状态码枚举集合 == services.StaticResponseStatusCodes()；
//  3. 文案里的「N 码」口径 == 权威集合长度（防 16/17/18/19 多口径并存再犯）。
//
// maxLength 同源断言为何不能直接 import handlers：handlers 依赖 mcpserver 方向
// 不成立（mcpserver 不 import handlers），且 staticResponseBodyMaxRunes 是包私有。
// 故本侧以 runtime 值 + 显式常量 staticResponseBodyMaxRunesExpectation 双锚定：
// 若 handlers 侧改了上限，handlers 侧 parity（apidocs 文案 ≤N 字符）与前端
// ruleValidation.spec.ts 会同时变红，本常量由本文件的失败信息指引同步。

// staticResponseBodyMaxRunesExpectation 是 response_body.maxLength 的期望值。
// 它与 handlers.staticResponseBodyMaxRunes 必须一致；改上限时三处同步
// （handlers 常量、MCP schema、前端 STATIC_RESPONSE_BODY_MAX_RUNES）。
const staticResponseBodyMaxRunesExpectation = 4096

// mcpStaticResponseStatusesFromText 从文案中抽出状态码清单并返回升序切片。
// 只认独立出现的 1xx–5xx 三位数（前后非数字），避免把 4096 之类的数值误收。
func mcpStaticResponseStatusesFromText(text string) []int {
	seen := map[int]bool{}
	runes := []rune(text)
	for index := 0; index+2 < len(runes); index++ {
		if !mcpIsDigit(runes[index]) || !mcpIsDigit(runes[index+1]) || !mcpIsDigit(runes[index+2]) {
			continue
		}
		if index > 0 && mcpIsDigit(runes[index-1]) {
			continue
		}
		if index+3 < len(runes) && mcpIsDigit(runes[index+3]) {
			continue
		}
		code, err := strconv.Atoi(string(runes[index : index+3]))
		if err != nil || code < 100 || code > 599 {
			continue
		}
		seen[code] = true
	}
	codes := make([]int, 0, len(seen))
	for code := range seen {
		codes = append(codes, code)
	}
	sort.Ints(codes)
	return codes
}

func mcpIsDigit(r rune) bool { return r >= '0' && r <= '9' }

// mcpStaticResponseSegment 截出「response_status 支持 …」到最近的终止符之间的文本。
func mcpStaticResponseSegment(t *testing.T, name, text string) string {
	t.Helper()
	const marker = "response_status 支持"
	start := strings.Index(text, marker)
	if start < 0 {
		t.Fatalf("%s: 文案缺少 %q 标记——无法定位状态码枚举段", name, marker)
	}
	rest := text[start+len(marker):]
	end := len(rest)
	for _, terminator := range []string{"，", "；", "）", ")"} {
		if at := strings.Index(rest, terminator); at >= 0 && at < end {
			end = at
		}
	}
	return rest[:end]
}

// TestMCPSchemas_staticResponseDocumentedParity 钉住两份规则 schema 的静态响应
// 文档面与权威集合一致。
//
// 判别力：把 schema 里 maxLength 改回 64、或把码清单删掉/追加一个码、
// 或把「19 码」写错成「17 码」→ 本测必红（已在 r2 自证中实测变红）。
func TestMCPSchemas_staticResponseDocumentedParity(t *testing.T) {
	authority := services.StaticResponseStatusCodes()
	if len(authority) == 0 {
		t.Fatal("services.StaticResponseStatusCodes() 返回空集")
	}

	for name, schema := range map[string]string{"create_rule": createRuleSchema, "update_rule": updateRuleSchema} {
		var decoded map[string]any
		if err := json.Unmarshal([]byte(schema), &decoded); err != nil {
			t.Fatalf("%s: schema 非法 JSON: %v", name, err)
		}
		properties, ok := decoded["properties"].(map[string]any)
		if !ok {
			t.Fatalf("%s: schema 无 properties", name)
		}
		pathRules, ok := properties["path_rules"].(map[string]any)
		if !ok {
			t.Fatalf("%s: schema 缺少 path_rules", name)
		}
		items, ok := pathRules["items"].(map[string]any)
		if !ok {
			t.Fatalf("%s: path_rules 缺少 items", name)
		}
		itemProperties, ok := items["properties"].(map[string]any)
		if !ok {
			t.Fatalf("%s: path_rules.items 缺少 properties", name)
		}

		// ① response_body.maxLength 必须与实现同值。
		body, ok := itemProperties["response_body"].(map[string]any)
		if !ok {
			t.Fatalf("%s: 缺少 response_body 字段", name)
		}
		maxLength, ok := body["maxLength"].(float64)
		if !ok {
			t.Fatalf("%s: response_body 缺少 maxLength（Agent 无法预知长度上限）", name)
		}
		if int(maxLength) != staticResponseBodyMaxRunesExpectation {
			t.Errorf("%s: response_body.maxLength=%v, want %d（须与 handlers.staticResponseBodyMaxRunes 同值；改上限请三处同步）",
				name, maxLength, staticResponseBodyMaxRunesExpectation)
		}

		// ② response_content_type 枚举必须仍与实现一致（改校验忘改 schema 同样漂移）。
		contentType, ok := itemProperties["response_content_type"].(map[string]any)
		if !ok {
			t.Fatalf("%s: 缺少 response_content_type 字段", name)
		}
		enums, _ := contentType["enum"].([]any)
		gotEnums := make([]string, 0, len(enums))
		for _, value := range enums {
			if text, ok := value.(string); ok {
				gotEnums = append(gotEnums, text)
			}
		}
		if want := []string{"", "text/plain", "application/json", "text/html"}; fmt.Sprint(gotEnums) != fmt.Sprint(want) {
			t.Errorf("%s: response_content_type enum=%v, want %v", name, gotEnums, want)
		}

		// ③ schema 全文里声明的「N 码」口径必须等于权威集合长度。
		wantCountToken := fmt.Sprintf("%d 码", len(authority))
		if !strings.Contains(schema, wantCountToken) {
			t.Errorf("%s: schema 文案缺少码数口径 %q（须与权威集合长度一致）", name, wantCountToken)
		}

		// ④ 状态码枚举集合必须与权威集合逐值同集。
		segment := mcpStaticResponseSegment(t, name, schema)
		got := mcpStaticResponseStatusesFromText(segment)
		if fmt.Sprint(got) != fmt.Sprint(authority) {
			t.Errorf("%s: 文案状态码集合与权威集合不同集：\n got = %v\nwant = %v", name, got, authority)
		}

		// ⑤ 上限文案与 201 语义提醒必须落到文档面。
		if want := fmt.Sprintf("≤%d 字符", staticResponseBodyMaxRunesExpectation); !strings.Contains(schema, want) {
			t.Errorf("%s: schema 文案缺少响应体上限 %q", name, want)
		}
		if !strings.Contains(schema, "201") {
			t.Errorf("%s: schema 文案未提及 201（存量兼容码必须在文档面可见，否则用户困惑）", name)
		}
	}
}
