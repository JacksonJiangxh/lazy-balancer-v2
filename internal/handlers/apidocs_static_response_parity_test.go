package handlers

import (
	"fmt"
	"sort"
	"strconv"
	"strings"
	"testing"

	"lazy-balancer-v2/internal/services"
)

// 文档面 ↔ 实现面 parity 钉测（2026-11-11 TASK-2026-1111-01 r2 · 风控官 P1-1）。
//
// 为什么需要本文件：S12 要求「API/MCP 文档面同步」，r1 却只在 apidocs.go /
// mcpserver/server.go 里手改了文案，全仓无任何测试校验文档面与权威集合一致。
// 结果是「改了没人守」——一旦增删状态码或调整响应体上限，文档面会静默漂移，
// 用户按文档写配置将直接吃 400，或按文档填超长内容被拒。
//
// 权威来源（唯一真值）：services.StaticResponseStatusCodes() 与
// handlers.staticResponseBodyMaxRunes。任何文档面（REST apidocs / MCP schema）
// 与其不一致即红。
//
// 分文件说明：createRuleSchema 在 mcpserver 包内、apiDocRoutes 在 handlers 包内，
// 两者互不可见（且 handlers→mcpserver 的依赖方向不允许反向）。故 parity 拆成
// 一对同族钉测，各自在自己包内直读真实常量，共享同一套断言口径：
//   - internal/handlers/apidocs_static_response_parity_test.go（本文件，REST 文档面）
//   - internal/mcpserver/schema_static_response_parity_test.go（MCP schema 文档面）
// 两侧都以 services.StaticResponseStatusCodes() 为基准，故任一处漂移都会在
// 它自己那一侧变红。

// staticResponseCodeSetFromText 从一段文案里抽出全部三位状态码，返回升序切片。
// 只认 1xx–5xx 且必须独立出现（前后非数字），避免把「4096」「17」等误当状态码。
func staticResponseCodeSetFromText(text string) []int {
	seen := map[int]bool{}
	runes := []rune(text)
	for index := 0; index+2 < len(runes); index++ {
		if !isASCIIDigit(runes[index]) || !isASCIIDigit(runes[index+1]) || !isASCIIDigit(runes[index+2]) {
			continue
		}
		// 前一位或后一位仍是数字 → 这是更长数字的一部分，跳过。
		if index > 0 && isASCIIDigit(runes[index-1]) {
			continue
		}
		if index+3 < len(runes) && isASCIIDigit(runes[index+3]) {
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

func isASCIIDigit(r rune) bool { return r >= '0' && r <= '9' }

// assertSameIntSet 断言 got 与 want 逐值同集（升序比较），不一致时打印差值明细。
func assertSameIntSet(t *testing.T, label string, got, want []int) {
	t.Helper()
	if fmt.Sprint(got) == fmt.Sprint(want) {
		return
	}
	t.Errorf("%s 与权威集合不同集：\n got = %v\nwant = %v", label, got, want)
}

// TestAPIDocs_staticResponseCodesMatchAuthority 钉住 apidocs 的 /rules notes：
// 其中列举的状态码集合必须与 services.StaticResponseStatusCodes() 逐值同集，
// 且必须写明响应体上限（≤4096 字符）。
//
// 判别力：把 apidocs.go 里码清单删掉一个码（或把 ≤4096 改成 ≤64）→ 本测必红。
func TestAPIDocs_staticResponseCodesMatchAuthority(t *testing.T) {
	authority := services.StaticResponseStatusCodes()
	if len(authority) == 0 {
		t.Fatal("services.StaticResponseStatusCodes() 返回空集——权威集合不能为空")
	}

	var notes string
	for _, route := range apiDocRoutes {
		if route.Method == "GET" && route.Path == "/rules" {
			notes = route.Description
			break
		}
	}
	if notes == "" {
		t.Fatal("apidocs 未找到 GET /rules 的描述（notes）——文档面缺失")
	}

	// ① 文案里必须出现「N 码」且 N == 权威集合长度（口径统一，见 P2-1）。
	wantCountToken := fmt.Sprintf("%d 码", len(authority))
	if !strings.Contains(notes, wantCountToken) {
		t.Errorf("/rules notes 缺少码数口径 %q（apidocs 文案必须写明实际码数）", wantCountToken)
	}

	// ② 码枚举集合必须与权威集合逐值同集。
	//
	// 只取「状态码清单」那一段（response_status 支持 … 之后、分号之前），避免
	// 把同一条 notes 里其它语义中的三位数字（如 tcp_proxy_protocol 的 v2、
	// 端口范围等）混入集合。
	segment := staticResponseStatusSegment(t, notes)
	assertSameIntSet(t, "/rules notes 状态码清单", staticResponseCodeSetFromText(segment), authority)

	// ③ 响应体上限文案必须与实现同值。
	wantLimitToken := fmt.Sprintf("≤%d 字符", staticResponseBodyMaxRunes)
	if !strings.Contains(notes, wantLimitToken) {
		t.Errorf("/rules notes 缺少响应体上限文案 %q（实现值 %d）——文档面与实现漂移",
			wantLimitToken, staticResponseBodyMaxRunes)
	}
}

// staticResponseStatusSegment 从 /rules notes 中截出状态码清单那一段：
// 以「response_status 支持」起、以紧随其后的「，」或「；」止。
//
// 取这一段而不是全文，是为了让断言精确指向「文档声明的状态码枚举」，
// 同时避免同段落中其它数字（0=缺省 200 等）污染集合比对。
func staticResponseStatusSegment(t *testing.T, notes string) string {
	t.Helper()
	const marker = "response_status 支持"
	start := strings.Index(notes, marker)
	if start < 0 {
		t.Fatalf("/rules notes 缺少 %q 标记——无法定位状态码枚举段", marker)
	}
	rest := notes[start+len(marker):]
	end := len(rest)
	for _, terminator := range []string{"，", "；", "）", ")"} {
		if at := strings.Index(rest, terminator); at >= 0 && at < end {
			end = at
		}
	}
	return rest[:end]
}

// TestStaticResponseDeprecatedSemanticsAreWhitelisted 钉住「warn 提示表 ⊆ 白名单」：
// 201 之类的语义提醒码必须仍在可保存集合内，否则「提醒」会变成废话
// （保存早已被拒，用户看不到日志）。
func TestStaticResponseDeprecatedSemanticsAreWhitelisted(t *testing.T) {
	authority := map[int]bool{}
	for _, code := range services.StaticResponseStatusCodes() {
		authority[code] = true
	}
	for code, hint := range staticResponseDeprecatedSemantics {
		if !authority[code] {
			t.Errorf("状态码 %d 登记了语义提醒（%s），但不在可保存白名单内——提醒无意义", code, hint)
		}
		if !validStaticResponseStatuses[code] {
			t.Errorf("状态码 %d 登记了语义提醒，但不在 handlers 校验白名单内", code)
		}
	}
	// 201 必须登记（r2 裁决的落点）；文案须说明语义偏差与建议动作。
	hint, exists := staticResponseDeprecatedSemantics[201]
	if !exists {
		t.Fatal("201 必须登记语义提醒（r2 总经理裁决：放行 + warn）")
	}
	for _, required := range []string{"201", "已创建资源", "不创建资源", "建议改用 200"} {
		if !strings.Contains(hint, required) {
			t.Errorf("201 提醒文案缺少要素 %q，当前：%q", required, hint)
		}
	}
}
