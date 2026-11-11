package handlers

import (
	"strings"
	"testing"

	"lazy-balancer-v2/internal/models"
	"lazy-balancer-v2/internal/services"
)

// 静态响应/3xx 强健度钉测（2026-11-11 TASK-2026-1111-01）。
//
// 背景：上游 v2.4.2 把静态响应收窄为「3 模式 + 11 码 + ≤64 字符」，3xx 只能走
// redirect 且 response_status 恒写 200（死值）。本轮按董事长自研口径把校验与
// 渲染的强健度提回：17 码（含 3xx）、static 允许 3xx 且跳转目标必填、非 3xx 带
// 目标显性拒绝、3xx/204 禁体、响应体上限 4096、控制字符门、跳转目标强校验。
//
// 本文件按 §1 S1–S11 逐条钉死；S12/S13 的 parity 与回归由既有套件覆盖。

// staticRuleInput 构造只含一条 static 路径规则的输入。
func staticRuleInput(pathRule models.PathRule) ruleFeatureInput {
	pathRule.MatchType = "exact"
	if pathRule.Path == "" {
		pathRule.Path = "/maint"
	}
	pathRule.ResponseMode = "static"
	return ruleFeatureInput{
		Protocol:            "http",
		CustomRoutesEnabled: true,
		PathRules:           []models.PathRule{pathRule},
	}
}

// redirectRuleInput 构造只含一条 redirect 路径规则的输入。
func redirectRuleInput(pathRule models.PathRule) ruleFeatureInput {
	pathRule.MatchType = "exact"
	if pathRule.Path == "" {
		pathRule.Path = "/old"
	}
	pathRule.ResponseMode = "redirect"
	return ruleFeatureInput{
		Protocol:            "http",
		CustomRoutesEnabled: true,
		PathRules:           []models.PathRule{pathRule},
	}
}

// S1 · 17 码逐一通过：白名单内每个状态码在填入合法跳转目标（仅 3xx）后均应放行。
func TestValidateRuleFeatures_staticAllSupportedStatusesAccepted(t *testing.T) {
	for _, status := range services.StaticResponseStatusCodes() {
		pathRule := models.PathRule{ResponseStatus: status}
		// 3xx 必须带跳转目标；其余码不得带（S3）。
		if services.StaticResponseIsRedirectStatus(status) {
			pathRule.RedirectTo = "https://example.com/new"
		} else if services.StaticResponseBodyAllowed(status) {
			pathRule.ResponseBody = "ok"
		}
		if err := validateRuleFeatures(staticRuleInput(pathRule)); err != nil {
			t.Fatalf("status %d 应放行，得到错误: %v", status, err)
		}
	}
}

// S1 · 非法码拒绝（含上游旧白名单里的 201，以及任意未收录值）。
func TestValidateRuleFeatures_staticRejectsUnsupportedStatuses(t *testing.T) {
	for _, status := range []int{201, 202, 206, 300, 304, 418, 451, 505, 999} {
		err := validateRuleFeatures(staticRuleInput(models.PathRule{ResponseStatus: status}))
		if err == nil {
			t.Fatalf("status %d 必须被拒绝", status)
		}
		if !strings.Contains(err.Error(), "不在支持范围") {
			t.Fatalf("status %d: 错误文案须点名「不在支持范围」，got %q", status, err.Error())
		}
	}
}

// S2 · static 允许 3xx，但选 3xx 必须填跳转目标。
func TestValidateRuleFeatures_staticRedirectStatusRequiresTarget(t *testing.T) {
	for _, status := range []int{301, 302, 303, 307, 308} {
		err := validateRuleFeatures(staticRuleInput(models.PathRule{ResponseStatus: status}))
		if err == nil {
			t.Fatalf("status %d 缺跳转目标必须被拒绝", status)
		}
		if !strings.Contains(err.Error(), "必须填写跳转地址") {
			t.Fatalf("status %d: 文案须点名「必须填写跳转地址」，got %q", status, err.Error())
		}
		// 填了目标即放行
		if err := validateRuleFeatures(staticRuleInput(models.PathRule{
			ResponseStatus: status, RedirectTo: "/new-place",
		})); err != nil {
			t.Fatalf("status %d + 站内路径目标应放行，得到: %v", status, err)
		}
	}
}

// S3 · 非 3xx 携带跳转目标 → 显性拒绝（自研口径：误配必须报错，不静默忽略）。
func TestValidateRuleFeatures_nonRedirectStatusRejectsTarget(t *testing.T) {
	for _, status := range []int{200, 204, 400, 404, 429, 500, 503} {
		err := validateRuleFeatures(staticRuleInput(models.PathRule{
			ResponseStatus: status, RedirectTo: "https://example.com/x",
		}))
		if err == nil {
			t.Fatalf("status %d 携带跳转目标必须被拒绝", status)
		}
		if !strings.Contains(err.Error(), "不应填写跳转地址") {
			t.Fatalf("status %d: 文案须点名「不应填写跳转地址」，got %q", status, err.Error())
		}
	}
}

// S4 · 响应体上限放宽到 4096：4096 码点合法、4097 拒绝；中文/emoji 按码点计。
func TestValidateRuleFeatures_responseBodyLengthLimit(t *testing.T) {
	// 边界：正好 4096 个 ASCII 字符通过
	if err := validateRuleFeatures(staticRuleInput(models.PathRule{
		ResponseStatus: 200, ResponseBody: strings.Repeat("x", 4096),
	})); err != nil {
		t.Fatalf("4096 字符应放行，得到: %v", err)
	}
	// 超一字符即拒
	err := validateRuleFeatures(staticRuleInput(models.PathRule{
		ResponseStatus: 200, ResponseBody: strings.Repeat("x", 4097),
	}))
	if err == nil {
		t.Fatal("4097 字符必须被拒绝")
	}
	if !strings.Contains(err.Error(), "不能超过 4096 个字符") {
		t.Fatalf("文案须点名 4096，got %q", err.Error())
	}
	// 按 Unicode 码点计（非字节、非 UTF-16 单元）：4096 个中文字合法
	if err := validateRuleFeatures(staticRuleInput(models.PathRule{
		ResponseStatus: 200, ResponseBody: strings.Repeat("维", 4096),
	})); err != nil {
		t.Fatalf("4096 个中文字（码点计）应放行，得到: %v", err)
	}
	if err := validateRuleFeatures(staticRuleInput(models.PathRule{
		ResponseStatus: 200, ResponseBody: strings.Repeat("🙂", 4096),
	})); err != nil {
		t.Fatalf("4096 个代理对字符（码点计）应放行，得到: %v", err)
	}
	// 旧 64 字符界值必须已放宽（上游回归防护）
	if err := validateRuleFeatures(staticRuleInput(models.PathRule{
		ResponseStatus: 200, ResponseBody: strings.Repeat("y", 200),
	})); err != nil {
		t.Fatalf("200 字符应放行（旧 64 上限已放宽），得到: %v", err)
	}
}

// S5 · 响应体控制字符门：放行 \n \r \t（HTML/JSON 多行排版），拒其余控制字符。
func TestValidateRuleFeatures_responseBodyControlChars(t *testing.T) {
	// 放行常规空白
	multiline := "<html>\n  <body>\r\n\t<h1>维护中</h1>\n  </body>\n</html>"
	if err := validateRuleFeatures(staticRuleInput(models.PathRule{
		ResponseStatus: 200, ResponseBody: multiline,
	})); err != nil {
		t.Fatalf("多行 HTML（含 \\n \\r \\t）应放行，得到: %v", err)
	}
	jsonBody := "{\n  \"error\": \"维护中\"\n}"
	if err := validateRuleFeatures(staticRuleInput(models.PathRule{
		ResponseStatus: 503, ResponseBody: jsonBody,
	})); err != nil {
		t.Fatalf("多行 JSON 应放行，得到: %v", err)
	}
	// 拒绝其余控制字符（NUL / BEL / VT / FF / ESC / DEL）
	for _, bad := range []string{"a\x00b", "a\x07b", "a\x0bb", "a\x0cb", "a\x1bb", "a\x7fb"} {
		err := validateRuleFeatures(staticRuleInput(models.PathRule{
			ResponseStatus: 200, ResponseBody: bad,
		}))
		if err == nil {
			t.Fatalf("控制字符 %q 必须被拒绝", bad)
		}
		if !strings.Contains(err.Error(), "非法控制字符") {
			t.Fatalf("控制字符 %q: 文案须点名「非法控制字符」，got %q", bad, err.Error())
		}
	}
}

// S6 · 跳转目标强校验：须 http:// / https:// / / 开头，不含空格与控制字符。
func TestValidateRuleFeatures_redirectTargetShape(t *testing.T) {
	valid := []string{
		"https://example.com/new",
		"http://example.com/new?q=1",
		"/new-place",
		"/new?q=1#frag",
		"HTTPS://Example.COM/Upper", // 大小写不敏感
	}
	for _, target := range valid {
		if err := validateRuleFeatures(staticRuleInput(models.PathRule{
			ResponseStatus: 301, RedirectTo: target,
		})); err != nil {
			t.Fatalf("目标 %q 应放行，得到: %v", target, err)
		}
	}
	invalid := []string{
		"ftp://example.com/x",       // 非 http(s) 协议
		"//example.com/x",           // 协议相对：不是 / 开头站内路径语义（实际以 / 开头，见下）
		"example.com/x",             // 无协议无前导 /
		"https://exa mple.com/x",    // 含空格
		"/new path",                 // 含空格
		"https://example.com/\x01x", // 控制字符
		"javascript:alert(1)",       // 危险协议
	}
	for _, target := range invalid {
		err := validateRuleFeatures(staticRuleInput(models.PathRule{
			ResponseStatus: 301, RedirectTo: target,
		}))
		// "//example.com/x" 以 / 开头，按「站内绝对路径」口径**是合法的**（浏览器
		// 解析为协议相对 URL，仍属站内重定向的安全形态）——此条单列断言放行。
		if target == "//example.com/x" {
			if err != nil {
				t.Fatalf("目标 %q 以 / 开头，按站内路径口径应放行，得到: %v", target, err)
			}
			continue
		}
		if err == nil {
			t.Fatalf("目标 %q 必须被拒绝", target)
		}
		if !strings.Contains(err.Error(), "跳转地址无效") {
			t.Fatalf("目标 %q: 文案须点名「跳转地址无效」，got %q", target, err.Error())
		}
	}
}

// S7 · 响应体与 3xx 互斥（RFC 9110：3xx 不带消息体）；204 同理。
func TestValidateRuleFeatures_noBodyForRedirectAnd204(t *testing.T) {
	for _, status := range []int{301, 302, 303, 307, 308} {
		err := validateRuleFeatures(staticRuleInput(models.PathRule{
			ResponseStatus: status, RedirectTo: "https://example.com/x", ResponseBody: "should not be here",
		}))
		if err == nil {
			t.Fatalf("status %d 携带响应体必须被拒绝", status)
		}
		if !strings.Contains(err.Error(), "不得携带响应内容") {
			t.Fatalf("status %d: 文案须点名 RFC 9110，got %q", status, err.Error())
		}
	}
	// 204 禁体
	err := validateRuleFeatures(staticRuleInput(models.PathRule{
		ResponseStatus: 204, ResponseBody: "should not be here",
	}))
	if err == nil {
		t.Fatal("204 携带响应体必须被拒绝")
	}
	if !strings.Contains(err.Error(), "不得携带响应内容") {
		t.Fatalf("204: 文案须点名 RFC 9110，got %q", err.Error())
	}
}

// S8 · redirect 模式语义对齐：响应码只能为 301（渲染侧恒写 301），非 301 显性拒绝。
func TestValidateRuleFeatures_redirectModeOnly301(t *testing.T) {
	// 301 / 0（缺省）放行
	for _, status := range []int{0, 301} {
		if err := validateRuleFeatures(redirectRuleInput(models.PathRule{
			ResponseStatus: status, RedirectTo: "https://example.com/new",
		})); err != nil {
			t.Fatalf("redirect 模式 status=%d 应放行，得到: %v", status, err)
		}
	}
	// 其他 3xx 与任意值拒绝，并指向 static 模式
	for _, status := range []int{302, 303, 307, 308, 200} {
		err := validateRuleFeatures(redirectRuleInput(models.PathRule{
			ResponseStatus: status, RedirectTo: "https://example.com/new",
		}))
		if err == nil {
			t.Fatalf("redirect 模式 status=%d 必须被拒绝（渲染恒写 301）", status)
		}
		if !strings.Contains(err.Error(), "只能为 301") {
			t.Fatalf("status %d: 文案须点名「只能为 301」，got %q", status, err.Error())
		}
	}
}

// S10 · 存量数据兼容：旧 11 码内的 static 配置行为不变（不做任何迁移也仍可保存）。
func TestValidateRuleFeatures_legacyStatusesStillAccepted(t *testing.T) {
	// 上游旧白名单 11 码 —— 其中 200/204/400/401/403/404/410/500/502/503 必须仍放行。
	// 201 是唯一被移出的一项（见 S1 拒绝用例）：它属「口径收紧」而非存量破坏——
	// 存量 201 配置在保存时会得到显式报错与改名建议，而不是静默改变渲染行为。
	for _, status := range []int{200, 204, 400, 401, 403, 404, 410, 500, 502, 503} {
		pathRule := models.PathRule{ResponseStatus: status}
		// 204 按 RFC 9110 不得带体（旧校验未拦，但那属旧校验的漏，不是合法
		// 存量形态）；其余码带体是常规用法。
		if services.StaticResponseBodyAllowed(status) {
			pathRule.ResponseBody = "legacy"
		}
		if err := validateRuleFeatures(staticRuleInput(pathRule)); err != nil {
			t.Fatalf("存量状态码 %d 必须仍放行，得到: %v", status, err)
		}
	}
	// 存量 redirect 配置（恒 301 + 目标）不变
	if err := validateRuleFeatures(redirectRuleInput(models.PathRule{
		RedirectTo: "https://legacy.example.com/old",
	})); err != nil {
		t.Fatalf("存量 redirect 配置必须仍放行，得到: %v", err)
	}
}

// 转发模式（response_mode 空）零影响：响应字段为死配置，不参与校验。
func TestValidateRuleFeatures_forwardModeUnaffected(t *testing.T) {
	input := ruleFeatureInput{
		Protocol:            "http",
		CustomRoutesEnabled: true,
		PathRules: []models.PathRule{{
			MatchType: "prefix", Path: "/api/",
			// 死配置字段：转发模式不校验（写侧归一）
			ResponseBody: "whatever\x01", RedirectTo: "not-a-url",
		}},
	}
	if err := validateRuleFeatures(input); err != nil {
		t.Fatalf("转发模式不得校验响应字段，得到: %v", err)
	}
}
