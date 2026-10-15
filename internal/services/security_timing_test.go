package services

// 审计行内嵌 timing（lb_timing）读侧契约测试（历史：
// 侧车退役——耗时随审计写插件注入审计 JSON 顶层 lb_timing 字段，摄取管道直接
// 从审计行取值，选值规则与退役前 securityEventsStageDuration 分段键二态契约逐
// 字对齐）。
//
// 分段契约（与写侧 caddygeoip 配对）：
//	pre_us=预检决策耗时（放行=timing_pre 收点记；预检拦=blocked_counter 代记）；
//	end_us=拦截事件 链首→中断全链 / logged 事件 预检后→链末（WAF 段值）。
// 选值规则：预检段规则取 pre（miss 回退 end）；WAF 段规则拦截=end-pre（缺 pre
// 退 end）；WAF 段 logged=end。缺席字段=0（UI 报「—」）。

import (
	"encoding/json"
	"fmt"
	"testing"
)

// timingFixture 构造一条最小审计事务 JSON（顶层 lb_timing 以 raw JSON 内嵌）。
func timingFixture(ruleID string, interrupted bool, lbTiming string) json.RawMessage {
	return json.RawMessage(fmt.Sprintf(`{
		"transaction": {
			"unix_timestamp": 1786447017841320426,
			"id": "tx-timing-1",
			"client_ip": "203.0.113.50",
			"server_id": "go029.com",
			"request": { "method": "GET", "uri": "/probe", "headers": { "host": ["go029.com"] } },
			"is_interrupted": %t
		},
		"lb_timing": %s,
		"messages": [
			{ "message": "probe", "data": { "id": %s, "raw": "id:%s,phase:1,deny,log" } }
		]
	}`, interrupted, lbTiming, ruleID, ruleID))
}

func mustParseTiming(t *testing.T, raw json.RawMessage) *securityEventRecord {
	t.Helper()
	rec, err := securityEventsParseTransaction(raw)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	return rec
}

// 预检段规则（id:2）+ pre 在场：duration=pre、precheck=pre（决策口径）。
func TestSecurityEventsTiming_precheckRuleUsesPre(t *testing.T) {
	rec := mustParseTiming(t, timingFixture("2", true, `{"pre_us":120,"end_us":9000}`))
	if rec.DurationUs != 120 || rec.PrecheckUs != 120 {
		t.Fatalf("duration=%d precheck=%d; want 120/120 (pre wins for precheck rules)", rec.DurationUs, rec.PrecheckUs)
	}
}

// 预检段规则 + 仅 end（头对缺失的降级形态）：回退 end，precheck=duration。
func TestSecurityEventsTiming_precheckRuleFallsBackToEnd(t *testing.T) {
	rec := mustParseTiming(t, timingFixture("800001", true, `{"end_us":777}`))
	if rec.DurationUs != 777 || rec.PrecheckUs != 777 {
		t.Fatalf("duration=%d precheck=%d; want 777/777 (end fallback)", rec.DurationUs, rec.PrecheckUs)
	}
}

// GeoIP 段规则（800xxx 六位 8 开头）按预检族选值。
func TestSecurityEventsTiming_geoipRuleUsesPre(t *testing.T) {
	rec := mustParseTiming(t, timingFixture("800012", true, `{"pre_us":300,"end_us":400}`))
	if rec.DurationUs != 300 || rec.PrecheckUs != 300 {
		t.Fatalf("duration=%d precheck=%d; want 300/300", rec.DurationUs, rec.PrecheckUs)
	}
}

// WAF 段规则 + 拦截 + pre/end 双在场：duration=end-pre（隔离 WAF 成本），
// precheck=pre。
func TestSecurityEventsTiming_wafRuleInterruptedSubtractsSegments(t *testing.T) {
	rec := mustParseTiming(t, timingFixture("942100", true, `{"pre_us":200,"end_us":950}`))
	if rec.DurationUs != 750 || rec.PrecheckUs != 200 {
		t.Fatalf("duration=%d precheck=%d; want 750/200 (end-pre)", rec.DurationUs, rec.PrecheckUs)
	}
}

// WAF 段规则 + 拦截 + 仅 end（WAF 段拦，blocked_counter 只写 end）：duration=end。
func TestSecurityEventsTiming_wafRuleInterruptedEndOnly(t *testing.T) {
	rec := mustParseTiming(t, timingFixture("942100", true, `{"end_us":640}`))
	if rec.DurationUs != 640 || rec.PrecheckUs != 0 {
		t.Fatalf("duration=%d precheck=%d; want 640/0", rec.DurationUs, rec.PrecheckUs)
	}
}

// WAF 段规则 + logged：duration=end 直接取用（锚点交接后的 WAF 段值），不减 pre。
func TestSecurityEventsTiming_wafRuleLoggedUsesEnd(t *testing.T) {
	rec := mustParseTiming(t, timingFixture("942100", false, `{"pre_us":150,"end_us":620}`))
	if rec.DurationUs != 620 || rec.PrecheckUs != 150 {
		t.Fatalf("duration=%d precheck=%d; want 620/150 (logged uses end as-is)", rec.DurationUs, rec.PrecheckUs)
	}
}

// 无 lb_timing 字段（审计行无计时头/降级形态）：双值零，UI 报「—」。
func TestSecurityEventsTiming_missingFieldYieldsZero(t *testing.T) {
	rec := mustParseTiming(t, timingFixture("942100", true, `null`))
	if rec.DurationUs != 0 || rec.PrecheckUs != 0 {
		t.Fatalf("duration=%d precheck=%d; want 0/0", rec.DurationUs, rec.PrecheckUs)
	}
}

// 空对象（字段全缺席）同零值。
func TestSecurityEventsTiming_emptyObjectYieldsZero(t *testing.T) {
	rec := mustParseTiming(t, timingFixture("942100", false, `{}`))
	if rec.DurationUs != 0 || rec.PrecheckUs != 0 {
		t.Fatalf("duration=%d precheck=%d; want 0/0", rec.DurationUs, rec.PrecheckUs)
	}
}

// 0µs 是合法计时值——在场即取用，不得当缺席。
func TestSecurityEventsTiming_zeroIsValid(t *testing.T) {
	rec := mustParseTiming(t, timingFixture("2", true, `{"pre_us":0}`))
	if rec.DurationUs != 0 || rec.PrecheckUs != 0 {
		t.Fatalf("duration=%d precheck=%d; want 0/0 (valid zero)", rec.DurationUs, rec.PrecheckUs)
	}
	// 与「缺席」的区分在 UI 层以字段存在性表达；此处只钉取值不误回退 end。
	rec2 := mustParseTiming(t, timingFixture("2", true, `{"pre_us":0,"end_us":999}`))
	if rec2.DurationUs != 0 || rec2.PrecheckUs != 0 {
		t.Fatalf("duration=%d precheck=%d; want 0/0 (pre present beats end)", rec2.DurationUs, rec2.PrecheckUs)
	}
}

// 负值视同缺席（防御畸形注入；写侧时序值恒非负）。
func TestSecurityEventsTiming_negativeTreatedAsAbsent(t *testing.T) {
	rec := mustParseTiming(t, timingFixture("942100", true, `{"pre_us":-5,"end_us":-7}`))
	if rec.DurationUs != 0 || rec.PrecheckUs != 0 {
		t.Fatalf("duration=%d precheck=%d; want 0/0 (negatives rejected)", rec.DurationUs, rec.PrecheckUs)
	}
	rec2 := mustParseTiming(t, timingFixture("942100", true, `{"pre_us":100,"end_us":-7}`))
	if rec2.DurationUs != 0 || rec2.PrecheckUs != 100 {
		t.Fatalf("duration=%d precheck=%d; want 0/100 (end rejected → interrupted WAF rule has no duration source)", rec2.DurationUs, rec2.PrecheckUs)
	}
}

// end<pre 的畸形组合：不做负数减法，退化为 end 单值。
func TestSecurityEventsTiming_endLessThanPreDegenerates(t *testing.T) {
	rec := mustParseTiming(t, timingFixture("942100", true, `{"pre_us":900,"end_us":400}`))
	if rec.DurationUs != 400 || rec.PrecheckUs != 900 {
		t.Fatalf("duration=%d precheck=%d; want 400/900 (no negative subtraction)", rec.DurationUs, rec.PrecheckUs)
	}
}
