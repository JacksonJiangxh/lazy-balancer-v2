package services

import (
	"encoding/json"
	"fmt"
	"strings"
	"testing"
	"unicode/utf8"
)

// TestSecurityEventsParseTransaction_clipsTextFields 钉住单行体积契约：URI 与
// rule_msg 与头/体同门裁剪，超限按 UTF-8 边界截断并追加可观测标记；解析后的
// 记录整体不超过披露的单行上限（插入与改判 UPDATE 共享该记录）。
func TestSecurityEventsParseTransaction_clipsTextFields(t *testing.T) {
	longURI := "/" + strings.Repeat("a", securityEventsURICap*2)
	longMsg := strings.Repeat("m", securityEventsRuleMsgCap*3)
	longHeader := strings.Repeat("h", securityEventsHeadersCap+1024)
	longBody := strings.Repeat("b", securityEventsBodyCap+1024)
	raw := fmt.Sprintf(`{"transaction":{"unix_timestamp":1754910200000000000,"id":"tx-row-caps","client_ip":"203.0.113.7","request":{"method":"GET","uri":%q,"headers":{"X-Long":[%q]},"body":%q}},"messages":[{"message":%q,"data":{"id":"949110","raw":""}}]}`,
		longURI, longHeader, longBody, longMsg)
	rec, err := securityEventsParseTransaction(json.RawMessage(raw))
	if err != nil {
		t.Fatalf("parse: %v", err)
	}

	if want := longURI[:securityEventsURICap] + securityEventsTruncatedMarker; rec.URI != want {
		t.Fatalf("URI len=%d, want capped form len=%d with marker", len(rec.URI), len(want))
	}
	if want := longMsg[:securityEventsRuleMsgCap] + securityEventsTruncatedMarker; rec.RuleMsg != want {
		t.Fatalf("RuleMsg len=%d, want capped form len=%d with marker", len(rec.RuleMsg), len(want))
	}
	if !strings.HasSuffix(rec.URI, securityEventsTruncatedMarker) || !strings.HasSuffix(rec.RuleMsg, securityEventsTruncatedMarker) {
		t.Fatalf("截断标记必须落在落库值上（可观测）: uri=%q... msg=%q...", rec.URI[len(rec.URI)-20:], rec.RuleMsg[len(rec.RuleMsg)-20:])
	}
	if len(rec.RequestHeaders) > securityEventsHeadersCap {
		t.Fatalf("headers 超出采集上限: %d", len(rec.RequestHeaders))
	}
	if len(rec.RequestBody) > securityEventsBodyCap+len(securityEventsTruncatedMarker) {
		t.Fatalf("body 超出采集上限: %d", len(rec.RequestBody))
	}
	if got, max := rec.rowBytes(), int(securityEventsRowMaxBytes()); got > max {
		t.Fatalf("rowBytes=%d 超出披露的单行上限 %d", got, max)
	}
}

// TestSecurityEventsClipTextField_runeBoundary 钉住多字节字符边界：截断回退到
// 符文起点，不产生非法 UTF-8。
func TestSecurityEventsClipTextField_runeBoundary(t *testing.T) {
	cases := []struct {
		name string
		cap  int
	}{
		{"uri", securityEventsURICap},
		{"rule msg", securityEventsRuleMsgCap},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			// 3 字节字符使 cap 落在字符中间（cap%3 != 0 时必然）。
			got := securityEventsClipTextField(strings.Repeat("界", tc.cap), tc.cap)
			if !utf8.ValidString(got) {
				t.Fatalf("截断产物必须是合法 UTF-8")
			}
			if !strings.HasSuffix(got, securityEventsTruncatedMarker) {
				t.Fatalf("超限必须带截断标记: %.20q", got)
			}
			trimmed := strings.TrimSuffix(got, securityEventsTruncatedMarker)
			if len(trimmed) == 0 || len(trimmed) > tc.cap {
				t.Fatalf("截断主体 len=%d, want (0, %d]", len(trimmed), tc.cap)
			}
			if strings.Trim(trimmed, "界") != "" {
				t.Fatalf("截断主体不得含半截字符: %q", trimmed)
			}
		})
	}
	// 上限内的值原样返回（不引入标记，避免常态化误标）。
	for _, v := range []string{"", "/login", strings.Repeat("a", securityEventsURICap)} {
		if got := securityEventsClipTextField(v, securityEventsURICap); got != v {
			t.Fatalf("上限内值被改动: len %d -> %d", len(v), len(got))
		}
	}
}

// TestSecurityEventRecord_rowBytes_countsAllTextFields 钉住批次/单轮字节口径：
// 头、体、URI、rule_msg 全部计入（旧实现只统计头+体，长 URI/msg 洪峰不触发
// 提前提交门）。
func TestSecurityEventRecord_rowBytes_countsAllTextFields(t *testing.T) {
	rec := &securityEventRecord{
		RequestHeaders: `{"host":["a.example.com"]}`,
		RequestBody:    "body",
		URI:            "/very/long/path?q=" + strings.Repeat("x", 4096),
		RuleMsg:        strings.Repeat("msg", 600),
	}
	want := len(rec.RequestHeaders) + len(rec.RequestBody) + len(rec.URI) + len(rec.RuleMsg)
	if got := rec.rowBytes(); got != want {
		t.Fatalf("rowBytes=%d, want %d（头+体+URI+rule_msg 单一口径）", got, want)
	}
	if rec.rowBytes() <= len(rec.RequestHeaders)+len(rec.RequestBody) {
		t.Fatalf("URI/rule_msg 未计入字节口径")
	}
	// 各采集上限之和就是披露的单行上限——上限常量新增字段时两处必须同步。
	if got, want := securityEventsRowMaxBytes(), int64(securityEventsHeadersCap+securityEventsBodyCap+securityEventsURICap+securityEventsRuleMsgCap+3*len(securityEventsTruncatedMarker)); got != want {
		t.Fatalf("row max=%d, want %d", got, want)
	}
}
