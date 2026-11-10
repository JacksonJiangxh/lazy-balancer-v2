package services

// 安全管线三处 P3 钉测：
//   - 攻击光流溢出披露（gap/gap_skipped 与正常光流同口径）；
//   - 保留地址在**入环前**排除（内网扫描不得挤占环与单轮配额）；
//   - 写侧 body_truncated 标记必须在读侧落库契约里被消费。

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestThreatScreenAttackFlowSnapshotReportsGap(t *testing.T) {
	enableAttackFlowSampling(t)
	// 首屏（since=0）不算空洞
	threatScreenAttackFlowRecordBatch(newAttackFlowBatchItems(threatScreenAttackFlowRingMax+500, time.Now()))
	if _, _, gap := ThreatScreenAttackFlowSnapshot(0, 10); gap != 0 {
		t.Fatalf("首屏 gap=%d，want 0（首屏只取最新窗口，不判空洞）", gap)
	}

	// 消费者游标落在最老保留序号之前 → 中间记录已被环覆盖
	threatScreenAttackFlowMu.Lock()
	oldest := threatScreenAttackFlowEvents[0].Seq
	threatScreenAttackFlowMu.Unlock()
	const since = uint64(10)
	if oldest <= since+1 {
		t.Fatalf("夹具前提不成立：oldest=%d since=%d", oldest, since)
	}
	events, next, gap := ThreatScreenAttackFlowSnapshot(since, 10)
	if gap != oldest-since-1 {
		t.Fatalf("gap=%d，want %d（环形缓冲溢出永久丢失数）", gap, oldest-since-1)
	}
	if len(events) == 0 || next != events[len(events)-1].Seq {
		t.Fatalf("gap 轮的事件/next 契约破坏: events=%d next=%d", len(events), next)
	}

	// 游标追平后不再报空洞
	if _, _, gap := ThreatScreenAttackFlowSnapshot(next, 10); gap != 0 {
		t.Fatalf("追平后 gap=%d，want 0", gap)
	}
}

// ingestReservedAndPublicAttackEvents 通过真实摄取链路写入一条保留地址攻击
// 事件与一条公网攻击事件，返回环内事件。
func ingestReservedAndPublicAttackEvents(t *testing.T) []ThreatScreenAttackFlowEvent {
	t.Helper()
	installSecurityEventsAutobanFixture(t)
	enableAttackFlowSampling(t)
	dir := t.TempDir()
	logPath := filepath.Join(dir, "audit.log")
	offsetPath := filepath.Join(dir, "security_events.offset")
	docs := strings.Join([]string{
		securityEvents历史Fixture("tx-flow-lan", "10.1.2.3", "/lan-scan"),
		securityEvents历史Fixture("tx-flow-wan", "45.33.32.71", "/wan-attack"),
	}, "\n") + "\n"
	if err := os.WriteFile(logPath, []byte(docs), 0o644); err != nil {
		t.Fatalf("write audit log: %v", err)
	}
	if err := securityEventsNewTailer(logPath, offsetPath).securityEventsTick(); err != nil {
		t.Fatalf("ingest tick: %v", err)
	}
	events, _, _ := ThreatScreenAttackFlowSnapshot(0, 0)
	return events
}

func TestSecurityEventsIngestExcludesReservedIPsFromAttackFlowRing(t *testing.T) {
	events := ingestReservedAndPublicAttackEvents(t)
	var lan, wan int
	for _, ev := range events {
		switch ev.ClientIP {
		case "10.1.2.3":
			lan++
		case "45.33.32.71":
			wan++
		}
	}
	if lan != 0 {
		t.Fatalf("保留地址事件进环 %d 条，want 0（应在入口侧排除，避免挤占环容量）", lan)
	}
	if wan != 1 {
		t.Fatalf("公网攻击事件进环 %d 条，want 1", wan)
	}
}

func TestSecurityEventsRecordBodyConsumesTruncatedFlag(t *testing.T) {
	// 二进制体：写侧只置标记、不加文本后缀——读侧把 base64: 前缀升级为
	// base64-truncated:（文本标记会破坏解码），截断事实不可丢。
	binary := securityEventsRecordBody("binary\xffpayload", true)
	if !strings.HasPrefix(binary, securityEventsB64TruncatedPrefix) {
		t.Fatalf("二进制截断体=%q，want base64-truncated: 前缀", binary)
	}
	// 文本体：未带后缀时补统一后缀（展示层识别）
	if got := securityEventsRecordBody("plain text", true); !strings.HasSuffix(got, securityEventsTruncatedMarker) {
		t.Fatalf("文本截断体=%q，want 带截断标记", got)
	}
	// 文本体写侧已带后缀：不得重复追加
	prefixed := "abcdef" + securityEventsTruncatedMarker
	if got := securityEventsRecordBody(prefixed, true); strings.Count(got, securityEventsTruncatedMarker) != 1 {
		t.Fatalf("截断标记重复: %q", got)
	}
	// 未截断：原样（零额外标记）
	if got := securityEventsRecordBody("plain", false); got != "plain" {
		t.Fatalf("未截断体=%q，want 原值", got)
	}
	// 空体：保持空（无内容可标）
	if got := securityEventsRecordBody("", true); got != "" {
		t.Fatalf("空体=%q，want 空", got)
	}
}

// 落库契约端到端：审计 JSON 的 request.body_truncated 必须体现在事件行。
func TestSecurityEventsParseTransactionConsumesBodyTruncated(t *testing.T) {
	raw := []byte(`{"transaction":{"unix_timestamp":1786447017841320426,"id":"tx-body-trunc",
		"client_ip":"45.33.32.72","server_id":"go029.com",
		"request":{"method":"POST","uri":"/upload","headers":{"host":["go029.com"]},
		"body":"--boundary\r\npartial","body_truncated":true},
		"is_interrupted":true},
		"messages":[{"message":"rule","data":{"id":942100,"raw":"id:942100,phase:2,deny,log"}}]}`)
	rec, err := securityEventsParseTransaction(raw)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if !strings.HasSuffix(rec.RequestBody, securityEventsTruncatedMarker) {
		t.Fatalf("落库请求体=%q，want 带截断标记", rec.RequestBody)
	}
}
