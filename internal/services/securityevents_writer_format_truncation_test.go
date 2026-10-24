package services

// 侧车 format_errors 与 io_errors 分开累计/分开披露（磁盘故障 vs 代码/契约
// 缺陷的排障方向不同），但格式化失败同样让该审计行未落盘，必须进同一失败窗口
// 与丢失事实。审计行 messages_dropped（写侧单行上限截断）同理：事件在库，但
// 被省略的命中明细永久缺失。

import (
	"encoding/json"
	"os"
	"strings"
	"testing"
	"time"
)

func TestWriterStatsHealth_formatErrorsAreParsedSeparately(t *testing.T) {
	isolationForWriterHealth(t)
	resetFormatBaseline := func() {
		securityEventsWriterHealth.mu.Lock()
		securityEventsWriterHealth.baselineFormat = 0
		securityEventsWriterHealth.formatTotal = 0
		securityEventsWriterHealth.mu.Unlock()
	}
	resetFormatBaseline()
	t.Cleanup(resetFormatBaseline)
	payload := `{"dropped":1,"io_errors":0,"format_errors":3,"written_at":"` +
		time.Now().UTC().Format(time.RFC3339) + `"}`
	if err := os.WriteFile(securityEventsAuditWriterStatsPath(), []byte(payload), 0o644); err != nil {
		t.Fatal(err)
	}

	securityEventsObserveAuditWriterStats()
	status := SecurityEventsIngestionHealthSnapshot()
	if status.WriterFormatErrors != 3 {
		t.Fatalf("format_errors 未消费: writer_format_errors=%d, want 3", status.WriterFormatErrors)
	}
	if status.WriterIOErrors != 0 {
		t.Fatalf("格式化失败不得混入 io_errors: %d", status.WriterIOErrors)
	}
	if !status.DataLoss {
		t.Fatal("格式化失败=审计行未落盘，必须计入 data_loss")
	}

	// 同一文件重复观测只累计增量（基线口径），不重复计数。
	securityEventsObserveAuditWriterStats()
	if got := SecurityEventsIngestionHealthSnapshot().WriterFormatErrors; got != 3 {
		t.Fatalf("重复观测同一文件重复计数: %d", got)
	}
}

func TestSecurityEventsParseTransaction_recordsMessagesDropped(t *testing.T) {
	raw := json.RawMessage(`{"transaction":{"unix_timestamp":1760000000,"id":"tx-drop","client_ip":"198.51.100.7"},` +
		`"messages":[{"message":"m","data":{"id":942100,"raw":"x"}}],"messages_dropped":4}`)
	rec, err := securityEventsParseTransaction(raw)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if rec.messagesDropped != 4 {
		t.Fatalf("messages_dropped 未解析: %d", rec.messagesDropped)
	}
}

func TestIngestionHealth_messagesDroppedSurfacesAsDataLoss(t *testing.T) {
	isolationForWriterHealth(t)
	oldDropped := securityEventsMessagesDropped.Load()
	securityEventsMessagesDropped.Store(0)
	t.Cleanup(func() { securityEventsMessagesDropped.Store(oldDropped) })

	securityEventsMessagesDropped.Add(7)
	status := SecurityEventsIngestionHealthSnapshot()
	if status.MessagesDropped != 7 {
		t.Fatalf("messages_dropped 未上抛: %d", status.MessagesDropped)
	}
	if !status.DataLoss {
		t.Fatal("命中明细永久缺失必须计入 data_loss（事件在库但明细不全）")
	}
}

// 逐行披露：写侧 messages 上限截断后，事件行自身必须说明「另有 N 条命中消息
// 未采集」——进程级健康位只告诉运维「有截断」，看不到是哪条事件、缺了多少。
func TestSecurityEventsParseTransaction_ruleMsgMarksDroppedMessages(t *testing.T) {
	parse := func(msg string, dropped int) string {
		t.Helper()
		raw, err := json.Marshal(map[string]any{
			"transaction":      map[string]any{"unix_timestamp": 1760000000, "id": "tx-drop-note"},
			"messages":         []any{map[string]any{"message": msg, "data": map[string]any{"id": 942100, "raw": "x"}}},
			"messages_dropped": dropped,
		})
		if err != nil {
			t.Fatal(err)
		}
		rec, err := securityEventsParseTransaction(raw)
		if err != nil {
			t.Fatalf("parse: %v", err)
		}
		return rec.RuleMsg
	}

	if got := parse("SQL Injection Attack", 0); got != "SQL Injection Attack" {
		t.Fatalf("未截断行被改写: %q", got)
	}
	got := parse("SQL Injection Attack", 9)
	want := "\n（另有 9 条规则命中消息未采集）"
	if !strings.HasSuffix(got, want) {
		t.Fatalf("截断行缺少逐行披露后缀: %q", got)
	}
	if !strings.HasPrefix(got, "SQL Injection Attack") {
		t.Fatalf("正文被破坏: %q", got)
	}

	// 超长正文 + 截断标记并存：总长仍受 rule_msg 上限约束（行体积披露口径
	// 不变），且披露后缀不得被裁剪吃掉（先留后缀再裁正文）。
	long := strings.Repeat("m", securityEventsRuleMsgCap*2)
	got = parse(long, 128)
	longWant := "\n（另有 128 条规则命中消息未采集）"
	if len(got) > securityEventsRuleMsgCap {
		t.Fatalf("rule_msg 长度 %d > 上限 %d", len(got), securityEventsRuleMsgCap)
	}
	if !strings.HasSuffix(got, longWant) {
		t.Fatalf("超长形态披露后缀丢失: tail=%q", got[max(0, len(got)-40):])
	}
	if !strings.Contains(got, securityEventsTruncatedMarker) {
		t.Fatal("超长形态必须同时保留文本裁剪标记")
	}
}

// 截断行解析出的异常分必须等于真实总分：写侧「掐中间、保两头」把评估汇总
// 消息（949xxx）留在尾段，分数因此不被截断影响；只保开头的形态会把它丢掉，
// 命中规则多的请求分数归零（事件列表与威胁大屏严重度分档同时低估）。
func TestSecurityEventsParseTransaction_truncatedRowKeepsAnomalyScore(t *testing.T) {
	raw := json.RawMessage(`{"transaction":{"unix_timestamp":1760000000,"id":"tx-trunc-score","is_interrupted":true},` +
		`"messages":[{"message":"SQL Injection Attack","data":{"id":942100,"raw":"@detectSQLi"}},` +
		`{"message":"Inbound Anomaly Score Exceeded (Total Score: 42)","data":{"id":949110,"raw":""}}],` +
		`"messages_dropped":145}`)
	rec, err := securityEventsParseTransaction(raw)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if rec.AnomalyScore != 42 {
		t.Fatalf("截断行异常分 = %d, want 42（评估汇总消息必须被采集，分数不得因截断归零）", rec.AnomalyScore)
	}
	if !strings.Contains(rec.RuleMsg, "另有 145 条规则命中消息未采集") {
		t.Fatalf("截断行未披露丢失条数: %q", rec.RuleMsg)
	}
}
