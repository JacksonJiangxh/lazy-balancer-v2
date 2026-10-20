package services

import (
	"testing"
	"time"
)

func TestThreatScreenAttackFlow_samplingAndCursor(t *testing.T) {
	ResetThreatScreenAttackFlowForTest()
	t.Cleanup(ResetThreatScreenAttackFlowForTest)

	at := time.Unix(1792300000, 0)
	items := []threatScreenAttackFlowItem{
		{at: at, clientIP: "203.0.113.1", action: "blocked", ruleTriggered: "942100"},
		{at: at.Add(time.Second), clientIP: "203.0.113.2", action: "logged", ruleTriggered: "942100"},
		{at: at.Add(2 * time.Second), clientIP: "203.0.113.3", action: "blocked", ruleTriggered: "942100"},
	}

	// 全量：三条全部入环，weight=1。
	SetThreatScreenAttackFlowSampleN(1)
	threatScreenAttackFlowRecordBatch(items)
	events, next := ThreatScreenAttackFlowSnapshot(0, 10)
	if len(events) != 3 || next != 3 {
		t.Fatalf("full sampling events=%d next=%d, want 3/3", len(events), next)
	}
	for _, ev := range events {
		if ev.Weight != 1 {
			t.Fatalf("full sampling weight=%d, want 1", ev.Weight)
		}
	}

	// 1/4：8 条只保留第 4、8 条，weight=4；游标从上一批继续。
	SetThreatScreenAttackFlowSampleN(4)
	for i := 0; i < 8; i++ {
		threatScreenAttackFlowRecordBatch([]threatScreenAttackFlowItem{{
			at:            at.Add(time.Duration(i) * time.Second),
			clientIP:      "203.0.113.4",
			action:        "blocked",
			ruleTriggered: "942100",
		}})
	}
	events, next = ThreatScreenAttackFlowSnapshot(next, 10)
	if len(events) != 2 || next != 5 {
		t.Fatalf("1/4 sampling events=%d next=%d, want 2/5", len(events), next)
	}
	for _, ev := range events {
		if ev.Weight != 4 {
			t.Fatalf("1/4 sampling weight=%d, want 4", ev.Weight)
		}
	}

	// 关闭：不再追加。
	SetThreatScreenAttackFlowSampleN(0)
	threatScreenAttackFlowRecordBatch(items)
	events, _ = ThreatScreenAttackFlowSnapshot(next, 10)
	if len(events) != 0 {
		t.Fatalf("sample_n=0 recorded %d events, want 0", len(events))
	}
}

func TestThreatScreenAttackFlow_cursorAheadResets(t *testing.T) {
	ResetThreatScreenAttackFlowForTest()
	t.Cleanup(ResetThreatScreenAttackFlowForTest)
	SetThreatScreenAttackFlowSampleN(1)
	threatScreenAttackFlowRecordBatch([]threatScreenAttackFlowItem{{
		at:            time.Unix(1792300000, 0),
		clientIP:      "203.0.113.1",
		action:        "blocked",
		ruleTriggered: "942100",
	}})
	_, next := ThreatScreenAttackFlowSnapshot(999, 10)
	if next != 0 {
		t.Fatalf("cursor ahead next=%d, want 0", next)
	}
}
