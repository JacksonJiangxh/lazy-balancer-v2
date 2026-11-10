package services

import (
	"bytes"
	"encoding/json"
	"testing"
	"time"
)

func mustAcquireAttackFlowLease(t *testing.T, id string, sampleN int) {
	t.Helper()
	if err := AcquireThreatScreenAttackFlowLease(id, 30*time.Second, sampleN); err != nil {
		t.Fatalf("acquire lease %s: %v", id, err)
	}
}

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
	mustAcquireAttackFlowLease(t, "tab-t", 1)
	threatScreenAttackFlowRecordBatch(items)
	events, next, _ := ThreatScreenAttackFlowSnapshot(0, 10)
	if len(events) != 3 || next != 3 {
		t.Fatalf("full sampling events=%d next=%d, want 3/3", len(events), next)
	}
	for _, ev := range events {
		if ev.Weight != 1 {
			t.Fatalf("full sampling weight=%d, want 1", ev.Weight)
		}
	}

	// 1/4：8 条只保留第 4、8 条，weight=4；游标从上一批继续。
	mustAcquireAttackFlowLease(t, "tab-t", 4)
	for i := 0; i < 8; i++ {
		threatScreenAttackFlowRecordBatch([]threatScreenAttackFlowItem{{
			at:            at.Add(time.Duration(i) * time.Second),
			clientIP:      "203.0.113.4",
			action:        "blocked",
			ruleTriggered: "942100",
		}})
	}
	events, next, _ = ThreatScreenAttackFlowSnapshot(next, 10)
	if len(events) != 2 || next != 5 {
		t.Fatalf("1/4 sampling events=%d next=%d, want 2/5", len(events), next)
	}
	for _, ev := range events {
		if ev.Weight != 4 {
			t.Fatalf("1/4 sampling weight=%d, want 4", ev.Weight)
		}
	}

	// 关闭（租约释放）：不再追加。
	ReleaseThreatScreenAttackFlowLease("tab-t")
	threatScreenAttackFlowRecordBatch(items)
	events, _, _ = ThreatScreenAttackFlowSnapshot(next, 10)
	if len(events) != 0 {
		t.Fatalf("sample_n=0 recorded %d events, want 0", len(events))
	}
}

// 攻击光流采样档位租约化——有效档位=存活租约的 min（最密），
// 单租约释放不误杀其他租约（旧码全局单值最后写者胜/DELETE 全局置 0）；
// 无租约=0（关闭），过期懒清理自动归 0。与 Caddy 侧 traffic_lease.go 同模型。
func TestThreatScreenAttackFlow_leaseTableMinAndExpiry(t *testing.T) {
	ResetThreatScreenAttackFlowForTest()
	t.Cleanup(ResetThreatScreenAttackFlowForTest)

	now := time.Unix(1792300000, 0)
	// Given 两个租约 A(8)/B(1) 并存
	if err := acquireThreatScreenAttackFlowLeaseAt("tab-a", 30*time.Second, 8, now); err != nil {
		t.Fatalf("acquire tab-a: %v", err)
	}
	if err := acquireThreatScreenAttackFlowLeaseAt("tab-b", 30*time.Second, 1, now); err != nil {
		t.Fatalf("acquire tab-b: %v", err)
	}
	// When 读取有效档位 Then 取最密（min=1）
	if got := threatScreenAttackFlowSampleNAt(now.Add(time.Second)); got != 1 {
		t.Fatalf("sample_n=%d, want 1（存活租约 min）", got)
	}
	// When B 释放 Then A(8) 仍生效（旧码 DELETE 全局置 0 误杀 A）
	releaseThreatScreenAttackFlowLeaseAt("tab-b", now.Add(2*time.Second))
	if got := threatScreenAttackFlowSampleNAt(now.Add(3 * time.Second)); got != 8 {
		t.Fatalf("after release tab-b sample_n=%d, want 8（A 存活）", got)
	}
	// When 无匹配 lease 释放 Then 幂等成功、档位不变
	releaseThreatScreenAttackFlowLeaseAt("ghost", now.Add(4*time.Second))
	if got := threatScreenAttackFlowSampleNAt(now.Add(5 * time.Second)); got != 8 {
		t.Fatalf("after ghost release sample_n=%d, want 8（幂等）", got)
	}
	// When 全部租约过期 Then 档位自动归 0（懒清理）
	if got := threatScreenAttackFlowSampleNAt(now.Add(31 * time.Second)); got != 0 {
		t.Fatalf("after all leases expired sample_n=%d, want 0（关闭）", got)
	}
}

// 续租同 lease_id 更新档位与过期时间；TTL 缺省 30s、钳 [5s,120s]；
// sample_n 钳 [0,8]（负值按 1 全量）。
func TestThreatScreenAttackFlow_leaseRenewAndClamps(t *testing.T) {
	ResetThreatScreenAttackFlowForTest()
	t.Cleanup(ResetThreatScreenAttackFlowForTest)

	now := time.Unix(1792300000, 0)
	// Given 租约以过短 TTL 申请 Then 钳到 5s
	if err := acquireThreatScreenAttackFlowLeaseAt("tab-c", time.Second, 4, now); err != nil {
		t.Fatalf("acquire tab-c: %v", err)
	}
	if got := threatScreenAttackFlowSampleNAt(now.Add(4 * time.Second)); got != 4 {
		t.Fatalf("sample_n=%d, want 4（TTL 1s 钳 5s，未过期）", got)
	}
	if got := threatScreenAttackFlowSampleNAt(now.Add(6 * time.Second)); got != 0 {
		t.Fatalf("sample_n=%d, want 0（钳后 5s 已过期）", got)
	}
	// Given 档位超界申请 Then 钳 [0,8]；负值按 1
	if err := acquireThreatScreenAttackFlowLeaseAt("tab-d", 30*time.Second, 99, now); err != nil {
		t.Fatalf("acquire tab-d: %v", err)
	}
	if got := threatScreenAttackFlowSampleNAt(now.Add(time.Second)); got != 8 {
		t.Fatalf("sample_n=%d, want 8（上限钳制）", got)
	}
	if err := acquireThreatScreenAttackFlowLeaseAt("tab-e", 30*time.Second, -3, now); err != nil {
		t.Fatalf("acquire tab-e: %v", err)
	}
	if got := threatScreenAttackFlowSampleNAt(now.Add(time.Second)); got != 1 {
		t.Fatalf("sample_n=%d, want 1（负值按全量，min 取最密）", got)
	}
	// When 续租同 lease_id 改档位 Then 覆盖旧档位
	if err := acquireThreatScreenAttackFlowLeaseAt("tab-e", 30*time.Second, 8, now); err != nil {
		t.Fatalf("renew tab-e: %v", err)
	}
	if got := threatScreenAttackFlowSampleNAt(now.Add(time.Second)); got != 8 {
		t.Fatalf("sample_n=%d, want 8（续租覆盖）", got)
	}
	// 0 档租约不参与 min（与 Caddy 侧同语义：租约保留但不产事件，
	// 不得把其他租约的采样拖成关闭）
	if err := acquireThreatScreenAttackFlowLeaseAt("tab-f", 30*time.Second, 0, now); err != nil {
		t.Fatalf("acquire tab-f: %v", err)
	}
	if got := threatScreenAttackFlowSampleNAt(now.Add(time.Second)); got != 8 {
		t.Fatalf("sample_n=%d, want 8（0 档租约不拖档）", got)
	}
	// 空 lease_id 拒绝
	if err := acquireThreatScreenAttackFlowLeaseAt("", 30*time.Second, 1, now); err == nil {
		t.Fatalf("empty lease_id must be rejected")
	}
}

func TestThreatScreenAttackFlowSnapshot_omitsRuleMessage(t *testing.T) {
	ResetThreatScreenAttackFlowForTest()
	t.Cleanup(ResetThreatScreenAttackFlowForTest)
	mustAcquireAttackFlowLease(t, "tab-output", 1)
	threatScreenAttackFlowRecordBatch([]threatScreenAttackFlowItem{{
		at:            time.Unix(1792300000, 0),
		clientIP:      "203.0.113.1",
		action:        "blocked",
		ruleTriggered: "942100",
	}})
	events, _, _ := ThreatScreenAttackFlowSnapshot(0, 1)
	if len(events) != 1 {
		t.Fatalf("events=%d, want 1", len(events))
	}
	encoded, err := json.Marshal(events[0])
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(encoded, []byte(`"rule_msg"`)) {
		t.Fatalf("attack flow output must not contain rule_msg: %s", encoded)
	}
}

func TestThreatScreenAttackFlow_cursorAheadResets(t *testing.T) {
	ResetThreatScreenAttackFlowForTest()
	t.Cleanup(ResetThreatScreenAttackFlowForTest)
	mustAcquireAttackFlowLease(t, "tab-t", 1)
	threatScreenAttackFlowRecordBatch([]threatScreenAttackFlowItem{{
		at:            time.Unix(1792300000, 0),
		clientIP:      "203.0.113.1",
		action:        "blocked",
		ruleTriggered: "942100",
	}})
	_, next, _ := ThreatScreenAttackFlowSnapshot(999, 10)
	if next != 0 {
		t.Fatalf("cursor ahead next=%d, want 0", next)
	}
}
