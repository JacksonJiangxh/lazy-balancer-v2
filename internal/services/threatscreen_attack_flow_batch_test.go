package services

// 攻击光流批量写入：单个日志批次（一次事务提交）内的事件必须一次性进入环形
// 缓冲——批内一次加锁 + 批量 append + 一次裁剪，而不是逐事件 Lock/append/
// 裁剪（锁往返与 O(ring) 切片搬移按事件数放大）。结果与逐事件形态等价：
// 序号严格递增、批次顺序保留、环形上限裁剪到最近 N 条。

import (
	"testing"
	"time"
)

func newAttackFlowBatchItems(n int, start time.Time) []threatScreenAttackFlowItem {
	items := make([]threatScreenAttackFlowItem, n)
	for i := range items {
		items[i] = threatScreenAttackFlowItem{
			at:            start.Add(time.Duration(i) * time.Millisecond),
			clientIP:      "198.51.100." + string(rune('1'+i%9)),
			action:        "blocked",
			ruleTriggered: "942100",
		}
	}
	return items
}

func enableAttackFlowSampling(t *testing.T) {
	t.Helper()
	ResetThreatScreenAttackFlowForTest()
	if err := AcquireThreatScreenAttackFlowLease("batch-test", time.Minute, 1); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(ResetThreatScreenAttackFlowForTest)
}

// Given 单批 200 条事件（采样档位=全量）。
// When 记录该批次。
// Then 只发生一次加锁/刷新，环形缓冲按序得到 200 条、序号连续递增。
func TestThreatScreenAttackFlowRecordBatch_singleFlushPerBatch(t *testing.T) {
	enableAttackFlowSampling(t)
	base := threatScreenAttackFlowFlushCalls.Load()

	threatScreenAttackFlowRecordBatch(newAttackFlowBatchItems(200, time.Now()))

	if got := threatScreenAttackFlowFlushCalls.Load() - base; got != 1 {
		t.Fatalf("单批 200 条的加锁/裁剪次数=%d, want 1（批内一次加锁）", got)
	}
	events, next, _ := ThreatScreenAttackFlowSnapshot(0, 1000)
	if len(events) != 200 {
		t.Fatalf("事件条数=%d, want 200", len(events))
	}
	if next != events[len(events)-1].Seq {
		t.Fatalf("next_seq=%d, want 末条序号 %d", next, events[len(events)-1].Seq)
	}
	for i := 1; i < len(events); i++ {
		if events[i].Seq != events[i-1].Seq+1 {
			t.Fatalf("序号不连续：第 %d 条 %d 前置 %d", i, events[i].Seq, events[i-1].Seq)
		}
	}
}

// Given 采样档位 n=4 且单批 4 条事件（旧夹具固定 sample_n=1，n>1 的逐事件
// 采样只被单事件批次覆盖过）。
// When 记录该批次。
// Then 恰好保留每第 4 次尝试的一条：Weight=4、批次顺序保留（第 4 条）、序号
// 递增，且仍只在批级加锁一次。
func TestThreatScreenAttackFlowRecordBatch_sampledMultiEventBatch(t *testing.T) {
	ResetThreatScreenAttackFlowForTest()
	if err := AcquireThreatScreenAttackFlowLease("batch-test-n4", time.Minute, 4); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(ResetThreatScreenAttackFlowForTest)
	base := threatScreenAttackFlowFlushCalls.Load()

	items := newAttackFlowBatchItems(4, time.Now())
	threatScreenAttackFlowRecordBatch(items)

	if got := threatScreenAttackFlowFlushCalls.Load() - base; got != 1 {
		t.Fatalf("单批采样写入的加锁/裁剪次数=%d, want 1（采样不得逐事件加锁）", got)
	}
	events, _, _ := ThreatScreenAttackFlowSnapshot(0, 10)
	if len(events) != 1 {
		t.Fatalf("n=4 采样应从 4 条中保留 1 条，got %d（%v）", len(events), events)
	}
	ev := events[0]
	if ev.Weight != 4 {
		t.Fatalf("Weight=%d, want 4（采样档位必须随事件披露）", ev.Weight)
	}
	if ev.ClientIP != items[3].clientIP || ev.At != items[3].at.UnixMilli() {
		t.Fatalf("采样必须保留第 4 次尝试对应事件（批次顺序/时间），got %+v want ip=%q at=%d", ev, items[3].clientIP, items[3].at.UnixMilli())
	}
	if ev.Seq != 1 {
		t.Fatalf("Seq=%d, want 1（采样后仍严格递增）", ev.Seq)
	}
}

// 等价形状（回归）：超过环形上限的批次仍裁剪到最近 ringMax 条。
func TestThreatScreenAttackFlowRecordBatch_trimsToRingMax(t *testing.T) {
	enableAttackFlowSampling(t)
	total := threatScreenAttackFlowRingMax + 500
	threatScreenAttackFlowRecordBatch(newAttackFlowBatchItems(total, time.Now()))

	events, _, _ := ThreatScreenAttackFlowSnapshot(0, 1000)
	threatScreenAttackFlowMu.Lock()
	ringLen := len(threatScreenAttackFlowEvents)
	last := threatScreenAttackFlowEvents[ringLen-1].Seq
	threatScreenAttackFlowMu.Unlock()
	if ringLen != threatScreenAttackFlowRingMax {
		t.Fatalf("环形长度=%d, want %d", ringLen, threatScreenAttackFlowRingMax)
	}
	if len(events) != 1000 {
		t.Fatalf("快照条数=%d, want 1000（limit 上限）", len(events))
	}
	if last != uint64(total) {
		t.Fatalf("末事件序号=%d, want %d", last, total)
	}
	if events[len(events)-1].Seq != last {
		t.Fatalf("快照末条序号=%d, want %d", events[len(events)-1].Seq, last)
	}
}

// 并发安全：多 goroutine 并发批量写入后，事件数与序号集合必须完整且无重复，
// 且环形缓冲内 Seq 严格递增（消费者按 Seq<=since 线性推进游标，乱序入环
// 会让事件重复返回/游标回退）。（-race 下同时验证加锁正确性）。
func TestThreatScreenAttackFlowRecordBatch_concurrentBatches(t *testing.T) {
	enableAttackFlowSampling(t)
	const (
		writers       = 8
		batchesEach   = 20
		itemsPerBatch = 5
	)
	done := make(chan struct{})
	for range writers {
		go func() {
			defer func() { done <- struct{}{} }()
			for range batchesEach {
				threatScreenAttackFlowRecordBatch(newAttackFlowBatchItems(itemsPerBatch, time.Now()))
			}
		}()
	}
	for range writers {
		<-done
	}

	want := writers * batchesEach * itemsPerBatch
	events, _, _ := ThreatScreenAttackFlowSnapshot(0, want)
	if len(events) != want {
		t.Fatalf("事件条数=%d, want %d", len(events), want)
	}
	seen := make(map[uint64]struct{}, want)
	for i, ev := range events {
		if _, dup := seen[ev.Seq]; dup {
			t.Fatalf("序号 %d 重复", ev.Seq)
		}
		seen[ev.Seq] = struct{}{}
		if i > 0 && ev.Seq <= events[i-1].Seq {
			t.Fatalf("环内序号非严格递增：第 %d 条 %d 前置 %d（跨批乱序会让消费游标重复/停滞）", i, ev.Seq, events[i-1].Seq)
		}
	}
	if len(seen) != want {
		t.Fatalf("唯一序号数=%d, want %d", len(seen), want)
	}
}
