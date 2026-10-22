package caddygeoip

import (
	"sync"
	"testing"
	"time"
)

func trafficEventSnapshot(since uint64, limit int) ([]trafficEvent, uint64) {
	events, next, _ := trafficEventSnapshotWithGap(since, limit)
	return events, next
}

func TestTrafficEventRing_recordsAndSnapshots(t *testing.T) {
	resetTrafficState(t)
	resetTrafficEvents()
	trafficCollectorEnabled.Store(false)
	if err := acquireTrafficLease("events-test", time.Minute, 1); err != nil {
		t.Fatal(err)
	}
	trafficEventRecord("中国", "广东省")
	trafficEventRecord("美国", "")
	events, next := trafficEventSnapshot(0, 10)
	if next != 2 || len(events) != 2 {
		t.Fatalf("next=%d events=%+v", next, events)
	}
	if events[0].Country != "中国" || events[0].Province != "广东省" {
		t.Fatalf("event0=%+v", events[0])
	}
	more, _ := trafficEventSnapshot(events[0].Seq, 10)
	// 「美国」入口归一为英文规范名。
	if len(more) != 1 || more[0].Country != "United States" {
		t.Fatalf("incremental=%+v", more)
	}
	releaseTrafficLease("events-test")
	if trafficEventSampleN.Load() != 0 {
		t.Fatalf("sample_n=%d, want 0 after release", trafficEventSampleN.Load())
	}
}

// trafficEventSeq 是进程内计数器，Caddy 重启后归零；前端则保留
// 上一代际的高水位 since。服务端若不判别代际而把入参 since 原样回吐，前端
// 「next_seq < previous 才复位」的判据永不成立 → 正常流量光流永久停更。
func TestTrafficEventSnapshot_cursorAheadOfGenerationResets(t *testing.T) {
	resetTrafficState(t)
	resetTrafficEvents()
	trafficEventSeq.Store(0)
	trafficCollectorEnabled.Store(false)
	if err := acquireTrafficLease("generation-test", time.Minute, 1); err != nil {
		t.Fatal(err)
	}
	defer releaseTrafficLease("generation-test")
	trafficEventRecord("中国", "广东省") // 新一代际的 seq=1

	// 上一代际的高水位游标（大于本进程已分配的 seq）→ 显式要求前端从 0 追赶。
	events, next := trafficEventSnapshot(500, 10)
	if next != 0 {
		t.Fatalf("next=%d, want 0 (stale-generation cursor must reset the client)", next)
	}
	if len(events) != 0 {
		t.Fatalf("stale cursor must not return out-of-window events: %+v", events)
	}
	// 复位后按 since=0 的首拉语义拿到最近窗口。
	events, next = trafficEventSnapshot(next, 10)
	if len(events) != 1 || next != 1 {
		t.Fatalf("after reset events=%+v next=%d, want one event at seq 1", events, next)
	}
	// 追平形态（since == 已分配最大 seq）不得复位，否则正常空窗会被反复重放。
	if _, caught := trafficEventSnapshot(1, 10); caught != 1 {
		t.Fatalf("caught-up next=%d, want 1 (must not reset)", caught)
	}
}

func TestTrafficEventRing_sampling(t *testing.T) {
	resetTrafficState(t)
	resetTrafficEvents()
	trafficCollectorEnabled.Store(false)
	if err := acquireTrafficLease("sample-test", time.Minute, 8); err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 16; i++ {
		trafficEventRecord("中国", "广东省")
	}
	events, _ := trafficEventSnapshot(0, 100)
	if len(events) != 2 {
		t.Fatalf("sampled events=%d, want 2 (1/8 of 16)", len(events))
	}
	releaseTrafficLease("sample-test")
}

func TestTrafficEventRing_concurrentSequenceOrder(t *testing.T) {
	resetTrafficState(t)
	resetTrafficEvents()
	trafficCollectorEnabled.Store(false)
	if err := acquireTrafficLease("concurrent-test", time.Minute, 1); err != nil {
		t.Fatal(err)
	}
	defer releaseTrafficLease("concurrent-test")

	const writers = 16
	const eventsPerWriter = 64
	start := make(chan struct{})
	var wg sync.WaitGroup
	for range writers {
		wg.Add(1)
		go func() {
			defer wg.Done()
			<-start
			for range eventsPerWriter {
				trafficEventRecord("中国", "广东省")
			}
		}()
	}
	close(start)
	wg.Wait()

	events, _ := trafficEventSnapshot(0, 1000)
	if len(events) != 1000 {
		t.Fatalf("events=%d, want latest 1000", len(events))
	}
	for i := 1; i < len(events); i++ {
		if events[i].Seq <= events[i-1].Seq {
			t.Fatalf("ring sequence is not strictly increasing at %d: previous=%d current=%d", i, events[i-1].Seq, events[i].Seq)
		}
	}
}
