package caddygeoip

import (
	"encoding/json"
	"math"
	"net/http"
	"net/http/httptest"
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

// since 取 MaxUint64 时 since+1 回绕为 0：gap 判定若用 +1 比较会把
// 「无空洞」误判成 gapSkipped=firstSeq 的无意义值。用减法比较后回绕安全；
// 代际复位（next=0）语义不受影响。
func TestTrafficEventSnapshot_maxCursorNoGapWrap(t *testing.T) {
	resetTrafficState(t)
	resetTrafficEvents()
	trafficEventSeq.Store(0)
	trafficCollectorEnabled.Store(false)
	if err := acquireTrafficLease("maxcursor-test", time.Minute, 1); err != nil {
		t.Fatal(err)
	}
	defer releaseTrafficLease("maxcursor-test")
	trafficEventRecord("中国", "广东省") // 新一代际的 seq=1

	events, next, gapSkipped := trafficEventSnapshotWithGap(math.MaxUint64, 10)
	if gapSkipped != 0 {
		t.Fatalf("gapSkipped=%d, want 0（since=MaxUint64 回绕不得误判空洞）", gapSkipped)
	}
	if next != 0 {
		t.Fatalf("next=%d, want 0（超代际游标仍复位）", next)
	}
	if len(events) != 0 {
		t.Fatalf("events=%+v, want empty", events)
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

// 环形缓冲溢出的正向披露：越过上限后最早的事件永久丢失，服务端必须以
// gap/gap_skipped 显式告知（前端据此放弃「连续光流」假设并跳到 next_seq）。
func TestTrafficEventSnapshot_gapAfterRingOverflow(t *testing.T) {
	resetTrafficState(t)
	resetTrafficEvents()
	trafficEventSeq.Store(0)
	trafficCollectorEnabled.Store(false)
	if err := acquireTrafficLease("overflow-test", time.Minute, 1); err != nil {
		t.Fatal(err)
	}
	defer releaseTrafficLease("overflow-test")

	const total = trafficEventRingMax + 4 // 环保留 seq 5..4100
	for i := 0; i < total; i++ {
		trafficEventRecord("中国", "广东省")
	}
	if got := trafficEventSeq.Load(); got != total {
		t.Fatalf("seq=%d, want %d", got, total)
	}

	// 遗留游标停在溢出前：seq 2..4 已永久丢失。
	events, next, gapSkipped := trafficEventSnapshotWithGap(1, 1000)
	if gapSkipped != 3 {
		t.Fatalf("gap_skipped=%d, want 3（since=1 与最老保留 seq=5 之间）", gapSkipped)
	}
	if len(events) != 1000 {
		t.Fatalf("events=%d, want 1000 (limit)", len(events))
	}
	if events[0].Seq != 5 {
		t.Fatalf("首批首条 seq=%d, want 5（已按环形容量截断）", events[0].Seq)
	}
	if next != events[len(events)-1].Seq {
		t.Fatalf("next=%d, want %d (本批最后一条)", next, events[len(events)-1].Seq)
	}

	// 游标落在保留窗口内不报空洞。
	if _, _, skipped := trafficEventSnapshotWithGap(5, 1000); skipped != 0 {
		t.Fatalf("since 在保留窗口内时 gap_skipped=%d, want 0", skipped)
	}

	// 追平拉取：无事件、无空洞、next 不回退。
	events, next, skipped := trafficEventSnapshotWithGap(total, 1000)
	if len(events) != 0 || skipped != 0 || next != total {
		t.Fatalf("追平拉取 events=%d skipped=%d next=%d", len(events), skipped, next)
	}
}

// HTTP 级形状：响应头与全字段（enabled/events/next_seq/sample_n/gap/
// gap_skipped）都必须存在，溢出披露经 HTTP 路径同样可见。
func TestServeTrafficEvents_httpShape(t *testing.T) {
	resetTrafficState(t)
	resetTrafficEvents()
	trafficEventSeq.Store(0)
	trafficCollectorEnabled.Store(false)
	if err := acquireTrafficLease("http-shape-test", time.Minute, 1); err != nil {
		t.Fatal(err)
	}
	defer releaseTrafficLease("http-shape-test")
	for i := 0; i < trafficEventRingMax+4; i++ {
		trafficEventRecord("中国", "广东省")
	}

	rec := httptest.NewRecorder()
	if err := serveTrafficEvents(rec, httptest.NewRequest(http.MethodGet, "/lb/traffic-events?since=1&limit=1000", nil)); err != nil {
		t.Fatal(err)
	}
	if ct := rec.Header().Get("Content-Type"); ct != "application/json" {
		t.Fatalf("Content-Type=%q, want application/json", ct)
	}
	if cc := rec.Header().Get("Cache-Control"); cc != "no-store" {
		t.Fatalf("Cache-Control=%q, want no-store", cc)
	}
	var payload struct {
		Enabled    bool           `json:"enabled"`
		Events     []trafficEvent `json:"events"`
		NextSeq    uint64         `json:"next_seq"`
		SampleN    uint32         `json:"sample_n"`
		Gap        bool           `json:"gap"`
		GapSkipped uint64         `json:"gap_skipped"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &payload); err != nil {
		t.Fatalf("decode body %q: %v", rec.Body.String(), err)
	}
	if !payload.Enabled || payload.SampleN != 1 {
		t.Fatalf("enabled=%v sample_n=%d, want true/1", payload.Enabled, payload.SampleN)
	}
	if !payload.Gap || payload.GapSkipped != 3 {
		t.Fatalf("gap=%v gap_skipped=%d, want true/3", payload.Gap, payload.GapSkipped)
	}
	if len(payload.Events) != 1000 || payload.Events[0].Seq != 5 {
		t.Fatalf("events=%d first=%d, want 1000/5", len(payload.Events), payload.Events[0].Seq)
	}
	if payload.NextSeq != payload.Events[len(payload.Events)-1].Seq {
		t.Fatalf("next_seq=%d, want %d", payload.NextSeq, payload.Events[len(payload.Events)-1].Seq)
	}
}

// sample_n=0（只留聚合计数、关闭逐请求事件）必须端到端不产出事件且不推进
// seq；追加采样租约后事件流恢复，有效 N 取最小非零值。
func TestTrafficEventRing_sampleNZeroDisablesEventStream(t *testing.T) {
	resetTrafficState(t)
	resetTrafficEvents()
	trafficEventSeq.Store(0)
	trafficCollectorEnabled.Store(false)
	if err := acquireTrafficLease("zero-sample-test", time.Minute, 0); err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 100; i++ {
		trafficEventRecord("中国", "广东省")
	}
	if got := trafficEventSeq.Load(); got != 0 {
		t.Fatalf("sample_n=0 时不得推进事件序列，seq=%d", got)
	}
	if events, _ := trafficEventSnapshot(0, 100); len(events) != 0 {
		t.Fatalf("sample_n=0 时环形缓冲必须为空，events=%+v", events)
	}

	// 追加采样租约：有效 N 取最小非零值（2），10 条记录产出 5 条事件。
	if err := acquireTrafficLease("sample-two-test", time.Minute, 2); err != nil {
		t.Fatal(err)
	}
	defer releaseTrafficLease("sample-two-test")
	for i := 0; i < 10; i++ {
		trafficEventRecord("中国", "广东省")
	}
	if got := trafficEventSeq.Load(); got != 5 {
		t.Fatalf("有效 N=2 时 10 条记录应产出 5 条事件，seq=%d", got)
	}
	if n := trafficEventSampleN.Load(); n != 2 {
		t.Fatalf("sample_n=%d, want 2（最小非零采样）", n)
	}
	releaseTrafficLease("zero-sample-test")
}
