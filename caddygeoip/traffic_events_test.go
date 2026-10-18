package caddygeoip

import (
	"testing"
	"time"
)

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
	if len(more) != 1 || more[0].Country != "美国" {
		t.Fatalf("incremental=%+v", more)
	}
	releaseTrafficLease("events-test")
	if trafficEventSampleN.Load() != 0 {
		t.Fatalf("sample_n=%d, want 0 after release", trafficEventSampleN.Load())
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
