package caddygeoip

import (
	"bytes"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

func TestTrafficLease_enableRelease(t *testing.T) {
	resetTrafficState(t)
	trafficCollectorEnabled.Store(false)

	if trafficCollectorActive() {
		t.Fatal("collector should start disabled after explicit reset")
	}
	if err := acquireTrafficLease("screen-1", time.Minute, 1); err != nil {
		t.Fatal(err)
	}
	if !trafficCollectorActive() {
		t.Fatal("collector should be enabled after lease")
	}
	releaseTrafficLease("screen-1")
	if trafficCollectorActive() {
		t.Fatal("collector should be disabled after last lease release")
	}
}

func TestTrafficCollectorAdmin_postGetDelete(t *testing.T) {
	resetTrafficState(t)
	trafficCollectorEnabled.Store(false)

	body := bytes.NewBufferString(`{"lease_id":"tab-1","ttl_ms":30000}`)
	rec := httptest.NewRecorder()
	if err := serveTrafficCollector(rec, httptest.NewRequest(http.MethodPost, "/lb/traffic-collector", body)); err != nil {
		t.Fatal(err)
	}
	if rec.Code != http.StatusOK || !trafficCollectorActive() {
		t.Fatalf("post status=%d enabled=%v", rec.Code, trafficCollectorActive())
	}

	rec = httptest.NewRecorder()
	if err := serveTrafficCollector(rec, httptest.NewRequest(http.MethodDelete, "/lb/traffic-collector?lease_id=tab-1", nil)); err != nil {
		t.Fatal(err)
	}
	if trafficCollectorActive() {
		t.Fatal("collector should be disabled after DELETE")
	}
}

func TestTrafficLease_renewalPreservesEventsAndSequence(t *testing.T) {
	resetTrafficState(t)
	resetTrafficEvents()
	trafficEventSeq.Store(0)
	trafficCollectorEnabled.Store(false)

	if err := acquireTrafficLease("screen-renew", time.Minute, 1); err != nil {
		t.Fatal(err)
	}
	trafficEventRecord("中国", "广东省")
	before, beforeNext := trafficEventSnapshot(0, 10)
	if len(before) != 1 || beforeNext != 1 {
		t.Fatalf("initial events=%+v next=%d, want one event at seq 1", before, beforeNext)
	}

	// 同一 lease_id 心跳续租不得清空环形缓冲。
	if err := acquireTrafficLease("screen-renew", time.Minute, 1); err != nil {
		t.Fatal(err)
	}
	afterRenew, afterRenewNext := trafficEventSnapshot(0, 10)
	if len(afterRenew) != 1 || afterRenewNext != beforeNext {
		t.Fatalf("renewal reset events: events=%+v next=%d, want preserved next=%d", afterRenew, afterRenewNext, beforeNext)
	}
	trafficEventRecord("美国", "")
	afterSecond, afterSecondNext := trafficEventSnapshot(beforeNext, 10)
	if len(afterSecond) != 1 || afterSecondNext != beforeNext+1 {
		t.Fatalf("post-renewal events=%+v next=%d, want monotonic seq=%d", afterSecond, afterSecondNext, beforeNext+1)
	}

	// 最后一个租约释放仍清空旧环，但重新采集后的 seq 必须继续单调，避免
	// 前端在两轮轮询之间未观察到 disabled 时永久落后于重新从 1 开始的序列。
	releaseTrafficLease("screen-renew")
	if err := acquireTrafficLease("screen-renew", time.Minute, 1); err != nil {
		t.Fatal(err)
	}
	trafficEventRecord("日本", "")
	afterRestart, restartNext := trafficEventSnapshot(afterSecondNext, 10)
	if len(afterRestart) != 1 || restartNext <= afterSecondNext {
		t.Fatalf("restarted events=%+v next=%d, want seq greater than %d", afterRestart, restartNext, afterSecondNext)
	}
}
