package caddygeoip

import (
	"bytes"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
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

// 历史问题：租约表无界——管理端 POST 原样接受调用方投递的 lease_id，单条
// 4KiB ID 长期驻留（TTL ≤120s），条目数也无上限。ID 长度必须设上限。
func TestTrafficLease_rejectsOversizedID(t *testing.T) {
	resetTrafficState(t)
	trafficCollectorEnabled.Store(false)

	// 运行形态：64 是常量上限口径（trafficLeaseIDMaxLen）；65 字节必须拒绝。
	if err := acquireTrafficLease(strings.Repeat("x", 65), time.Minute, 1); err == nil {
		t.Fatal("oversized lease_id must be rejected")
	}
	trafficLeasesMu.Lock()
	n := len(trafficLeases)
	trafficLeasesMu.Unlock()
	if n != 0 {
		t.Fatalf("rejected lease must not be stored, got %d entries", n)
	}
	if trafficCollectorActive() {
		t.Fatal("rejected lease must not enable the collector")
	}

	// 上限边界：64 字节仍合法（与上限等值）。
	if err := acquireTrafficLease(strings.Repeat("y", 64), time.Minute, 1); err != nil {
		t.Fatalf("64-byte lease_id must be accepted: %v", err)
	}
	releaseTrafficLease(strings.Repeat("y", 64))

	// 管理端形态：超长 ID 必须是 400 而不是 200（app 端点原样转发该状态）。
	rec := httptest.NewRecorder()
	body := bytes.NewBufferString(`{"lease_id":"` + strings.Repeat("z", 65) + `","ttl_ms":30000}`)
	if err := serveTrafficCollector(rec, httptest.NewRequest(http.MethodPost, "/lb/traffic-collector", body)); err != nil {
		t.Fatal(err)
	}
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("oversized lease_id over admin API: status=%d, want 400", rec.Code)
	}
	if trafficCollectorActive() {
		t.Fatal("oversized id must not enable the collector")
	}
}

// 历史问题：条目数上限——满表时拒绝新键，续租既有键不受影响（不淘汰活跃
// 租约，否则真实标签页会静默失去采集）。
func TestTrafficLease_entryCapRejectsNewKeys(t *testing.T) {
	resetTrafficState(t)
	trafficCollectorEnabled.Store(false)
	t.Cleanup(func() {
		trafficLeasesMu.Lock()
		ids := make([]string, 0, len(trafficLeases))
		for id := range trafficLeases {
			ids = append(ids, id)
		}
		trafficLeasesMu.Unlock()
		for _, id := range ids {
			releaseTrafficLease(id)
		}
	})

	// 64 = 常量上限口径（trafficLeasesMax），按字面值断言上限语义。
	const maxLeases = 64
	for i := range maxLeases {
		if err := acquireTrafficLease(fmt.Sprintf("tab-%02d", i), time.Minute, 1); err != nil {
			t.Fatalf("lease %d rejected before cap: %v", i, err)
		}
	}
	// 第 65 个新键必须拒绝。
	if err := acquireTrafficLease("overflow", time.Minute, 1); err == nil {
		t.Fatal("new lease must be rejected at the entry cap")
	}
	// 既有键续租不受上限影响（心跳路径不能因满表而断采）。
	if err := acquireTrafficLease("tab-00", time.Minute, 1); err != nil {
		t.Fatalf("renewal at cap must still succeed: %v", err)
	}
	trafficLeasesMu.Lock()
	n := len(trafficLeases)
	_, overflowed := trafficLeases["overflow"]
	trafficLeasesMu.Unlock()
	if n != maxLeases {
		t.Fatalf("leases=%d, want %d (rejection must not evict active leases)", n, maxLeases)
	}
	if overflowed {
		t.Fatal("rejected lease must not be present in the table")
	}
	if !trafficCollectorActive() {
		t.Fatal("collector must stay enabled for the active leases")
	}
}

// 历史问题：DELETE 的畸形 JSON 不得中断 query 回退释放（旧实现忽略解码
// 错误后继续走 query 回退，需钉住该形状不被「改写为严格 400」误伤）。
func TestTrafficCollectorAdmin_deleteMalformedBody(t *testing.T) {
	resetTrafficState(t)
	trafficCollectorEnabled.Store(false)
	if err := acquireTrafficLease("tab-del", time.Minute, 1); err != nil {
		t.Fatal(err)
	}
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodDelete, "/lb/traffic-collector?lease_id=tab-del", bytes.NewBufferString(`{"lease_id":`))
	req.ContentLength = int64(len(`{"lease_id":`))
	if err := serveTrafficCollector(rec, req); err != nil {
		t.Fatal(err)
	}
	trafficLeasesMu.Lock()
	n := len(trafficLeases)
	trafficLeasesMu.Unlock()
	if n != 0 {
		t.Fatalf("DELETE with malformed body must still release via query, leases=%d", n)
	}
	if trafficCollectorActive() {
		t.Fatal("collector should be disabled after DELETE")
	}
}

// 历史问题：POST 的畸形/负 sample_n 必须 400 且不建租约（uint32 解码拒绝
// 负值，不会静默折叠成 0=关闭事件流）。
func TestTrafficCollectorAdmin_rejectsNegativeSampleN(t *testing.T) {
	resetTrafficState(t)
	trafficCollectorEnabled.Store(false)

	rec := httptest.NewRecorder()
	body := bytes.NewBufferString(`{"lease_id":"tab-neg","sample_n":-1}`)
	if err := serveTrafficCollector(rec, httptest.NewRequest(http.MethodPost, "/lb/traffic-collector", body)); err != nil {
		t.Fatal(err)
	}
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("negative sample_n: status=%d, want 400", rec.Code)
	}
	trafficLeasesMu.Lock()
	n := len(trafficLeases)
	trafficLeasesMu.Unlock()
	if n != 0 {
		t.Fatalf("invalid body must not create a lease, got %d entries", n)
	}
	if trafficCollectorActive() {
		t.Fatal("invalid body must not enable the collector")
	}
}
