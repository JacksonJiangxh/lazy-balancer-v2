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

// TTL 到期自动关闭（租约核心语义）：标签页崩溃/被强关时没有 DELETE，采集
// 必须在租约到期后自行停止。把到期时间拨到过去并重排生产清理定时器
// （delay<=0 立即触发），驱动真实清理回调——不依赖真实等待 TTL。
func TestTrafficLease_expiresAutomatically(t *testing.T) {
	resetTrafficState(t)
	trafficCollectorEnabled.Store(false)
	if err := acquireTrafficLease("expire-1", time.Minute, 1); err != nil {
		t.Fatal(err)
	}
	if !trafficCollectorActive() {
		t.Fatal("租约生效后采集应开启")
	}

	trafficLeasesMu.Lock()
	lease := trafficLeases["expire-1"]
	lease.expires = time.Now().Add(-time.Second)
	trafficLeases["expire-1"] = lease
	scheduleTrafficLeaseCleanupLocked()
	trafficLeasesMu.Unlock()

	deadline := time.Now().Add(2 * time.Second)
	for {
		trafficLeasesMu.Lock()
		remaining := len(trafficLeases)
		trafficLeasesMu.Unlock()
		if remaining == 0 && !trafficCollectorActive() {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("TTL 到期后未自动清理：remaining leases=%d enabled=%v", remaining, trafficCollectorActive())
		}
		time.Sleep(5 * time.Millisecond)
	}

	trafficLeasesMu.Lock()
	timerCleared := trafficLeaseTimer == nil
	trafficLeasesMu.Unlock()
	if !timerCleared {
		t.Fatal("无租约后清理定时器必须停止并清空（防泄漏）")
	}
	if sample := trafficEventSampleN.Load(); sample != 0 {
		t.Fatalf("sample_n=%d, want 0 after TTL expiry", sample)
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

// 租约表无界——管理端 POST 原样接受调用方投递的 lease_id，单条
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

// 条目数上限——满表时拒绝新键，续租既有键不受影响（不淘汰活跃
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

// DELETE 的畸形 JSON 不得中断 query 回退释放（旧实现忽略解码
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

// POST 的畸形/负 sample_n 必须 400 且不建租约（uint32 解码拒绝
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

// sample_n 越界钳制：租约申请不限身份，sample_n 不设上限会把逐请求事件流
// 稀释到近似 0（N 越大采样越稀）。Ruling：收敛而非 400——前端只发合法值，
// 收敛保持既有契约且不新增错误分支；0 保留「关闭逐请求事件」语义。
func TestTrafficLease_clampsSampleNToSupportedRange(t *testing.T) {
	resetTrafficState(t)
	trafficCollectorEnabled.Store(false)

	if err := acquireTrafficLease("clamp-max", time.Minute, 1_000_000); err != nil {
		t.Fatal(err)
	}
	if err := acquireTrafficLease("clamp-zero", time.Minute, 0); err != nil {
		t.Fatal(err)
	}
	if err := acquireTrafficLease("clamp-ok", time.Minute, 3); err != nil {
		t.Fatal(err)
	}

	trafficLeasesMu.Lock()
	gotMax := trafficLeases["clamp-max"].sampleN
	gotZero := trafficLeases["clamp-zero"].sampleN
	gotOK := trafficLeases["clamp-ok"].sampleN
	trafficLeasesMu.Unlock()

	if gotMax != 8 {
		t.Fatalf("sample_n=1000000 stored as %d, want clamped to 8", gotMax)
	}
	if gotZero != 0 {
		t.Fatalf("sample_n=0 stored as %d, want 0 (逐请求事件关闭语义)", gotZero)
	}
	if gotOK != 3 {
		t.Fatalf("sample_n=3 stored as %d, want unchanged", gotOK)
	}
	// 多租约取最密采样：0(关闭) 不参与，max(8) 与 3 取 min=3。
	if got := trafficEventSampleN.Load(); got != 3 {
		t.Fatalf("effective sample_n=%d, want 3", got)
	}
}

// 多租约下释放其一：DELETE 必须报告释放后的真实状态（仍 enabled、租约数
// 递减），与 GET 完全同形——此前无条件回 {"enabled":false}，调用方会误以为
// 采集已停止。
func TestTrafficCollectorAdmin_deleteReportsLiveState(t *testing.T) {
	resetTrafficState(t)
	trafficCollectorEnabled.Store(false)

	for _, id := range []string{"tab-1", "tab-2"} {
		body := bytes.NewBufferString(`{"lease_id":"` + id + `","ttl_ms":30000}`)
		rec := httptest.NewRecorder()
		if err := serveTrafficCollector(rec, httptest.NewRequest(http.MethodPost, "/lb/traffic-collector", body)); err != nil {
			t.Fatal(err)
		}
		if rec.Code != http.StatusOK {
			t.Fatalf("post %s status=%d", id, rec.Code)
		}
	}

	rec := httptest.NewRecorder()
	if err := serveTrafficCollector(rec, httptest.NewRequest(http.MethodDelete, "/lb/traffic-collector?lease_id=tab-1", nil)); err != nil {
		t.Fatal(err)
	}
	deleteBody := rec.Body.String()
	if deleteBody != `{"enabled":true,"leases":1}` {
		t.Fatalf("DELETE 后状态=%s, want enabled=true leases=1（仍有活跃租约）", deleteBody)
	}

	rec = httptest.NewRecorder()
	if err := serveTrafficCollector(rec, httptest.NewRequest(http.MethodGet, "/lb/traffic-collector", nil)); err != nil {
		t.Fatal(err)
	}
	if got := rec.Body.String(); got != deleteBody {
		t.Fatalf("GET=%s, DELETE=%s（两路由必须同形同值）", got, deleteBody)
	}

	// 末租约释放后如实报告关闭。
	rec = httptest.NewRecorder()
	if err := serveTrafficCollector(rec, httptest.NewRequest(http.MethodDelete, "/lb/traffic-collector?lease_id=tab-2", nil)); err != nil {
		t.Fatal(err)
	}
	if got := rec.Body.String(); got != `{"enabled":false,"leases":0}` {
		t.Fatalf("末租约释放后状态=%s, want enabled=false leases=0", got)
	}
}
