package caddygeoip

// 逐请求正常流量事件环形缓冲（仅在大屏采集租约有效时运行）。
// 有界内存、无 goroutine；前端按 since_seq 增量拉取，用于正常请求光流。
// 安全事件日志仍由审计链独立写入，本缓冲不落盘。

import (
	"encoding/json"
	"net/http"
	"strconv"
	"sync"
	"sync/atomic"
	"time"
)

const trafficEventRingMax = 4096

type trafficEvent struct {
	Seq      uint64 `json:"seq"`
	Country  string `json:"country"`
	Province string `json:"province,omitempty"`
	At       int64  `json:"at"`
}

var (
	trafficEventsMu     sync.Mutex
	trafficEvents       []trafficEvent
	trafficEventSeq     atomic.Uint64
	trafficEventAttempt atomic.Uint64
	trafficEventSampleN atomic.Uint32
)

// resetTrafficEvents 清空环形缓冲与采样计数，但保留单调递增的 seq。
// 前端可能未观察到短暂的采集空窗；若 seq 归零，其单调 since 游标会永久
// 过滤重新从 1 开始的事件。
func resetTrafficEvents() {
	trafficEventsMu.Lock()
	trafficEvents = nil
	trafficEventsMu.Unlock()
	trafficEventAttempt.Store(0)
}

// trafficEventRecord 记录一条正常请求（抽样在写入前完成）。国名键非国家值
// （空/0/Reserved）不记录——与计数桶及聚合端点同口径（历史问题）；异体
// 归一与计数桶同 helper（历史问题，事件流与计数桶键口径一致）。
func trafficEventRecord(country, province string) {
	country = normalizeTrafficCountryKey(country)
	if !trafficCountryKeyValid(country) || !trafficCollectorActive() {
		return
	}
	n := trafficEventSampleN.Load()
	if n == 0 {
		return
	}
	if n > 1 && trafficEventAttempt.Add(1)%uint64(n) != 0 {
		return
	}
	if n <= 1 {
		trafficEventAttempt.Add(1)
	}
	ev := trafficEvent{Seq: trafficEventSeq.Add(1), Country: country, Province: province, At: time.Now().UnixMilli()}
	trafficEventsMu.Lock()
	trafficEvents = append(trafficEvents, ev)
	if len(trafficEvents) > trafficEventRingMax {
		trafficEvents = trafficEvents[len(trafficEvents)-trafficEventRingMax:]
	}
	trafficEventsMu.Unlock()
}

// trafficEventSnapshot 兼容形态（测试/内部两返回值消费方）：丢弃 gap 统计。
func trafficEventSnapshot(since uint64, limit int) ([]trafficEvent, uint64) {
	events, next, _ := trafficEventSnapshotWithGap(since, limit)
	return events, next
}

// trafficEventSnapshotWithGap 返回本批事件、next_seq 与「因环形缓冲溢出而
// 永久丢失」的事件数（gapSkipped>0 即存在空洞）。审计项：此前溢出后
// 消费者只看到 seq 跳号、无任何标记——前端无法区分「抽样稀疏」与「丢事件」。
func trafficEventSnapshotWithGap(since uint64, limit int) ([]trafficEvent, uint64, uint64) {
	if limit <= 0 {
		limit = 200
	}
	if limit > 1000 {
		limit = 1000
	}
	trafficEventsMu.Lock()
	defer trafficEventsMu.Unlock()
	out := make([]trafficEvent, 0, limit)
	// gap：消费者游标 before 最老保留序号 ⇒ 中间的记录已被环形缓冲覆盖。
	// since=0（首屏）不算空洞——它本就只取最新窗口。
	var gapSkipped uint64
	if since > 0 && len(trafficEvents) > 0 && since+1 < trafficEvents[0].Seq {
		gapSkipped = trafficEvents[0].Seq - since - 1
	}
	// since=0 首次拉取只返回最近 limit 条，避免重放整个环形缓冲。
	start := 0
	if since == 0 {
		if len(trafficEvents) > limit {
			start = len(trafficEvents) - limit
		}
	} else {
		for start < len(trafficEvents) && trafficEvents[start].Seq <= since {
			start++
		}
	}
	for _, ev := range trafficEvents[start:] {
		if len(out) >= limit {
			break
		}
		out = append(out, ev)
	}
	// next 必须是本批最后一条的 seq，而不是全局最新 seq；否则一批被 limit
	// 截断时前端会把未返回的事件永久跳过（全量 1000/s 下必现）。
	// 历史问题：入参游标超过本进程已分配的最大 seq，只可能来自上一进程代际
	// （trafficEventSeq 是进程内计数器，Caddy 重启后归零）——此时必须显式回吐
	// 0 要求前端从最新窗口重新追赶。原样回吐 since 会让前端「next_seq <
	// previous 才复位」的判据永不成立，光流在该标签页内永久停更。
	// 注意 since == 已分配 seq（正常追平/空窗）不得复位，否则会被反复重放。
	next := since
	if since > trafficEventSeq.Load() {
		next = 0
	} else if len(out) > 0 {
		next = out[len(out)-1].Seq
	}
	return out, next, gapSkipped
}

func serveTrafficEvents(w http.ResponseWriter, r *http.Request) error {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	since, _ := strconv.ParseUint(r.URL.Query().Get("since"), 10, 64)
	limit, _ := strconv.Atoi(r.URL.Query().Get("limit"))
	events, next, gapSkipped := trafficEventSnapshotWithGap(since, limit)
	_ = json.NewEncoder(w).Encode(map[string]any{
		"enabled":  trafficCollectorActive(),
		"events":   events,
		"next_seq": next,
		"sample_n": trafficEventSampleN.Load(),
		// 环形缓冲溢出导致的永久空洞（>0=本批之前有事件未送达，前端应
		// 丢弃「连续光流」假设并跳到 next_seq 继续追赶）。
		"gap":         gapSkipped > 0,
		"gap_skipped": gapSkipped,
	})
	return nil
}
