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
// （空/0/Reserved）不记录——与计数桶及聚合端点同口径（E81-历史问题）。
func trafficEventRecord(country, province string) {
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

func trafficEventSnapshot(since uint64, limit int) ([]trafficEvent, uint64) {
	if limit <= 0 {
		limit = 200
	}
	if limit > 1000 {
		limit = 1000
	}
	trafficEventsMu.Lock()
	defer trafficEventsMu.Unlock()
	out := make([]trafficEvent, 0, limit)
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
	next := since
	if len(out) > 0 {
		next = out[len(out)-1].Seq
	}
	return out, next
}

func serveTrafficEvents(w http.ResponseWriter, r *http.Request) error {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	since, _ := strconv.ParseUint(r.URL.Query().Get("since"), 10, 64)
	limit, _ := strconv.Atoi(r.URL.Query().Get("limit"))
	events, next := trafficEventSnapshot(since, limit)
	_ = json.NewEncoder(w).Encode(map[string]any{
		"enabled":  trafficCollectorActive(),
		"events":   events,
		"next_seq": next,
		"sample_n": trafficEventSampleN.Load(),
	})
	return nil
}
