package caddygeoip

// 流量采集租约：大屏打开时前端申请，关闭/崩溃后 TTL 过期自动关闭。
// 采集关闭时 blocked_counter 每请求只做一次 atomic load，不再读 GeoIP 变量、
// 不再做秒计数/map 查找。安全事件日志/GeoIP 解析不受影响。

import (
	"encoding/json"
	"errors"
	"net/http"
	"strconv"
	"sync"
	"sync/atomic"
	"time"
)

const (
	trafficLeaseTTLDefault = 30 * time.Second
	trafficLeaseTTLMax     = 120 * time.Second
	trafficLeaseTTLMin     = 5 * time.Second
)

type trafficLease struct {
	expires time.Time
	sampleN uint32
}

var (
	trafficCollectorEnabled atomic.Bool
	trafficLeasesMu         sync.Mutex
	trafficLeases           = map[string]trafficLease{}
	trafficLeaseTimer       *time.Timer
)

func trafficCollectorActive() bool {
	return trafficCollectorEnabled.Load()
}

func acquireTrafficLease(id string, ttl time.Duration, sampleN uint32) error {
	if id == "" {
		return errors.New("lease_id required")
	}
	if ttl <= 0 {
		ttl = trafficLeaseTTLDefault
	}
	if ttl < trafficLeaseTTLMin {
		ttl = trafficLeaseTTLMin
	}
	if ttl > trafficLeaseTTLMax {
		ttl = trafficLeaseTTLMax
	}
	// sampleN=0 表示关闭逐请求事件（仍可保留聚合计数）。
	trafficLeasesMu.Lock()
	trafficLeases[id] = trafficLease{expires: time.Now().Add(ttl), sampleN: sampleN}
	trafficCollectorEnabled.Store(true)
	refreshTrafficEventSampleLocked()
	if len(trafficLeases) == 1 {
		resetTrafficEvents()
	}
	scheduleTrafficLeaseCleanupLocked()
	trafficLeasesMu.Unlock()
	return nil
}

func releaseTrafficLease(id string) {
	trafficLeasesMu.Lock()
	delete(trafficLeases, id)
	if len(trafficLeases) == 0 {
		trafficCollectorEnabled.Store(false)
		trafficEventSampleN.Store(0)
		resetTrafficEvents()
		if trafficLeaseTimer != nil {
			trafficLeaseTimer.Stop()
			trafficLeaseTimer = nil
		}
	} else {
		refreshTrafficEventSampleLocked()
		scheduleTrafficLeaseCleanupLocked()
	}
	trafficLeasesMu.Unlock()
}

// refreshTrafficEventSampleLocked 多标签页取最密采样（最小 N），null=关闭。
func refreshTrafficEventSampleLocked() {
	if len(trafficLeases) == 0 {
		trafficEventSampleN.Store(0)
		return
	}
	min := uint32(0)
	for _, lease := range trafficLeases {
		n := lease.sampleN
		if n == 0 {
			continue
		}
		if min == 0 || n < min {
			min = n
		}
	}
	trafficEventSampleN.Store(min)
}

// scheduleTrafficLeaseCleanupLocked 只保留一个定时器，按最近过期时间清理；
// 无租约时立即关闭采集。调用方必须持有 trafficLeasesMu。
func scheduleTrafficLeaseCleanupLocked() {
	if len(trafficLeases) == 0 {
		trafficCollectorEnabled.Store(false)
		trafficEventSampleN.Store(0)
		resetTrafficEvents()
		if trafficLeaseTimer != nil {
			trafficLeaseTimer.Stop()
			trafficLeaseTimer = nil
		}
		return
	}
	var next time.Time
	for _, lease := range trafficLeases {
		if next.IsZero() || lease.expires.Before(next) {
			next = lease.expires
		}
	}
	delay := time.Until(next)
	if delay < 0 {
		delay = 0
	}
	if trafficLeaseTimer != nil {
		trafficLeaseTimer.Stop()
	}
	trafficLeaseTimer = time.AfterFunc(delay, func() {
		trafficLeasesMu.Lock()
		now := time.Now()
		for id, lease := range trafficLeases {
			if !lease.expires.After(now) {
				delete(trafficLeases, id)
			}
		}
		if len(trafficLeases) == 0 {
			trafficCollectorEnabled.Store(false)
			trafficEventSampleN.Store(0)
			resetTrafficEvents()
			trafficLeaseTimer = nil
		} else {
			refreshTrafficEventSampleLocked()
			scheduleTrafficLeaseCleanupLocked()
		}
		trafficLeasesMu.Unlock()
	})
}

// trafficLeaseRequest admin API 请求体。
type trafficLeaseRequest struct {
	LeaseID string `json:"lease_id"`
	TTLMs   int64  `json:"ttl_ms"`
	SampleN uint32 `json:"sample_n"`
}

// serveTrafficCollector admin API：POST 申请/续租，DELETE 释放，GET 状态。
func serveTrafficCollector(w http.ResponseWriter, r *http.Request) error {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	switch r.Method {
	case http.MethodPost:
		var req trafficLeaseRequest
		if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 4096)).Decode(&req); err != nil {
			http.Error(w, `{"error":"invalid body"}`, http.StatusBadRequest)
			return nil
		}
		if err := acquireTrafficLease(req.LeaseID, time.Duration(req.TTLMs)*time.Millisecond, req.SampleN); err != nil {
			http.Error(w, `{"error":"lease_id required"}`, http.StatusBadRequest)
			return nil
		}
		_, _ = w.Write([]byte(`{"enabled":true}`))
		return nil
	case http.MethodDelete:
		var req trafficLeaseRequest
		if r.ContentLength != 0 {
			_ = json.NewDecoder(http.MaxBytesReader(w, r.Body, 4096)).Decode(&req)
		}
		if req.LeaseID == "" {
			req.LeaseID = r.URL.Query().Get("lease_id")
		}
		releaseTrafficLease(req.LeaseID)
		_, _ = w.Write([]byte(`{"enabled":false}`))
		return nil
	case http.MethodGet:
		trafficLeasesMu.Lock()
		n := len(trafficLeases)
		trafficLeasesMu.Unlock()
		_, _ = w.Write([]byte(`{"enabled":` + strconv.FormatBool(trafficCollectorActive()) + `,"leases":` + strconv.Itoa(n) + `}`))
		return nil
	default:
		http.Error(w, `{"error":"method not allowed"}`, http.StatusMethodNotAllowed)
		return nil
	}
}
