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
	// trafficLeaseIDMaxLen 租约 ID 长度上限（PL历史问题）：管理端 POST 原样接受
	// 调用方投递的 lease_id（app 端点仅限 body 4096B），不设上限时单个键即可
	// 占 4KiB 并驻留至 TTL 上限。正常形态每标签页一个 UUID（36 字符）。
	trafficLeaseIDMaxLen = 64
	// trafficLeasesMax 租约表条目上限（PL历史问题）：正常形态条目数=并发打开的
	// 大屏标签页数（个位数）。满时拒绝新键，既有键续租照常——绝不淘汰活跃租约
	// （淘汰会让真实标签页静默失去采集）。
	trafficLeasesMax = 64
)

// 租约申请失败原因（固定文案，可直接拼进 JSON error 字段）。
var (
	errTrafficLeaseIDRequired = errors.New("lease_id required")
	errTrafficLeaseIDTooLong  = errors.New("lease_id too long")
	errTrafficLeaseLimit      = errors.New("too many leases")
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
		return errTrafficLeaseIDRequired
	}
	// PL历史问题：字节长度上限（正常形态 UUID 36 字节），超限直接拒绝。
	if len(id) > trafficLeaseIDMaxLen {
		return errTrafficLeaseIDTooLong
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
	// PL历史问题：条目上限只拦新键——续租既有键走原路径（否则满表会让真实
	// 标签页的心跳失败而静默断采）。
	if _, exists := trafficLeases[id]; !exists && len(trafficLeases) >= trafficLeasesMax {
		trafficLeasesMu.Unlock()
		return errTrafficLeaseLimit
	}
	wasEmpty := len(trafficLeases) == 0
	trafficLeases[id] = trafficLease{expires: time.Now().Add(ttl), sampleN: sampleN}
	trafficCollectorEnabled.Store(true)
	refreshTrafficEventSampleLocked()
	if wasEmpty {
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
			// 三种失败原因均为固定 ASCII 文案（无引号/控制字符），可直接拼进
			// JSON；调用方（app 端点）原样转发该 400 状态。
			http.Error(w, `{"error":"`+err.Error()+`"}`, http.StatusBadRequest)
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
