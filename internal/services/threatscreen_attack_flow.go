package services

// 威胁大屏攻击光流独立采集源：只服务光流/弹框态势，不写安全事件日志。
// 安全事件日志仍由 securityevents.go 全量落库；本环形缓冲在事务提交后追加，
// 支持 1/N 抽样与容量上限，避免大屏消费路径直接扫描 security_events。

import (
	"errors"
	"sync"
	"sync/atomic"
	"time"
)

const threatScreenAttackFlowRingMax = 4096

// ThreatScreenAttackFlowEvent 是攻击光流的轻量事件（不含请求头/正文）。
type ThreatScreenAttackFlowEvent struct {
	Seq           uint64 `json:"seq"`
	At            int64  `json:"at"`
	ClientIP      string `json:"client_ip"`
	Action        string `json:"action"`
	RuleTriggered string `json:"rule_triggered"`
	RuleMsg       string `json:"rule_msg"`
	// Weight 是写入时的采样因子：1=全量，4/8=1/N 抽样后的权重。
	// 前端用 sum(weight) 还原近似总量，避免采样档位直接改变线宽语义。
	Weight uint32 `json:"weight"`
}

type threatScreenAttackFlowItem struct {
	at            time.Time
	clientIP      string
	action        string
	ruleTriggered string
	ruleMsg       string
}

var (
	threatScreenAttackFlowMu      sync.Mutex
	threatScreenAttackFlowEvents  []ThreatScreenAttackFlowEvent
	threatScreenAttackFlowSeq     atomic.Uint64
	threatScreenAttackFlowAttempt atomic.Uint64
	threatScreenAttackFlowSampleN atomic.Uint32
	// 历史修复：采样档位租约表（与 Caddy 侧 traffic_lease.go 同模型）——
	// 取代「全局单值最后写者胜」：多标签页/多租约并存时单租约释放不误杀
	// 其他租约；有效档位=存活租约的 min（最密），无租约=0（关闭）。
	threatScreenAttackFlowLeases = map[string]threatScreenAttackFlowLease{}
)

const (
	threatScreenAttackFlowLeaseTTLDefault = 30 * time.Second
	threatScreenAttackFlowLeaseTTLMin     = 5 * time.Second
	threatScreenAttackFlowLeaseTTLMax     = 120 * time.Second
	// 与 Caddy 侧同族上限：lease_id 64 字节、并发租约 64 条（续租不受限）。
	threatScreenAttackFlowLeaseIDMaxLen = 64
	threatScreenAttackFlowLeaseMax      = 64
)

type threatScreenAttackFlowLease struct {
	sampleN   int
	expiresAt time.Time
}

// clampThreatScreenAttackFlowSampleN 档位归一：0=关闭；负数按 1（全量）；
// 上限 8（与前端自适应档位一致）。
func clampThreatScreenAttackFlowSampleN(n int) int {
	if n < 0 {
		n = 1
	}
	if n > 8 {
		n = 8
	}
	return n
}

// AcquireThreatScreenAttackFlowLease 登记/续租攻击光流采样租约。
// TTL 与 Caddy 侧同族：缺省 30s、钳 [5s,120s]（前端每 10s 心跳续租）。
// sample_n 钳 [0,8]。威胁大屏关闭/崩溃后租约 TTL 过期自动停止采样。
func AcquireThreatScreenAttackFlowLease(id string, ttl time.Duration, sampleN int) error {
	return acquireThreatScreenAttackFlowLeaseAt(id, ttl, sampleN, time.Now())
}

func acquireThreatScreenAttackFlowLeaseAt(id string, ttl time.Duration, sampleN int, now time.Time) error {
	if id == "" {
		return errors.New("lease_id required")
	}
	if len(id) > threatScreenAttackFlowLeaseIDMaxLen {
		return errors.New("lease_id too long")
	}
	if ttl <= 0 {
		ttl = threatScreenAttackFlowLeaseTTLDefault
	}
	if ttl < threatScreenAttackFlowLeaseTTLMin {
		ttl = threatScreenAttackFlowLeaseTTLMin
	}
	if ttl > threatScreenAttackFlowLeaseTTLMax {
		ttl = threatScreenAttackFlowLeaseTTLMax
	}
	threatScreenAttackFlowMu.Lock()
	defer threatScreenAttackFlowMu.Unlock()
	sweepThreatScreenAttackFlowLeasesLocked(now)
	// 条目上限只拦新键——续租既有键不受限（满表不应让真实标签页心跳失败）。
	if _, exists := threatScreenAttackFlowLeases[id]; !exists && len(threatScreenAttackFlowLeases) >= threatScreenAttackFlowLeaseMax {
		return errors.New("too many leases")
	}
	threatScreenAttackFlowLeases[id] = threatScreenAttackFlowLease{
		sampleN:   clampThreatScreenAttackFlowSampleN(sampleN),
		expiresAt: now.Add(ttl),
	}
	refreshThreatScreenAttackFlowSampleLocked()
	return nil
}

// ReleaseThreatScreenAttackFlowLease 释放租约；无匹配=幂等成功。
func ReleaseThreatScreenAttackFlowLease(id string) {
	releaseThreatScreenAttackFlowLeaseAt(id, time.Now())
}

func releaseThreatScreenAttackFlowLeaseAt(id string, now time.Time) {
	threatScreenAttackFlowMu.Lock()
	defer threatScreenAttackFlowMu.Unlock()
	sweepThreatScreenAttackFlowLeasesLocked(now)
	delete(threatScreenAttackFlowLeases, id)
	refreshThreatScreenAttackFlowSampleLocked()
}

// sweepThreatScreenAttackFlowLeasesLocked 懒清理过期租约。调用方必须持锁。
func sweepThreatScreenAttackFlowLeasesLocked(now time.Time) {
	for id, lease := range threatScreenAttackFlowLeases {
		if !now.Before(lease.expiresAt) {
			delete(threatScreenAttackFlowLeases, id)
		}
	}
}

// refreshThreatScreenAttackFlowSampleLocked 有效档位=存活租约的最密档（最小 N）；
// sampleN=0 的租约不参与 min（与 Caddy 侧同语义：租约保留但不产事件），
// 无租约/全部 0 档=0（关闭）。调用方必须持锁。
func refreshThreatScreenAttackFlowSampleLocked() {
	n := 0
	for _, lease := range threatScreenAttackFlowLeases {
		if lease.sampleN == 0 {
			continue
		}
		if n == 0 || lease.sampleN < n {
			n = lease.sampleN
		}
	}
	threatScreenAttackFlowSampleN.Store(uint32(n))
}

// ThreatScreenAttackFlowSampleN 返回当前采样档位（0=关闭）。
// 读路径顺带懒清理过期租约——租约全过期后档位自动归 0。
func ThreatScreenAttackFlowSampleN() int {
	return threatScreenAttackFlowSampleNAt(time.Now())
}

func threatScreenAttackFlowSampleNAt(now time.Time) int {
	threatScreenAttackFlowMu.Lock()
	sweepThreatScreenAttackFlowLeasesLocked(now)
	refreshThreatScreenAttackFlowSampleLocked()
	threatScreenAttackFlowMu.Unlock()
	return int(threatScreenAttackFlowSampleN.Load())
}

// threatScreenAttackFlowFlushCalls 环形缓冲追加批次的加锁/裁剪次数（测试观测
// 「批内一次加锁」；生产成本=每批一次原子加）。
var threatScreenAttackFlowFlushCalls atomic.Int64

// threatScreenAttackFlowRecordBatch 在 security_events 事务提交成功后调用。
// 采样在环形缓冲写入前完成；失败/回滚的日志批次不得进入光流。
func threatScreenAttackFlowRecordBatch(items []threatScreenAttackFlowItem) {
	if len(items) == 0 {
		return
	}
	n := threatScreenAttackFlowSampleNAt(time.Now())
	if n == 0 {
		return
	}
	// 采样与序号分配在锁外完成（原子计数本就无锁），攒批后一次性进入环形
	// 缓冲：一次加锁 + 批量 append + 一次裁剪。逐事件加锁会让锁往返与
	// O(ring) 的尾部搬移按事件数放大（一次事务提交可达数百条事件）。
	batch := make([]ThreatScreenAttackFlowEvent, 0, len(items))
	for _, item := range items {
		if n > 1 && threatScreenAttackFlowAttempt.Add(1)%uint64(n) != 0 {
			continue
		}
		if n <= 1 {
			threatScreenAttackFlowAttempt.Add(1)
		}
		seq := threatScreenAttackFlowSeq.Add(1)
		batch = append(batch, ThreatScreenAttackFlowEvent{
			Seq:           seq,
			At:            item.at.UnixMilli(),
			ClientIP:      item.clientIP,
			Action:        item.action,
			RuleTriggered: item.ruleTriggered,
			RuleMsg:       item.ruleMsg,
			Weight:        uint32(n),
		})
	}
	if len(batch) == 0 {
		return
	}
	threatScreenAttackFlowFlushCalls.Add(1)
	threatScreenAttackFlowMu.Lock()
	threatScreenAttackFlowEvents = append(threatScreenAttackFlowEvents, batch...)
	if over := len(threatScreenAttackFlowEvents) - threatScreenAttackFlowRingMax; over > 0 {
		threatScreenAttackFlowEvents = threatScreenAttackFlowEvents[over:]
	}
	threatScreenAttackFlowMu.Unlock()
}

// ThreatScreenAttackFlowSnapshot 返回 since 之后的攻击流事件。
// since=0 只返回最近 limit 条；next_seq 为本批实际推进到的序号。
// 游标超前于本进程已分配序号（如进程重启）时返回 next_seq=0，前端从最新窗口追赶。
func ThreatScreenAttackFlowSnapshot(since uint64, limit int) ([]ThreatScreenAttackFlowEvent, uint64) {
	if limit <= 0 {
		limit = 200
	}
	if limit > 1000 {
		limit = 1000
	}
	threatScreenAttackFlowMu.Lock()
	defer threatScreenAttackFlowMu.Unlock()

	out := make([]ThreatScreenAttackFlowEvent, 0, limit)
	start := 0
	if since == 0 {
		if len(threatScreenAttackFlowEvents) > limit {
			start = len(threatScreenAttackFlowEvents) - limit
		}
	} else {
		for start < len(threatScreenAttackFlowEvents) && threatScreenAttackFlowEvents[start].Seq <= since {
			start++
		}
	}
	for _, ev := range threatScreenAttackFlowEvents[start:] {
		if len(out) >= limit {
			break
		}
		out = append(out, ev)
	}
	next := since
	if since > threatScreenAttackFlowSeq.Load() {
		next = 0
	} else if len(out) > 0 {
		next = out[len(out)-1].Seq
	}
	return out, next
}

// ResetThreatScreenAttackFlowForTest 测试缝：清空环形缓冲、租约表与采样状态。
func ResetThreatScreenAttackFlowForTest() {
	threatScreenAttackFlowMu.Lock()
	threatScreenAttackFlowEvents = nil
	threatScreenAttackFlowLeases = map[string]threatScreenAttackFlowLease{}
	threatScreenAttackFlowMu.Unlock()
	threatScreenAttackFlowSeq.Store(0)
	threatScreenAttackFlowAttempt.Store(0)
	threatScreenAttackFlowSampleN.Store(0)
}
