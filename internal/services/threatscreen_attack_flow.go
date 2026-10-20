package services

// 威胁大屏攻击光流独立采集源：只服务光流/弹框态势，不写安全事件日志。
// 安全事件日志仍由 securityevents.go 全量落库；本环形缓冲在事务提交后追加，
// 支持 1/N 抽样与容量上限，避免大屏消费路径直接扫描 security_events。

import (
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
)

// SetThreatScreenAttackFlowSampleN 更新攻击流光流采样档位。
// 0=关闭；负数按 1（全量）处理；上限 8（与前端自适应档位一致）。
func SetThreatScreenAttackFlowSampleN(n int) {
	if n < 0 {
		n = 1
	}
	if n > 8 {
		n = 8
	}
	threatScreenAttackFlowSampleN.Store(uint32(n))
}

// ThreatScreenAttackFlowSampleN 返回当前采样档位（0=关闭）。
func ThreatScreenAttackFlowSampleN() int {
	return int(threatScreenAttackFlowSampleN.Load())
}

// threatScreenAttackFlowRecordBatch 在 security_events 事务提交成功后调用。
// 采样在环形缓冲写入前完成；失败/回滚的日志批次不得进入光流。
func threatScreenAttackFlowRecordBatch(items []threatScreenAttackFlowItem) {
	if len(items) == 0 {
		return
	}
	n := threatScreenAttackFlowSampleN.Load()
	if n == 0 {
		return
	}
	for _, item := range items {
		if n > 1 && threatScreenAttackFlowAttempt.Add(1)%uint64(n) != 0 {
			continue
		}
		if n <= 1 {
			threatScreenAttackFlowAttempt.Add(1)
		}
		seq := threatScreenAttackFlowSeq.Add(1)
		ev := ThreatScreenAttackFlowEvent{
			Seq:           seq,
			At:            item.at.UnixMilli(),
			ClientIP:      item.clientIP,
			Action:        item.action,
			RuleTriggered: item.ruleTriggered,
			RuleMsg:       item.ruleMsg,
			Weight:        n,
		}
		threatScreenAttackFlowMu.Lock()
		threatScreenAttackFlowEvents = append(threatScreenAttackFlowEvents, ev)
		if len(threatScreenAttackFlowEvents) > threatScreenAttackFlowRingMax {
			threatScreenAttackFlowEvents = threatScreenAttackFlowEvents[len(threatScreenAttackFlowEvents)-threatScreenAttackFlowRingMax:]
		}
		threatScreenAttackFlowMu.Unlock()
	}
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

// ResetThreatScreenAttackFlowForTest 测试缝：清空环形缓冲与采样状态。
func ResetThreatScreenAttackFlowForTest() {
	threatScreenAttackFlowMu.Lock()
	threatScreenAttackFlowEvents = nil
	threatScreenAttackFlowMu.Unlock()
	threatScreenAttackFlowSeq.Store(0)
	threatScreenAttackFlowAttempt.Store(0)
	threatScreenAttackFlowSampleN.Store(0)
}
