package caddychain

// 被动 5xx 摘除子系统（JJC-20261120-002 / 方案 §A.2）：
//
// 逐车道 5xx 滑动窗口计数——数据面响应状态码 ≥500 记一次失败（挂点：
// roundTrip 响应出口与隧道非 101 透传口，统一走 recordPassive 单源）；
// 窗口内累计达 max_fails → 摘除 unhealthy_duration，期满即恢复（下一个
// 真实请求即试探的 half-open 语义，无专判探测；全灭不专判兜底在
// eligibleLanes 收口）。
//
// 与 uniform 原生 reverse_proxy 被动 HC 的对齐（方案 §A.3）：
//   - fail_duration 缺省 90s = uniform 渲染 interval*3（caddy.go:3942，
//     interval 缺省 30s）；
//   - max_fails 缺省 3 = uniform 渲染 failing 语义（unhealthy_threshold）；
//   - unhealthy_duration 缺省 = 同 fail_duration（uniform 未发射该键，
//     Caddy 官方回落语义）；
//   - 网络错误不计数（chain 有意差异：wrr/race「失败即切」已覆盖，
//     不双罚——uniform 原生则计入被动失败）。
//
// 【覆盖面】本子系统仅覆盖「升级响应的状态码面」：recordPassive 挂点在
// 响应头/非 101 透传出口；隧道升级（101）后的双向字节流无状态码概念，
// 天然不参与计数——与 uniform 原生 unhealthy_status 语义同构。
//
// 生命周期：无后台协程（纯请求驱动 + 时间戳比较），无 Cleanup 面；
// 恒启用、零配置（对齐 uniform 引擎自带恒启用）。

import (
	"sync"
	"time"

	"go.uber.org/zap"
)

// 被动摘除缺省值（与 uniform 渲染实值对齐，见文件头注释）。
const (
	DefaultPassiveFailDurationMS = 90000 // interval 缺省 30s × 3
	DefaultPassiveMaxFails       = 3
	DefaultPassiveUnhealthyDurMS = DefaultPassiveFailDurationMS
)

// lanePassiveState 单车道被动状态：滑动窗口失败时间戳 + 摘除截止时刻。
type lanePassiveState struct {
	fails        []time.Time
	ejectedUntil time.Time
}

// passiveMonitor 被动 5xx 摘除子系统：逐车道滑动计数（互斥锁保护），
// 纯请求驱动、无后台协程。
type passiveMonitor struct {
	h *ChainProxy

	failDuration time.Duration
	maxFails     int
	unhealthyDur time.Duration

	mu     sync.Mutex
	states []lanePassiveState
}

// newPassiveMonitor 装配被动子系统（缺省值归一；Upstreams 长度对齐）。
func newPassiveMonitor(h *ChainProxy) *passiveMonitor {
	m := &passiveMonitor{
		h:            h,
		failDuration: DefaultPassiveFailDurationMS * time.Millisecond,
		maxFails:     DefaultPassiveMaxFails,
		unhealthyDur: DefaultPassiveUnhealthyDurMS * time.Millisecond,
	}
	m.states = make([]lanePassiveState, len(h.Upstreams))
	return m
}

// recordPassive 单源计数入口：status ≥500 记一次失败（网络错误不进本函数
// ——「失败即切」已处理，不双罚）；达阈即摘除并打日志（车道号+计数+摘除时长）。
func (h *ChainProxy) recordPassive(idx int, status int) {
	if status < 500 {
		return
	}
	m := h.passiveState
	if m == nil || idx < 0 || idx >= len(m.states) {
		return
	}
	now := time.Now()
	m.mu.Lock()
	st := &m.states[idx]
	// 滑动窗口衰减：丢弃窗外时间戳。
	cutoff := now.Add(-m.failDuration)
	kept := st.fails[:0]
	for _, t := range st.fails {
		if t.After(cutoff) {
			kept = append(kept, t)
		}
	}
	st.fails = append(kept, now)
	if len(st.fails) >= m.maxFails {
		st.ejectedUntil = now.Add(m.unhealthyDur)
		st.fails = st.fails[:0]
		m.mu.Unlock()
		h.log().Warn("chain_proxy: 被动 5xx 摘除",
			zap.Int("lane", idx), zap.Int("fails", m.maxFails), zap.Duration("duration", m.unhealthyDur))
		return
	}
	m.mu.Unlock()
}

// passiveHealthy 单车道被动健康态：摘除期内 false；期满即恢复（half-open
// ——下一个真实请求即试探），恢复时打一行日志（车道号+摘除时长）。
func (h *ChainProxy) passiveHealthy(idx int) bool {
	m := h.passiveState
	if m == nil {
		return true
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	st := &m.states[idx]
	if st.ejectedUntil.IsZero() {
		return true
	}
	if time.Now().After(st.ejectedUntil) {
		// 期满恢复：清截止时刻，真实请求自然试探。
		st.ejectedUntil = time.Time{}
		h.log().Info("chain_proxy: 被动摘除期满恢复（half-open 试探）",
			zap.Int("lane", idx), zap.Duration("duration", m.unhealthyDur))
		return true
	}
	return false
}
