package services

import (
	"time"
)

type ip2RegionTaskState struct {
	status     IP2RegionUpdateStatus
	trigger    string
	startedAt  time.Time
	finishedAt time.Time
	message    string
	version    string
}

// IP2RegionUpdateStatusSnapshot is the point-in-time view served to handlers.
type IP2RegionUpdateStatusSnapshot struct {
	Status     string
	Trigger    string
	StartedAt  string
	FinishedAt string
	Message    string
	Version    string
}

// StatusSnapshot returns the in-memory task view, falling back to the stored
// terminal state when no update has run since process start.
func (m *IP2RegionUpdateManager) StatusSnapshot() IP2RegionUpdateStatusSnapshot {
	m.mu.Lock()
	state := m.state
	m.mu.Unlock()
	if state.trigger != "" || !state.startedAt.IsZero() {
		return ip2RegionSnapshotFromState(state)
	}
	return ip2RegionStoredStatusSnapshot()
}

// setSlotAdvanceError 记录「状态行已落库、但排程槽未推进」——任务引擎 Run 体
// 据此把本轮按失败返回（更新本身成功；失败的是调度契约，引擎需要失败才能
// 退避重投同一槽，而不是把本槽记入消费水位）。
func (m *IP2RegionUpdateManager) setSlotAdvanceError(err error) {
	m.mu.Lock()
	m.scheduleSlotErr = err
	m.mu.Unlock()
	if err != nil {
		Logf("error", "ip2region update: 排程不可读，本轮排程槽未推进（引擎将退避重投，读恢复后自愈）: %v", err)
	}
}

// ScheduleSlotError 本运行成功落库但排程槽未推进的原因（nil=槽已推进或本轮
// 未成功）。驱动任务引擎 Run 体在状态为 success 时复核：非 nil 时返回该错误。
func (m *IP2RegionUpdateManager) ScheduleSlotError() error {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.scheduleSlotErr
}

func ip2RegionStoredStatusSnapshot() IP2RegionUpdateStatusSnapshot {
	// 半初始化（db.DB=nil）降级 idle（同 crsstatus 口径）。
	row, ok, err := versionTableStatusRowOf("security_ip2region_version")
	if err != nil {
		// 同 crsstatus 口径：失败留 warn 后回退 idle。
		Logf("warn", "IP2Region 状态: 读取存储快照失败，回退 idle: %v", err)
	}
	if !ok {
		return IP2RegionUpdateStatusSnapshot{Status: string(IP2RegionStatusIdle)}
	}
	status, message := ProjectActiveUpdateStatusForLocalRole(row.status, row.message)
	return IP2RegionUpdateStatusSnapshot{
		Status:     status,
		Trigger:    row.trigger,
		StartedAt:  row.startedAt,
		FinishedAt: row.finishedAt,
		Message:    message,
		Version:    row.version,
	}
}

func ip2RegionSnapshotFromState(state ip2RegionTaskState) IP2RegionUpdateStatusSnapshot {
	snap := IP2RegionUpdateStatusSnapshot{
		Status:  string(state.status),
		Trigger: state.trigger,
		Message: state.message,
		Version: state.version,
	}
	if !state.startedAt.IsZero() {
		snap.StartedAt = state.startedAt.Format(crsTimeLayout)
	}
	if !state.finishedAt.IsZero() {
		snap.FinishedAt = state.finishedAt.Format(crsTimeLayout)
	}
	return snap
}

// IsActiveIP2RegionStatus reports whether the status describes an in-flight update.
func IsActiveIP2RegionStatus(status string) bool {
	switch IP2RegionUpdateStatus(status) {
	case IP2RegionStatusChecking, IP2RegionStatusDownloading, IP2RegionStatusInstalling, IP2RegionStatusReloading:
		return true
	}
	return false
}
