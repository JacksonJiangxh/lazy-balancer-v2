package services

import (
	"context"
	"path/filepath"

	"lazy-balancer-v2/internal/db"
)

func storedStatusSnapshot() CRSUpdateStatusSnapshot {
	row, ok, err := versionTableStatusRowOf("security_crs_version")
	if err != nil {
		// DB 读失败静默回退 idle 会丢可回溯性：留 warn 后回退。
		Logf("warn", "CRS 状态: 读取存储快照失败，回退 idle: %v", err)
	}
	if !ok {
		return CRSUpdateStatusSnapshot{Status: string(CRSStatusIdle)}
	}
	status, message := ProjectActiveUpdateStatusForLocalRole(row.status, row.message)
	return CRSUpdateStatusSnapshot{
		Status:     status,
		Trigger:    row.trigger,
		StartedAt:  row.startedAt,
		FinishedAt: row.finishedAt,
		Message:    message,
		Version:    row.version,
	}
}

// ProjectActiveUpdateStatusForLocalRole 把「进行中」活动态按本节点角色投影：
// 这些任务全部 RunsOn=RoleMasterOnly，从节点上的活动态只可能是主端镜像或降级
// 前的本机残留，本进程不可能将它推进到终态——读侧统一投影为 failed + 归属
// 文案，避免规则库页/威胁库行长期显示「更新中」（与任务视图 role_applicable
// 自相矛盾）。数据面收敛仍由启动归一（主节点）与快照应用归一（从节点）负责，
// 本投影只影响展示，且**不写库**。
//
// 角色读失败按原值返回（不猜测）：把活动态投影成 failed 会成为新的假信息。
func ProjectActiveUpdateStatusForLocalRole(status, message string) (string, string) {
	if !snapshotActiveUpdateStatus(status) {
		return status, message
	}
	isMaster, err := RoleOf(context.Background(), db.GetDB())
	if err != nil || isMaster {
		return status, message
	}
	return "failed", snapshotActiveUpdateStatusMessage
}

// versionTableStatusRow 版本表族（security_crs_version /
// security_ip2region_version）存储快照行的列集：两族完全相同，读取与
// 「库未初始化/读失败回退 idle」判定收敛为单一事实源（此前两份逐字同构，
// 任一族新增字段或改判定都会漂移）。表名只接受包内常量，不接受外部输入。
type versionTableStatusRow struct {
	status, trigger, startedAt, finishedAt, message, version string
}

// versionTableStatusRowOf 读取版本表族状态快照行。
//   - ok=false 且 err=nil：库未初始化（半初始化降级 idle，非故障）；
//   - ok=false 且 err!=nil：读失败，由调用方按族前缀留痕后回退 idle；
//   - ok=true：行值可用。
func versionTableStatusRowOf(table string) (versionTableStatusRow, bool, error) {
	var row versionTableStatusRow
	// 半初始化（db.DB=nil）时降级 idle 而非 panic——与同包
	// crs_rule_index/securityevents_retention 的 nil 守卫同口径。
	if db.DB == nil {
		return row, false, nil
	}
	err := db.DB.QueryRow(`SELECT COALESCE(update_status,'idle'), COALESCE(trigger,''),
		COALESCE(started_at,''), COALESCE(finished_at,''), COALESCE(message,''), version
		FROM `+table+` WHERE id=1`).
		Scan(&row.status, &row.trigger, &row.startedAt, &row.finishedAt, &row.message, &row.version)
	if err != nil {
		return versionTableStatusRow{}, false, err
	}
	return row, true, nil
}

func snapshotFromState(state crsTaskState) CRSUpdateStatusSnapshot {
	snap := CRSUpdateStatusSnapshot{
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

// IsActiveCRSStatus reports whether the status describes an in-flight update.
func IsActiveCRSStatus(status string) bool {
	switch CRSUpdateStatus(status) {
	case CRSStatusChecking, CRSStatusDownloading, CRSStatusInstalling, CRSStatusReloading:
		return true
	}
	return false
}

// RuleCount returns the cached SecRule count, scanning the live rules dir on
// first use.
func (m *CRSUpdateManager) RuleCount() int {
	m.mu.Lock()
	if m.hasRuleCount {
		defer m.mu.Unlock()
		return m.ruleCount
	}
	m.mu.Unlock()
	count, err := countSecRules(filepath.Join(m.liveDir(), "rules"))
	if err != nil {
		Logf("error", "crs update: failed to count SecRules: %v", err)
		return 0
	}
	// 放锁扫描期间 rescan 可能已写入新值——
	// 重锁写回前双重检查,不覆盖更新值(展示层一致性)。
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.hasRuleCount {
		return m.ruleCount
	}
	m.ruleCount = count
	m.hasRuleCount = true
	return count
}

func (m *CRSUpdateManager) rescanRuleCount() {
	count, err := countSecRules(filepath.Join(m.liveDir(), "rules"))
	if err != nil {
		Logf("error", "crs update: failed to rescan SecRules: %v", err)
		return
	}
	m.mu.Lock()
	m.ruleCount = count
	m.hasRuleCount = true
	m.mu.Unlock()
}

// InvalidateRuleCount 丢弃规则数缓存：/security/crs 的
// rule_count 是首次扫描后的进程内缓存，而集群同步（ApplyWafFileBundle）与
// lbbak 备份导入都会带外替换 live CRS 树——不失效则规则数滞留旧值直到进程
// 重启或下一次成功更新。下次 RuleCount() 调用重新扫描。
func (m *CRSUpdateManager) InvalidateRuleCount() {
	m.mu.Lock()
	m.ruleCount = -1
	m.hasRuleCount = false
	m.mu.Unlock()
}

// InvalidateCRSRuleCount 供带外替换 live CRS 树的通道丢弃规则数缓存
// 集群同步/备份导入的文件相位统一收敛在
// ApplyWafFileBundle，由该函数在 CRS 落盘成功后调用；manager 未初始化
// （测试/半初始化装配）时为空操作，不 panic。
func InvalidateCRSRuleCount() {
	if mgr := GetCRSUpdateManager(); mgr != nil {
		mgr.InvalidateRuleCount()
	}
}
