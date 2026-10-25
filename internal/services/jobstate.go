package services

import (
	"database/sql"
	"errors"
	"fmt"
	"sort"
	"strings"

	"lazy-balancer-v2/internal/db"
)

const (
	JobLifecycleQueued     = "queued"
	JobLifecycleActive     = "active"
	JobLifecycleDownloaded = "downloaded"
	JobLifecycleIssued     = "issued"
	JobLifecycleFailed     = "failed"
	JobLifecycleWaitingCA  = "waiting_ca"
	JobLifecycleDisabled   = "disabled"
)

var (
	ErrJobTransitionConflict = errors.New("certificate job status transition conflict")
	// allJobStatuses 派生自 db.CertJobStatuses()（单源：cert_jobs 的
	// CHECK 枚举与 DDL 由同一列表生成；services 依赖 db，反向不可行）。
	allJobStatuses         = db.CertJobStatuses()
	nonTerminalJobStatuses = withoutJobStatuses("issued", "failed", "disabled")
	jobLifecycleByStatus   = map[string]string{
		"queued":              JobLifecycleQueued,
		"pending":             JobLifecycleActive,
		"processing":          JobLifecycleActive,
		"creating_account":    JobLifecycleActive,
		"creating_order":      JobLifecycleActive,
		"order_created":       JobLifecycleActive,
		"cleanup_dns":         JobLifecycleDownloaded,
		"cleanup_warning":     JobLifecycleDownloaded,
		"presenting_dns":      JobLifecycleActive,
		"waiting_propagation": JobLifecycleActive,
		"dns_propagated":      JobLifecycleActive,
		"accepting_challenge": JobLifecycleActive,
		"validating":          JobLifecycleActive,
		"validated":           JobLifecycleActive,
		"finalizing":          JobLifecycleActive,
		"finalized":           JobLifecycleActive,
		"downloading":         JobLifecycleActive,
		"downloaded":          JobLifecycleDownloaded,
		"issued":              JobLifecycleIssued,
		"failed":              JobLifecycleFailed,
		"waiting_ca":          JobLifecycleWaitingCA,
		"disabled":            JobLifecycleDisabled,
		"waiting_order_ready": JobLifecycleActive,
		"order_ready":         JobLifecycleActive,
		"waiting_order_valid": JobLifecycleActive,
		"order_valid":         JobLifecycleActive,
	}
)

// deploymentLifecycleJobStatuses / DeploymentLifecycleJobStatusSQL 由
// jobLifecycleByStatus 派生（JobLifecycle==downloaded 单源）——状态集新增时
// 只改映射表，切片与 SQL IN 片段不再双份真源。消费方：transitionJob 的
// from 集合、启动/补扫装载的 CAS 源态集、cluster_report 与 handlers 的 SQL IN
// （跨包消费方无法触达切片，必须走导出的 SQL 片段）。
var (
	deploymentLifecycleJobStatuses = func() []string {
		statuses := make([]string, 0, 3)
		for status, lifecycle := range jobLifecycleByStatus {
			if lifecycle == JobLifecycleDownloaded {
				statuses = append(statuses, status)
			}
		}
		sort.Strings(statuses)
		return statuses
	}()
	// DeploymentLifecycleJobStatusSQL 供 SQL IN (...) 复用（由同一切片派生，
	// 非编译期常量——拼接点均为运行时字符串构造）。
	DeploymentLifecycleJobStatusSQL = "'" + strings.Join(deploymentLifecycleJobStatuses, "','") + "'"
	// deploymentCleanupJobStatuses 是部署生命周期中「仅剩 DNS 清理窗口」的子集：
	// downloaded 之外的部署态行由补扫的时间窗/settle 分支单独处理（它们不带
	// window 判据），cleanup_* 行则可能连窗口列都没写成功，必须无条件拾起。
	deploymentCleanupJobStatuses = func() []string {
		statuses := make([]string, 0, len(deploymentLifecycleJobStatuses))
		for _, status := range deploymentLifecycleJobStatuses {
			if status != "downloaded" {
				statuses = append(statuses, status)
			}
		}
		return statuses
	}()
	// DeploymentCleanupJobStatusSQL 同上，供补扫 cleanup 分支的 SQL IN 复用
	// （该分支刻意不覆盖 downloaded——否则 downloaded 行会绕过窗口与沉降判据）。
	DeploymentCleanupJobStatusSQL = "'" + strings.Join(deploymentCleanupJobStatuses, "','") + "'"
)

type jobTransitionExecutor interface {
	Exec(query string, args ...any) (sql.Result, error)
}

type jobSQLExpression string

// AllJobStatuses 返回 cert_jobs.status 规范枚举的副本（单一真源
// 与 db.CertJobStatuses()/fresh DDL CHECK/迁移白名单同源）。调用方可安全修改
// 返回值，不影响状态机。
func AllJobStatuses() []string { return db.CertJobStatuses() }

func withoutJobStatuses(excluded ...string) []string {
	exclude := make(map[string]struct{}, len(excluded))
	for _, status := range excluded {
		exclude[status] = struct{}{}
	}
	statuses := make([]string, 0, len(allJobStatuses)-len(exclude))
	for _, status := range allJobStatuses {
		if _, skip := exclude[status]; !skip {
			statuses = append(statuses, status)
		}
	}
	return statuses
}

func JobLifecycle(status string) string {
	if lifecycle, exists := jobLifecycleByStatus[status]; exists {
		return lifecycle
	}
	return JobLifecycleFailed
}

func JobIsTerminal(status string) bool {
	switch JobLifecycle(status) {
	case JobLifecycleIssued, JobLifecycleFailed, JobLifecycleDisabled:
		return true
	default:
		return false
	}
}

// maxJobMessageBytes 限制写入 cert_jobs.message 的任务消息大小。CA 错误详情等外部
// 文本可能无界嵌入错误链，而 message 列会同步到从节点并展示在 UI（历史
// 各写入点（failJob/jobLogger.Log/deploymentFailed）统一截断。
const maxJobMessageBytes = 1024

// truncateJobMessage 将任务消息截断到 maxJobMessageBytes 字节内，并回退到合法
// UTF-8 边界，避免 LimitReader 式按字节截断留下多字节字符残片。
func truncateJobMessage(message string) string {
	if len(message) <= maxJobMessageBytes {
		return message
	}
	return string(truncateValidUTF8Tail([]byte(message[:maxJobMessageBytes])))
}

func transitionJob(tx jobTransitionExecutor, id int, from []string, to string, fields map[string]any) error {
	if len(from) == 0 {
		return fmt.Errorf("transition certificate job %d to %s: %w", id, to, ErrJobTransitionConflict)
	}
	keys := make([]string, 0, len(fields))
	for key := range fields {
		keys = append(keys, key)
	}
	sort.Strings(keys)

	assignments := []string{"status=?"}
	args := []any{to}
	for _, key := range keys {
		if expression, ok := fields[key].(jobSQLExpression); ok {
			assignments = append(assignments, key+"="+string(expression))
			continue
		}
		assignments = append(assignments, key+"=?")
		args = append(args, fields[key])
	}
	assignments = append(assignments, "updated_at=datetime('now')")

	placeholders := strings.TrimSuffix(strings.Repeat("?,", len(from)), ",")
	args = append(args, id)
	for _, status := range from {
		args = append(args, status)
	}
	result, err := tx.Exec(
		"UPDATE cert_jobs SET "+strings.Join(assignments, ",")+" WHERE id=? AND status IN ("+placeholders+")",
		args...,
	)
	if err != nil {
		return fmt.Errorf("transition certificate job %d to %s: %w", id, to, err)
	}
	updated, err := result.RowsAffected()
	if err != nil {
		return fmt.Errorf("read certificate job %d transition result: %w", id, err)
	}
	if updated != 1 {
		return fmt.Errorf("transition certificate job %d to %s: %w", id, to, ErrJobTransitionConflict)
	}
	return nil
}
