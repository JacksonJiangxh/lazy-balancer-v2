package services

// 任务监控聚合服务（v2.3.4）：统一枚举系统全部定时/后台任务族，聚合各族
// 状态面（DB 行 + manager 内存态）为单一 DTO，供「系统设置 → 任务监控」
// 页面与 /system/tasks 端点消费。纯读聚合——零新表零迁移；操作面（触发/
// 暂停/取消）复用各任务族既有入口（handlers 映射层）。

import (
	"database/sql"
	"fmt"
	"strings"
	"time"

	"lazy-balancer-v2/internal/db"
)

// TaskKind 任务类型。
type TaskKind string

const (
	TaskKindScheduled  TaskKind = "scheduled"  // 排程驱动（周/时刻槽）
	TaskKindContinuous TaskKind = "continuous" // 常驻循环（间隔轮询/看门狗）
	TaskKindQueue      TaskKind = "queue"      // 队列驱动（按需入队）
)

// TaskStatus 任务当前状态。
type TaskStatus string

const (
	TaskStatusRunning   TaskStatus = "running"
	TaskStatusIdle      TaskStatus = "idle"
	TaskStatusFailed    TaskStatus = "failed"
	TaskStatusCancelled TaskStatus = "cancelled"
	TaskStatusDisabled  TaskStatus = "disabled"
	TaskStatusQueued    TaskStatus = "queued"
	TaskStatusPassive   TaskStatus = "passive" // 常驻无显式运行态（看门狗/清理）
	TaskStatusNoRuns    TaskStatus = "no_runs" // 从未运行
)

// TaskInfo 是单任务族的聚合视图。
type TaskInfo struct {
	ID          string       `json:"id"`
	Name        string       `json:"name"`
	Category    string       `json:"category"` // 安全防护/证书/备份/集群/系统
	Kind        TaskKind     `json:"kind"`
	Status      TaskStatus   `json:"status"`
	Enabled     bool         `json:"enabled"`     // 自动调度开关
	Cancellable bool         `json:"cancellable"` // 运行中可手动取消（仅下载类）
	LastRun     *TaskRunInfo `json:"last_run,omitempty"`
	NextRunAt   string       `json:"next_run_at,omitempty"`
	Runs24h     int          `json:"runs_24h"`
	Success24h  int          `json:"success_24h"`
	Fail24h     int          `json:"fail_24h"`
	DetailHint  string       `json:"detail_hint,omitempty"` // 前端详情跳转提示
}

// TaskRunInfo 最近一次运行。
type TaskRunInfo struct {
	StartedAt  string `json:"started_at"`
	FinishedAt string `json:"finished_at"`
	DurationMs int64  `json:"duration_ms"`
	Trigger    string `json:"trigger"` // manual/auto/schedule/queue/slave-sync
	Result     string `json:"result"`  // success/failed/cancelled/skipped/…
	Message    string `json:"message,omitempty"`
}

// CollectSystemTasks 聚合全部任务族（读侧统一入口）。
func CollectSystemTasks() []TaskInfo {
	tasks := []TaskInfo{
		collectThreatTask(),
		collectCRSTask(),
		collectIP2RegionTask(),
		collectCertQueueTask(),
		collectAutoBackupTask(),
		collectClusterSyncTask(),
		collectWatchdogTask(),
		collectAuditRetentionTask(),
	}
	return tasks
}

// taskRunFromCrsLayout 用 crsTimeLayout 时间串构造最近运行（无终态=进行中，
// 时长计到当前时刻）。
func taskRunFromCrsLayout(startedAt, finishedAt, trigger, result, message string) *TaskRunInfo {
	r := &TaskRunInfo{StartedAt: startedAt, FinishedAt: finishedAt, Trigger: trigger, Result: result, Message: message}
	if startedAt == "" {
		return r
	}
	if t0, e0 := time.Parse(crsTimeLayout, startedAt); e0 == nil {
		end := time.Now().UTC()
		if finishedAt != "" {
			if t1, e1 := time.Parse(crsTimeLayout, finishedAt); e1 == nil {
				end = t1
			}
		}
		r.DurationMs = end.Sub(t0).Milliseconds()
	}
	return r
}

// collectThreatTask 威胁情报库更新（任务级单条；源级明细在 message 汇总）。
func collectThreatTask() TaskInfo {
	ti := TaskInfo{ID: "threat", Name: "威胁情报库更新", Category: "安全防护", Kind: TaskKindScheduled, DetailHint: "threat"}
	// 源级汇总（展示名/条数/状态）
	type srcRow struct {
		name, display, status string
		count                 int
	}
	var srcs []srcRow
	var anyEnabled int
	rows, err := db.DB.Query(`SELECT name, COALESCE(display_name,name), COALESCE(update_status,''), COALESCE(entry_count,0), COALESCE(update_enabled,0) FROM security_threat_sources ORDER BY id`)
	if err == nil {
		defer rows.Close()
		for rows.Next() {
			var s srcRow
			var en int
			if rows.Scan(&s.name, &s.display, &s.status, &s.count, &en) == nil {
				srcs = append(srcs, s)
				anyEnabled += en
			}
		}
	}
	// 任务级内存态
	var snap ThreatTaskStatus
	if m := GetThreatUpdateManager(); m != nil {
		snap = m.StatusSnapshot()
	}
	ti.Enabled = anyEnabled > 0 && ThreatAutoUpdateEnabled()
	ti.Status = TaskStatusIdle
	switch snap.Outcome {
	case "failed":
		ti.Status = TaskStatusFailed
	case "cancelled":
		ti.Status = TaskStatusCancelled
	}
	if snap.Running {
		ti.Status = TaskStatusRunning
		ti.Cancellable = true
	}
	if !ti.Enabled && !snap.Running && ti.Status == TaskStatusIdle {
		ti.Status = TaskStatusDisabled
	}
	if snap.StartedAt != "" {
		ti.LastRun = taskRunFromCrsLayout(snap.StartedAt, snap.FinishedAt, snap.Trigger, snap.Outcome, "")
	}
	// message：源级摘要 + 下次执行取最早源槽
	var parts []string
	for _, s := range srcs {
		parts = append(parts, fmt.Sprintf("%s %d 条(%s)", s.display, s.count, s.status))
	}
	if ti.LastRun != nil {
		ti.LastRun.Message = strings.Join(parts, "；")
	}
	if next := earliestThreatNextUpdate(); next != "" {
		ti.NextRunAt = next
	}
	return ti
}

func earliestThreatNextUpdate() string {
	var next string
	if err := db.DB.QueryRow(`SELECT MIN(COALESCE(NULLIF(next_update,''), '9999')) FROM security_threat_sources WHERE update_enabled=1`).Scan(&next); err != nil || next == "9999" {
		return ""
	}
	return next
}

// collectCRSTask CRS 规则库更新。
func collectCRSTask() TaskInfo {
	ti := TaskInfo{ID: "crs", Name: "CRS 规则库更新", Category: "安全防护", Kind: TaskKindScheduled, DetailHint: "crs"}
	var enabled int
	var next string
	if err := db.DB.QueryRow("SELECT COALESCE(auto_update,1), COALESCE(next_update,'') FROM security_crs_version WHERE id=1").Scan(&enabled, &next); err != nil {
		ti.Status = TaskStatusNoRuns
		return ti
	}
	snap := GetCRSUpdateManager().StatusSnapshot()
	ti.Enabled = enabled == 1
	ti.Status = TaskStatusIdle
	switch snap.Status {
	case string(CRSStatusFailed):
		ti.Status = TaskStatusFailed
	case string(CRSStatusIdle), string(CRSStatusSuccess), "":
		ti.Status = TaskStatusIdle
	default:
		// downloading/installing/reloading 等运行阶段
		ti.Status = TaskStatusRunning
		ti.Cancellable = true
	}
	if !ti.Enabled && ti.Status == TaskStatusIdle {
		ti.Status = TaskStatusDisabled
	}
	ti.LastRun = taskRunFromCrsLayout(snap.StartedAt, snap.FinishedAt, snap.Trigger, snap.Status, snap.Message)
	if snap.Version != "" && ti.LastRun != nil {
		ti.LastRun.Message = strings.TrimSpace("v" + strings.TrimPrefix(snap.Version, "v") + " " + ti.LastRun.Message)
	}
	ti.NextRunAt = next
	return ti
}

// collectIP2RegionTask IP2Region 地理库更新。
func collectIP2RegionTask() TaskInfo {
	ti := TaskInfo{ID: "ip2region", Name: "IP2Region 地理库更新", Category: "安全防护", Kind: TaskKindScheduled, DetailHint: "ip2region"}
	var enabled int
	var status, message, finished, next string
	err := db.DB.QueryRow(`SELECT COALESCE(auto_update,1), COALESCE(update_status,''), COALESCE(message,''), COALESCE(finished_at,''), COALESCE(next_update,'') FROM security_ip2region_version WHERE id=1`).Scan(&enabled, &status, &message, &finished, &next)
	if err != nil {
		ti.Status = TaskStatusNoRuns
		return ti
	}
	m := GetIP2RegionUpdateManager()
	ti.Enabled = enabled == 1
	ti.Status = TaskStatusIdle
	if status == "failed" {
		ti.Status = TaskStatusFailed
	}
	if m != nil && m.IsRunning() {
		ti.Status = TaskStatusRunning
		ti.Cancellable = true
	}
	if !ti.Enabled && ti.Status == TaskStatusIdle {
		ti.Status = TaskStatusDisabled
	}
	ti.LastRun = taskRunFromCrsLayout("", finished, "auto", status, message)
	ti.NextRunAt = next
	return ti
}

// collectCertQueueTask ACME 证书任务队列。
func collectCertQueueTask() TaskInfo {
	ti := TaskInfo{ID: "cert-queue", Name: "ACME 证书任务队列", Category: "证书", Kind: TaskKindQueue, Enabled: true, Status: TaskStatusIdle, DetailHint: "certificates"}
	var queued, running, failed, issued int
	err1 := db.DB.QueryRow(`SELECT
		(SELECT COUNT(*) FROM cert_jobs WHERE status IN ('queued','pending')),
		(SELECT COUNT(*) FROM cert_jobs WHERE status NOT IN ('queued','pending','issued','failed','disabled')),
		(SELECT COUNT(*) FROM cert_jobs WHERE status='failed' AND COALESCE(updated_at,created_at) > datetime('now','-1 day')),
		(SELECT COUNT(*) FROM cert_jobs WHERE status='issued' AND COALESCE(updated_at,created_at) > datetime('now','-1 day'))`).Scan(&queued, &running, &failed, &issued)
	if err1 == nil {
		switch {
		case running > 0:
			ti.Status = TaskStatusRunning
		case queued > 0:
			ti.Status = TaskStatusQueued
		}
		ti.Runs24h = issued + failed
		ti.Success24h = issued
		ti.Fail24h = failed
		if msg := fmt.Sprintf("待处理 %d · 运行中 %d · 24h 签发 %d / 失败 %d", queued, running, issued, failed); ti.LastRun != nil || true {
			ti.LastRun = &TaskRunInfo{Trigger: "queue", Result: string(ti.Status), Message: msg}
		}
	}
	return ti
}

// collectAutoBackupTask 自动备份。
func collectAutoBackupTask() TaskInfo {
	ti := TaskInfo{ID: "auto-backup", Name: "自动备份", Category: "备份", Kind: TaskKindScheduled, Enabled: true, DetailHint: "backup"}
	var filename, status, trigger, created string
	var size int64
	row := db.DB.QueryRow(`SELECT filename, status, trigger_type, COALESCE(created_at,''), COALESCE(size_bytes,0) FROM auto_backups ORDER BY id DESC LIMIT 1`)
	if err := row.Scan(&filename, &status, &trigger, &created, &size); err != nil {
		ti.Status = TaskStatusNoRuns
		return ti
	}
	ti.Status = TaskStatusIdle
	if status == "failed" {
		ti.Status = TaskStatusFailed
	}
	ti.LastRun = &TaskRunInfo{StartedAt: created, FinishedAt: created, Trigger: trigger, Result: status, Message: fmt.Sprintf("%s (%d KB)", filename, size/1024)}
	var runs, fails int
	if err := db.DB.QueryRow(`SELECT COUNT(*), COALESCE(SUM(CASE WHEN status='failed' THEN 1 ELSE 0 END),0) FROM auto_backups WHERE created_at > datetime('now','-1 day')`).Scan(&runs, &fails); err == nil {
		ti.Runs24h = runs
		ti.Fail24h = fails
		ti.Success24h = runs - fails
	}
	return ti
}

// collectClusterSyncTask 集群同步（从节点常驻循环；主节点为签发方）。
func collectClusterSyncTask() TaskInfo {
	ti := TaskInfo{ID: "cluster-sync", Name: "集群同步（主节点签发）", Category: "集群", Kind: TaskKindContinuous, Enabled: true, Status: TaskStatusPassive, DetailHint: "cluster"}
	var isMaster int
	if err := db.DB.QueryRow("SELECT COALESCE(is_master,1) FROM global_config WHERE id=1").Scan(&isMaster); err != nil {
		ti.Status = TaskStatusNoRuns
		return ti
	}
	if isMaster == 1 {
		return ti
	}
	ti.Name = "集群同步（从节点回放）"
	ti.Status = TaskStatusRunning // 常驻循环按间隔轮询视为运行中
	// 最近一次实际应用（304 短路不刷新——last_sync 只记全量应用）
	var applied, clusterVer int
	var lastSync sql.NullString
	var interval int
	if err := db.DB.QueryRow("SELECT COALESCE(applied_version,0), COALESCE(cluster_version,0), COALESCE(sync_interval,60), last_sync FROM global_config WHERE id=1").Scan(&applied, &clusterVer, &interval, &lastSync); err == nil {
		msg := fmt.Sprintf("每 %ds 轮询 · 已应用版本 %d", interval, applied)
		if clusterVer > applied {
			msg += fmt.Sprintf("（落后主节点 %d 版）", clusterVer-applied)
		} else {
			msg += "（与主节点一致）"
		}
		at := ""
		if lastSync.Valid {
			at = lastSync.String
		}
		ti.LastRun = &TaskRunInfo{StartedAt: at, FinishedAt: at, Trigger: "slave-sync", Result: "success", Message: msg}
	}
	return ti
}

// collectWatchdogTask 配置漂移看门狗（60s 常驻）。
func collectWatchdogTask() TaskInfo {
	return TaskInfo{ID: "config-watchdog", Name: "配置漂移看门狗", Category: "系统", Kind: TaskKindContinuous, Enabled: true, Status: TaskStatusPassive, DetailHint: "watchdog"}
}

// collectAuditRetentionTask 审计日志保留清理。
func collectAuditRetentionTask() TaskInfo {
	ti := TaskInfo{ID: "audit-retention", Name: "审计日志保留清理", Category: "系统", Kind: TaskKindScheduled, Enabled: true, Status: TaskStatusPassive, DetailHint: "audit"}
	var months int
	if err := db.DB.QueryRow("SELECT COALESCE(audit_retention_months,3) FROM global_config WHERE id=1").Scan(&months); err == nil {
		if months > 0 {
			ti.NextRunAt = "每日 03:00（保留 " + fmt.Sprint(months) + " 个月）"
		}
	}
	return ti
}
