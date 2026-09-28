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
	TaskStatusPassive   TaskStatus = "passive" // 常驻无显式运行态（角色驱动/引擎外）
	TaskStatusNoRuns    TaskStatus = "no_runs" // 从未运行
	TaskStatusStopped   TaskStatus = "stopped" // 常驻可控循环已停止
)

// TaskInfo 是单任务族的聚合视图。
type TaskInfo struct {
	ID           string       `json:"id"`
	Name         string       `json:"name"`
	Description  string       `json:"description,omitempty"` // 任务作用说明（任务名 hover 提示）
	Cadence      string       `json:"cadence,omitempty"`     // 运行节奏（如「每 6 小时」；非下次时间）
	Category     string       `json:"category"`              // 安全防护/证书/备份/集群/系统
	Kind         TaskKind     `json:"kind"`
	Status       TaskStatus   `json:"status"`
	Enabled      bool         `json:"enabled"`      // 自动调度开关
	Cancellable  bool         `json:"cancellable"`  // 运行中可手动取消（仅下载类）
	Controllable bool         `json:"controllable"` // 常驻循环可启停（start/stop/restart）
	LastRun      *TaskRunInfo `json:"last_run,omitempty"`
	NextRunAt    string       `json:"next_run_at,omitempty"`
	Runs24h      int          `json:"runs_24h"`
	Success24h   int          `json:"success_24h"`
	Fail24h      int          `json:"fail_24h"`
	DetailHint   string       `json:"detail_hint,omitempty"` // 前端详情跳转提示
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
	}
	tasks = append(tasks, collectCertTasks()...)
	tasks = append(tasks,
		collectAutoBackupTask(),
		collectClusterSyncTask(),
		collectWatchdogTask(),
		collectSecurityEventsIngestion(),
		collectLogRotateTask(),
		collectLogCleanupTask(),
		collectSecurityEventsRetention(),
		collectAuditRetentionTask(),
		collectCaddyAccessLogRotation(),
	)
	tasks = append(tasks, collectStartupPhases()...)
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
	ti := TaskInfo{ID: "threat", Name: "威胁情报库更新", Description: "每日从 USTC/FireHOL/ET 三源下载恶意 IP 名单，聚合去重后写入威胁库文件并同步从节点——引用名单的安全策略据此拦截", Cadence: "排程槽（可配置星期/时刻）", Category: "安全防护", Kind: TaskKindScheduled, DetailHint: "threat"}
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
	} else {
		// 进程重启后内存态为空——回退 DB 源行终态（最近完成源时间）
		var lastFinished, lastStatus, lastTrigger string
		if err := db.DB.QueryRow(`SELECT COALESCE(MAX(NULLIF(finished_at,'')),''), COALESCE(MAX(NULLIF(update_status,'')),''), COALESCE(MAX(NULLIF(trigger,'')),'') FROM security_threat_sources`).Scan(&lastFinished, &lastStatus, &lastTrigger); err == nil && lastFinished != "" {
			ti.LastRun = taskRunFromCrsLayout(lastFinished, lastFinished, lastTrigger, lastStatus, "")
		}
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
	ti := TaskInfo{ID: "crs", Name: "CRS 规则库更新", Description: "检查并更新 OWASP CoreRuleSet 规则集到最新版本（保留用户 overrides），供 WAF 拦截模式消费", Cadence: "排程槽（可配置）", Category: "安全防护", Kind: TaskKindScheduled, DetailHint: "crs"}
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
	ti := TaskInfo{ID: "ip2region", Name: "IP2Region 地理库更新", Description: "更新 IP 地理位置离线库（xdb），供 GeoIP 地域拦截与归属地展示使用", Cadence: "排程槽（可配置）", Category: "安全防护", Kind: TaskKindScheduled, DetailHint: "ip2region"}
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

// collectCertTasks 证书族：任务队列摘要 + 逐证书任务行（活跃或 24h 内有
// 动作的 job 各一行——每证书/规则一个任务，非聚合黑箱）+ 四个内部调度循环。
func collectCertTasks() []TaskInfo {
	var out []TaskInfo
	summary := TaskInfo{ID: "cert-queue", Name: "ACME 证书任务队列", Description: "ACME 签发/续签任务的处理引擎：按证书配置入队，DNS 挑战、验证、签发、部署全流程状态机", Cadence: "按需入队", Category: "证书", Kind: TaskKindQueue, Enabled: true, Status: TaskStatusIdle, DetailHint: "certificates"}
	var queued, running, failed, issued int
	if err := db.DB.QueryRow(`SELECT
		(SELECT COUNT(*) FROM cert_jobs WHERE status IN ('queued','pending')),
		(SELECT COUNT(*) FROM cert_jobs WHERE status NOT IN ('queued','pending','issued','failed','disabled')),
		(SELECT COUNT(*) FROM cert_jobs WHERE status='failed' AND COALESCE(updated_at,created_at) > datetime('now','-1 day')),
		(SELECT COUNT(*) FROM cert_jobs WHERE status='issued' AND COALESCE(updated_at,created_at) > datetime('now','-1 day'))`).Scan(&queued, &running, &failed, &issued); err == nil {
		switch {
		case running > 0:
			summary.Status = TaskStatusRunning
		case queued > 0:
			summary.Status = TaskStatusQueued
		}
		summary.Runs24h = issued + failed
		summary.Success24h = issued
		summary.Fail24h = failed
		summary.LastRun = &TaskRunInfo{Trigger: "queue", Result: string(summary.Status),
			Message: fmt.Sprintf("待处理 %d · 运行中 %d · 24h 签发 %d / 失败 %d", queued, running, issued, failed)}
	}
	out = append(out, summary)

	// 逐任务行：活跃(queued/运行中) 或 24h 内有终态的 job
	// cert_jobs 无 trigger/started_at/finished_at 列——时间面用 created/updated
	rows, err := db.DB.Query(`SELECT id, rule_id, domain, status, COALESCE(message,''), COALESCE(created_at,''), COALESCE(updated_at,created_at)
		FROM cert_jobs
		WHERE status NOT IN ('issued','failed','disabled') OR COALESCE(updated_at,created_at) > datetime('now','-1 day')
		ORDER BY COALESCE(updated_at,created_at) DESC LIMIT 20`)
	if err == nil {
		defer rows.Close()
		for rows.Next() {
			var id int
			var ruleID, domain, status, message, createdAt, updatedAt string
			if err := rows.Scan(&id, &ruleID, &domain, &status, &message, &createdAt, &updatedAt); err != nil {
				continue
			}
			trigger, startedAt, finishedAt := "auto", createdAt, updatedAt
			ti := TaskInfo{
				ID:          fmt.Sprintf("cert-job:%d", id),
				Name:        "ACME · " + domain,
				Description: "单证书签发/续签任务（规则 " + ruleID + "，阶段 " + status + "）",
				Category:    "证书",
				Kind:        TaskKindQueue,
				Enabled:     true,
				Status:      TaskStatusIdle,
			}
			switch status {
			case "failed":
				ti.Status = TaskStatusFailed
			case "issued":
				ti.Status = TaskStatusIdle
			default:
				ti.Status = TaskStatusRunning // 队列/处理中的全部运行态细分
				if status == "queued" || status == "pending" {
					ti.Status = TaskStatusQueued
				}
			}
			start := startedAt
			if start == "" {
				start = updatedAt
			}
			end := finishedAt
			if end == "" {
				end = updatedAt
			}
			ti.LastRun = &TaskRunInfo{StartedAt: start, FinishedAt: end, Trigger: orDefault(trigger, "auto"), Result: status, Message: message}
			ti.DetailHint = "certificates"
			out = append(out, ti)
		}
	}

	// 证书族内部调度循环（certificates.go 四 ticker——无 DB 状态面，常驻展示）
	out = append(out,
		TaskInfo{ID: "cert-renewal-scan", Name: "证书续期扫描", Description: "扫描全部证书配置的到期时间，临期证书自动入队续签", Cadence: "每 6 小时", Category: "证书", Kind: TaskKindScheduled, Enabled: true, Status: TaskStatusPassive},
		TaskInfo{ID: "cert-reconcile", Name: "证书状态对账", Description: "核对证书文件与数据库状态一致性，修复中断任务残留的中间态", Cadence: "每 6 小时", Category: "证书", Kind: TaskKindScheduled, Enabled: true, Status: TaskStatusPassive},
		TaskInfo{ID: "cert-manual-poll", Name: "手动证书任务轮询", Description: "处理手工触发或重试的证书任务", Cadence: "每 10 分钟", Category: "证书", Kind: TaskKindScheduled, Enabled: true, Status: TaskStatusPassive},
		TaskInfo{ID: "cert-waiting-ca", Name: "CA 等待轮询", Description: "轮询等待 CA 完成验证/签发的异步订单（LE/ZeroSSL 等）", Cadence: "每 30 秒", Category: "证书", Kind: TaskKindScheduled, Enabled: true, Status: TaskStatusPassive},
	)
	return out
}

func orDefault(v, def string) string {
	if v == "" {
		return def
	}
	return v
}

// collectAutoBackupTask 自动备份。
func collectAutoBackupTask() TaskInfo {
	ti := TaskInfo{ID: "auto-backup", Name: "自动备份", Description: "按排程把全量配置打包为 lbbak 落盘 backup 目录（含 CRS/IP2Region/威胁库数据文件），保留份数自动清理", Cadence: "按备份排程（日/周/月）", Category: "备份", Kind: TaskKindScheduled, Enabled: true, DetailHint: "backup"}
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
	// 下次执行：按排程参数算下一槽（daily/weekly/monthly）
	if next, ok := nextAutoBackupSlot(time.Now()); ok {
		ti.NextRunAt = next.UTC().Format(crsTimeLayout)
	}
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
	ti := TaskInfo{ID: "cluster-sync", Name: "集群同步（主节点签发）", Description: "主节点向从节点签发配置快照与规则库数据（CRS/IP2Region/威胁库 .fast）", Category: "集群", Kind: TaskKindContinuous, Enabled: true, Status: TaskStatusPassive, DetailHint: "cluster"}
	var isMaster int
	if err := db.DB.QueryRow("SELECT COALESCE(is_master,1) FROM global_config WHERE id=1").Scan(&isMaster); err != nil {
		ti.Status = TaskStatusNoRuns
		return ti
	}
	if isMaster == 1 {
		return ti
	}
	ti.Name = "集群同步（从节点回放）"
	ti.Description = "从节点按同步间隔轮询主节点快照，增量回放数据库与规则库数据"
	ti.Cadence = "按同步间隔设置"
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
	return TaskInfo{ID: "config-watchdog", Name: "配置漂移看门狗", Description: "每 60 秒比对运行中 Caddy 配置与数据库期望配置，漂移时面板横幅告警并触发对账", Cadence: "每 60 秒", Category: "系统", Kind: TaskKindContinuous, Enabled: true, Status: continuousStatus("config-watchdog"), Controllable: true, DetailHint: "watchdog"}
}

// collectAuditRetentionTask 审计日志保留清理。
func collectAuditRetentionTask() TaskInfo {
	ti := TaskInfo{ID: "audit-retention", Name: "审计日志保留清理", Description: "按「审计保留月数」配置删除 audit 库过期操作日志（基础设置可调）", Cadence: "每日", Category: "系统", Kind: TaskKindScheduled, Enabled: true, Status: TaskStatusPassive, DetailHint: "audit"}
	var months int
	if err := db.DB.QueryRow("SELECT COALESCE(audit_retention_months,3) FROM global_config WHERE id=1").Scan(&months); err == nil && months > 0 {
		ti.Cadence = fmt.Sprintf("每日（保留 %d 个月）", months)
	}
	return ti
}

// collectSecurityEventsIngestion 安全事件采集（coraza audit 尾读摄取+轮转，
// 2s tick——安全总览/事件页数据源）。
func collectSecurityEventsIngestion() TaskInfo {
	return TaskInfo{ID: "security-events-ingestion", Name: "安全事件采集", Description: "尾读 coraza WAF 审计日志并摄取为安全事件（安全总览/事件页的数据源），含审计日志轮转跟随", Cadence: "每 2 秒", Category: "系统", Kind: TaskKindContinuous, Enabled: true, Status: continuousStatus("security-events-ingestion"), Controllable: true, DetailHint: "security-events"}
}

// collectLogRotateTask 运行日志尺寸轮转（30s 检查 + 超限 copytruncate）。
func collectLogRotateTask() TaskInfo {
	return TaskInfo{ID: "log-rotate", Name: "运行日志尺寸轮转", Description: "按「日志大小上限」设置检查应用运行日志，超限即轮转（copytruncate，不丢正在写入的行）", Cadence: "每 30 秒", Category: "系统", Kind: TaskKindContinuous, Enabled: true, Status: TaskStatusPassive}
}

// collectLogCleanupTask 旧日志文件清理（每日——logrotate 保留窗清理）。
func collectLogCleanupTask() TaskInfo {
	return TaskInfo{ID: "log-cleanup", Name: "运行日志轮转副本清理", Description: "删除超过保留期（与审计保留月数同配置）的应用日志轮转副本（app.log.*）——Caddy 访问日志与安全事件/审计库的清理由各自独立任务负责", Cadence: "每日", Category: "系统", Kind: TaskKindScheduled, Enabled: true, Status: TaskStatusPassive}
}

// collectSecurityEventsRetention 安全事件保留清理（每日——security_events
// 保留期清理）。
func collectSecurityEventsRetention() TaskInfo {
	return TaskInfo{ID: "security-events-retention", Name: "安全事件保留清理", Description: "按保留期配置删除 metrics 库中过期的安全事件记录", Cadence: "每日", Category: "系统", Kind: TaskKindScheduled, Enabled: true, Status: TaskStatusPassive, DetailHint: "security-events"}
}

// nextAutoBackupSlot 计算自动备份的下一执行槽（复用 autoBackupDueSlot
// 逐槽推进语义；禁用或参数非法返回 false）。
func nextAutoBackupSlot(now time.Time) (time.Time, bool) {
	row, err := loadAutoBackupSettings()
	if err != nil || !row.enabled {
		return time.Time{}, false
	}
	loc := CurrentLocation()
	due, ok := autoBackupDueSlot(now.In(loc), row.freq, row.hhmm, row.day, loc)
	if !ok {
		return time.Time{}, false
	}
	if !due.After(now.In(loc)) {
		// 当前槽已触发（last_run 已吃掉）——推进一天再算
		due, ok = autoBackupDueSlot(now.In(loc).Add(24*time.Hour), row.freq, row.hhmm, row.day, loc)
	}
	return due, ok
}

// continuousStatus 常驻任务真实运行态（M2：引擎优先，TaskRuntime 回退）。
func continuousStatus(id string) TaskStatus {
	if te := TaskEngine(); te != nil {
		if te.IsRunning(id) {
			return TaskStatusRunning
		}
		if _, ctrl := TaskRuntimeState(id); ctrl || engineControllable(id) {
			return TaskStatusStopped // 可控常驻停止（区别于空闲——可再启动）
		}
		return TaskStatusIdle
	}
	if r, ok := TaskRuntimeState(id); ok {
		if r {
			return TaskStatusRunning
		}
		return TaskStatusIdle
	}
	return TaskStatusRunning
}

// scheduledRuntimeStatus 日清理类任务的运行态（调度循环在跑=running）。
func scheduledRuntimeStatus(id string) TaskStatus {
	if te := TaskEngine(); te != nil && te.IsRunning(id) {
		return TaskStatusRunning
	}
	if r, ok := TaskRuntimeState(id); ok && r {
		return TaskStatusRunning
	}
	return TaskStatusPassive
}

// collectCaddyAccessLogRotation Caddy 访问日志轮转（引擎内置——非本进程
// goroutine，随生成的 Caddy 日志配置生效：roll_size_mb=日志大小上限设置、
// roll_keep=5；被动信息行）。
func collectCaddyAccessLogRotation() TaskInfo {
	sizeMB := 100
	_ = db.DB.QueryRow("SELECT COALESCE(caddy_log_size_mb,100) FROM global_config WHERE id=1").Scan(&sizeMB)
	return TaskInfo{ID: "caddy-access-log-rotation", Name: "Caddy 访问日志轮转", Description: "由 Caddy 引擎内置执行（非面板进程任务）：访问日志超过大小上限即轮转，保留 5 份；上限在基础设置的 Caddy 日志大小中调整", Cadence: fmt.Sprintf("持续（超过 %d MB 轮转）", sizeMB), Category: "系统", Kind: TaskKindContinuous, Enabled: true, Status: TaskStatusPassive}
}

// engineControllable 引擎注册面是否提供该族启停控制。
func engineControllable(id string) bool {
	te := TaskEngine()
	if te == nil {
		return false
	}
	switch id {
	case "config-watchdog", "security-events-ingestion", "log-cleanup":
		return true
	}
	return false
}

// collectStartupPhases 启动阶段任务（oneshot——main 启动序列各阶段，
// 执行同步有序不变，此处只读 task_runs 最近一次 startup 记录做展示）。
func collectStartupPhases() []TaskInfo {
	type phaseDef struct{ id, name, desc string }
	defs := []phaseDef{
		{"startup:db-init", "启动 · 数据库初始化", "数据目录三库（主/审计/metrics）建库与全部迁移"},
		{"startup:rule-libraries", "启动 · 规则库装载", "CRS 规则种子与状态对账（waf 目录就绪）"},
		{"startup:certs", "启动 · 证书装载", "从 DB 物化全部证书文件到 certs 目录"},
		{"startup:caddy-render", "启动 · Caddy 配置渲染", "DB 期望配置渲染并应用至运行 Caddy（失败回退最后已知正确配置）"},
		{"startup:engine", "启动 · 任务引擎", "恢复孤儿运行记录、注册任务族并启动调度循环"},
	}
	var out []TaskInfo
	for _, d := range defs {
		ti := TaskInfo{ID: d.id, Name: d.name, Description: d.desc, Category: "启动", Kind: "oneshot", Enabled: false, Status: TaskStatusNoRuns}
		// 最近一次 startup 触发的运行
		var st, started, finished string
		var dur int64
		if err := db.DB.QueryRow(`SELECT status, started_at, COALESCE(finished_at,''), duration_ms FROM task_runs WHERE task_id=? AND trigger='startup' ORDER BY id DESC LIMIT 1`, d.id).Scan(&st, &started, &finished, &dur); err == nil {
			ti.Status = TaskStatus(st)
			ti.LastRun = taskRunFromCrsLayout(started, finished, "startup", st, "")
			// SQLite datetime 形态直存
			if ti.LastRun != nil {
				ti.LastRun.StartedAt = started
				ti.LastRun.FinishedAt = finished
				ti.LastRun.DurationMs = dur
			}
		}
		out = append(out, ti)
	}
	return out
}
