package services

// 任务监控聚合服务（v2.3.4）：统一枚举系统全部定时/后台任务族，聚合各族
// 状态面（DB 行 + manager 内存态）为单一 DTO，供「系统设置 → 任务监控」
// 页面与 /system/tasks 端点消费。纯读聚合——零新表零迁移；操作面（触发/
// 暂停/取消）复用各任务族既有入口（handlers 映射层）。

import (
	"fmt"
	"time"

	"lazy-balancer-v2/internal/db"
	"lazy-balancer-v2/internal/taskengine"
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
	Triggerable  bool         `json:"triggerable"`  // 支持手动触发（ManualRun 语义族）
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

// CollectSystemTasks 聚合全部任务族（终态：引擎唯一事实源——全部任务族
// 注册于任务引擎，视图=DescribeAll 元数据+task_runs 真实运行/统计；
// 零收集器零特化）。
// CollectSystemTasks 聚合全部任务族（终态：引擎唯一事实源——全部任务族
// 注册于任务引擎，视图=DescribeAll 元数据+task_runs 真实运行/统计；
// 零收集器零特化）。
func CollectSystemTasks() []TaskInfo {
	te := TaskEngine()
	if te == nil {
		return []TaskInfo{}
	}
	tasks := collectEngineFamilies(te)
	// 证书签发任务动态行（实时非终态 + 24h 内终态——执行状态进任务列表，
	// 队列卡只展示实时队列内容）
	tasks = append(tasks, collectCertJobRows()...)
	return tasks
}

// collectCertJobRows 逐签发任务行：非终态（实时队列内容）+ 24h 内终态
// （结果可见）；id=cert-job:{jobID}，日志走 /certificates/jobs/{id}/logs。
func collectCertJobRows() []TaskInfo {
	rows, err := db.DB.Query(`SELECT id, domain, status, COALESCE(message,''), COALESCE(updated_at,created_at)
		FROM cert_jobs
		WHERE status NOT IN ('issued','failed','disabled') OR COALESCE(updated_at,created_at) > datetime('now','-1 day')
		ORDER BY COALESCE(updated_at,created_at) DESC LIMIT 20`)
	if err != nil {
		return nil
	}
	defer rows.Close()
	var out []TaskInfo
	for rows.Next() {
		var id int
		var domain, status, message, updatedAt string
		if err := rows.Scan(&id, &domain, &status, &message, &updatedAt); err != nil {
			continue
		}
		ti := TaskInfo{
			ID:         fmt.Sprintf("cert-job:%d", id),
			Name:       "ACME 签发 · " + domain,
			Category:   "证书",
			Kind:       TaskKindQueue,
			Enabled:    true,
			DetailHint: "certificates",
			LastRun: &TaskRunInfo{StartedAt: localDisplayUTC(updatedAt), FinishedAt: localDisplayUTC(updatedAt),
				Trigger: "queue", Result: status, Message: message},
		}
		ti.Status = TaskStatusIdle
		switch status {
		case "failed":
			ti.Status = TaskStatusFailed
		case "issued":
			ti.Status = TaskStatusIdle
		case "queued", "pending":
			ti.Status = TaskStatusQueued
		case "disabled":
			ti.Status = TaskStatusDisabled
		default:
			ti.Status = TaskStatusRunning // 处理中各阶段
		}
		out = append(out, ti)
	}
	return out
}

// collectEngineFamilies 引擎注册族统一视图（终态：零特化零收集器——
// 元数据/开关/下一槽/状态镜像全来自 DescribeAll，最近运行与 24h 统计
// 来自 task_runs，下次时间兜底 last+interval）。
// collectEngineFamilies 引擎注册族统一视图（终态：零特化零收集器——
// 元数据/开关/下一槽/状态镜像全来自 DescribeAll，最近运行与 24h 统计
// 来自 task_runs，下次时间兜底 last+interval）。
func collectEngineFamilies(te *taskengine.Engine) []TaskInfo {
	cadences := map[string]string{
		"threat":          "排程槽（可配置星期/时刻）",
		"crs":             "排程槽（可配置）",
		"ip2region":       "排程槽（可配置）",
		"auto-backup":     "按备份排程（日/周/月）",
		"audit-retention": "每日（保留月数可配）",
	}
	var out []TaskInfo
	for _, m := range te.DescribeAll() {
		ti := TaskInfo{
			ID: m.ID, Name: m.Name, Description: m.Description,
			Category: m.Category, Kind: TaskKind(m.AsKind), // 性质口径（定时≠探测轮常驻）
			Controllable: m.Controllable, Cancellable: m.Cancelable, Triggerable: m.CanTrigger,
			Enabled: m.Enabled, DetailHint: m.Family,
		}
		// 排程槽族（下一时间以槽为权威，禁探测兜底）——仅这四个有用户排程槽；
		// 清理族虽在 cadences 有文案但本质是固定间隔（last+interval 兜底有效）。
		slotBased := m.ID == "threat" || m.ID == "crs" || m.ID == "ip2region" || m.ID == "auto-backup"
		if c, ok := cadences[m.ID]; ok {
			ti.Cadence = c
		} else if m.IntervalSec > 0 {
			ti.Cadence = "每 " + humanInterval(m.IntervalSec)
		}
		if m.ID == "cluster-sync" {
			var iv int
			if err := db.DB.QueryRow("SELECT COALESCE(sync_interval,60) FROM global_config WHERE id=1").Scan(&iv); err == nil {
				ti.Cadence = fmt.Sprintf("每 %d 秒（用户配置同步间隔）", iv)
			}
		}
		// 状态按「任务性质」分流（探测轮循环态只对真常驻有意义）：
		// · 镜像优先（manager 运行中/队列计数/角色）
		// · 定时性质 → 最近真实运行终态（空闲/失败/运行中），循环态不外露
		// · 常驻性质 → 引擎循环态（运行中/已停止）
		if m.StatusMirror != "" {
			ti.Status = TaskStatus(m.StatusMirror)
		} else if m.AsKind == taskengine.KindContinuous {
			if te.IsRunning(m.ID) {
				ti.Status = TaskStatusRunning
			} else if m.Controllable {
				ti.Status = TaskStatusStopped
			} else {
				ti.Status = TaskStatusPassive
			}
		} else {
			ti.Status = TaskStatusIdle
			if lr := te.LatestRun(m.ID); lr != nil {
				switch lr.Status {
				case "failed":
					ti.Status = TaskStatusFailed
				case "running":
					ti.Status = TaskStatusRunning
				}
			}
		}
		if !m.Enabled && ti.Status == TaskStatusIdle {
			ti.Status = TaskStatusDisabled
		}
		// 下一槽（排程族声明式）
		ti.NextRunAt = m.NextSlot
		// 最近运行 + 24h 统计（task_runs）
		if lr := te.LatestRun(m.ID); lr != nil {
			ti.LastRun = &TaskRunInfo{StartedAt: lr.StartedAt, FinishedAt: lr.FinishedAt,
				DurationMs: lr.DurationMs, Trigger: lr.Trigger, Result: lr.Status, Message: lr.Message}
			// 固定间隔族兜底：last + interval（排程槽族不兜底——见 slotBased）
			if ti.NextRunAt == "" && m.IntervalSec > 0 && m.Enabled && !slotBased {
				if t, err := time.ParseInLocation("2006-01-02 15:04:05", lr.StartedAt, CurrentLocation()); err == nil {
					ti.NextRunAt = t.Add(time.Duration(m.IntervalSec) * time.Second).Format("2006-01-02 15:04:05")
				}
			}
		}
		st := te.Stats24h(m.ID)
		ti.Runs24h, ti.Success24h, ti.Fail24h = st.Runs, st.Success, st.Fail
		out = append(out, ti)
	}
	return out
}

func humanInterval(sec int) string {
	switch {
	case sec%86400 == 0:
		d := sec / 86400
		if d == 1 {
			return "24 小时"
		}
		return fmt.Sprintf("%d 天", d)
	case sec%3600 == 0:
		return fmt.Sprintf("%d 小时", sec/3600)
	case sec%60 == 0:
		return fmt.Sprintf("%d 分钟", sec/60)
	default:
		return fmt.Sprintf("%d 秒", sec)
	}
}

// localDisplayUTC 把 DB datetime('now')/crsTimeLayout 的 UTC 时间串转为
// 配置时区展示（引擎 task_runs 已按配置时区写入——勿二次转换）。
// localDisplayUTC 把 DB datetime('now')/crsTimeLayout 的 UTC 时间串转为
// 配置时区展示（引擎 task_runs 已按配置时区写入——勿二次转换）。
func localDisplayUTC(ts string) string {
	if ts == "" {
		return ts
	}
	for _, layout := range []string{"2006-01-02 15:04:05", time.RFC3339} {
		if t, err := time.Parse(layout, ts); err == nil {
			return t.In(CurrentLocation()).Format("2006-01-02 15:04:05")
		}
	}
	return ts
}

// taskRunFromCrsLayout 用 crsTimeLayout 时间串构造最近运行（无终态=进行中，
// 时长计到当前时刻）。
// collectThreatTask 威胁情报库更新（任务级单条；源级明细在 message 汇总）。
func earliestThreatNextUpdate() string {
	var next string
	if err := db.DB.QueryRow(`SELECT MIN(COALESCE(NULLIF(next_update,''), '9999')) FROM security_threat_sources WHERE update_enabled=1`).Scan(&next); err != nil || next == "9999" {
		return ""
	}
	return next
}

// collectCRSTask CRS 规则库更新。
// collectIP2RegionTask IP2Region 地理库更新。
// collectCertTasks 证书族：任务队列摘要 + 逐证书任务行（活跃或 24h 内有
// 动作的 job 各一行——每证书/规则一个任务，非聚合黑箱）+ 四个内部调度循环。
// collectAutoBackupTask 自动备份。
// collectClusterSyncTask 集群同步（从节点常驻循环；主节点为签发方）。
// collectWatchdogTask 配置漂移看门狗（60s 常驻）。
// collectAuditRetentionTask 审计日志保留清理。
// collectSecurityEventsIngestion 安全事件采集（coraza audit 尾读摄取+轮转，
// 2s tick——安全总览/事件页数据源）。
// collectLogRotateTask 运行日志尺寸轮转（30s 检查 + 超限 copytruncate）。
// collectLogCleanupTask 旧日志文件清理（每日——logrotate 保留窗清理）。
// collectSecurityEventsRetention 安全事件保留清理（每日——security_events
// 保留期清理）。
// nextAutoBackupSlot 计算自动备份的下一执行槽（复用 autoBackupDueSlot
// 逐槽推进语义；禁用或参数非法返回 false）。
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
// scheduledRuntimeStatus 日清理类任务的运行态（调度循环在跑=running）。
// collectCaddyAccessLogRotation Caddy 访问日志轮转（引擎内置——非本进程
// goroutine，随生成的 Caddy 日志配置生效：roll_size_mb=日志大小上限设置、
// roll_keep=5；被动信息行）。
// engineControllable 引擎注册面是否提供该族启停控制。
// collectStartupPhases 启动阶段任务（oneshot——main 启动序列各阶段，
// 执行同步有序不变，此处只读 task_runs 最近一次 startup 记录做展示）。
