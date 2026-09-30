package services

// 任务监控聚合服务（v2.3.4）：统一枚举系统全部定时/后台任务族，聚合各族
// 状态面（DB 行 + manager 内存态）为单一 DTO，供「系统设置 → 任务监控」
// 页面与 /system/tasks 端点消费。纯读聚合——零新表零迁移；操作面（触发/
// 暂停/取消）复用各任务族既有入口（handlers 映射层）。

import (
	"fmt"
	"os"
	"time"

	"lazy-balancer-v2/internal/db"
	"lazy-balancer-v2/internal/taskengine"
)

// TaskKind 任务类型（v2.0 四类型标准）。
type TaskKind string

const (
	TaskKindScheduled TaskKind = "scheduled" // 定时：排程槽驱动
	TaskKindDaemon    TaskKind = "daemon"    // 常驻：自管理循环
	TaskKindPeriodic  TaskKind = "periodic"  // 循环：固定间隔
	TaskKindOneshot   TaskKind = "oneshot"   // 触发：手动/代码触发
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
	Enabled      bool         `json:"enabled"`              // 自动调度开关
	Cancellable  bool         `json:"cancellable"`          // 运行中可手动取消（仅下载类）
	Controllable bool         `json:"controllable"`         // 常驻循环可启停（start/stop/restart）
	Triggerable  bool         `json:"triggerable"`          // 支持手动触发（ManualRun 语义族）
	Toggleable   bool         `json:"toggleable"`           // 调度开关可暂停/恢复（ToggleFn 声明族）
	StartedAt    string       `json:"started_at,omitempty"` // 常驻族启动时刻；其他类型空
	LogSizeBytes int64        `json:"log_size_bytes"`       // 本任务日志文件大小（字节）
	LoopOn       bool         `json:"loop_on"`              // 调度开关当前态（定时/循环/常驻调度列绑定值）
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
		WHERE status NOT IN ('issued','disabled') OR (status = 'issued' AND COALESCE(updated_at,created_at) > datetime('now','-1 day'))
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
		// 终态计数（2026-09-29 用户反馈：签发成功应成功+1）——24h 窗口内
		// issued=成功 1、failed=失败 1（作业实例行，无周期 runs 概念）。
		success, fail := 0, 0
		switch status {
		case "issued":
			success = 1
		case "failed":
			fail = 1
		}
		ti := TaskInfo{
			ID:         fmt.Sprintf("cert-job:%d", id),
			Name:       "ACME 签发 · " + domain,
			Category:   "证书",
			Kind:       TaskKindOneshot, // 动态签发行=按需触发的工作项
			Enabled:    true,
			DetailHint: "certificates",
			LastRun: &TaskRunInfo{StartedAt: localDisplayUTC(updatedAt), FinishedAt: localDisplayUTC(updatedAt),
				Trigger: "queue", Result: status, Message: message},
		}
		ti.Success24h, ti.Fail24h = success, fail
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
	if err := rows.Err(); err != nil {
		// U3-P4-4：迭代失败不再静默部分列表（曾 rows.Err 未查）
		Logf("warn", "cert 任务行迭代失败: %v", err)
	}
	return out
}

// collectEngineFamilies 引擎注册族统一视图（终态：零特化零收集器——
// 元数据/开关/下一槽/状态镜像全来自 DescribeAll，最近运行与 24h 统计
// 来自 task_runs，下次时间兜底 last+interval）。
func collectEngineFamilies(te *taskengine.Engine) []TaskInfo {
	var out []TaskInfo
	for _, m := range te.DescribeAll() {
		ti := TaskInfo{
			ID: m.ID, Name: m.Name, Description: m.Description,
			Category: m.Category, Kind: TaskKind(m.Kind),
			Controllable: m.Controllable, Cancellable: m.Cancelable, Triggerable: m.CanTrigger,
			Toggleable: m.Toggleable, Enabled: m.Enabled, DetailHint: m.Family,
			LoopOn: m.LoopOn,
		}
		// 节奏：循环=间隔，定时=排程槽，常驻=自管理，触发=手动
		switch m.Kind {
		case taskengine.KindPeriodic:
			if m.IntervalSec > 0 {
				ti.Cadence = "每 " + humanInterval(m.IntervalSec)
			}
		case taskengine.KindDaemon:
			ti.Cadence = "常驻自管理"
		case taskengine.KindOneshot:
			ti.Cadence = "手动触发"
		}
		if m.ID == "cluster-sync" {
			var iv int
			if err := db.DB.QueryRow("SELECT COALESCE(sync_interval,60) FROM global_config WHERE id=1").Scan(&iv); err == nil {
				ti.Cadence = fmt.Sprintf("每 %d 秒（用户配置同步间隔）", iv)
			}
		}
		// 状态分流（v2.0 四类型）：
		// · 镜像优先（manager 运行中/队列计数/角色/cert-waiting-ca 门控）
		// · 常驻 → 调度开关态（运行中/已停止）
		// · 定时/循环/触发 → 最近真实运行终态（空闲/失败/运行中）
		if m.StatusMirror != "" {
			ti.Status = TaskStatus(m.StatusMirror)
		} else if m.Kind == taskengine.KindDaemon {
			if m.LoopOn {
				ti.Status = TaskStatusRunning
			} else {
				ti.Status = TaskStatusStopped
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
		if !m.LoopOn && m.Kind != taskengine.KindOneshot && ti.Status == TaskStatusIdle {
			ti.Status = TaskStatusDisabled // 调度关闭（如 cert-waiting-ca 默认态）
		}
		if !m.Enabled && ti.Status == TaskStatusIdle {
			ti.Status = TaskStatusDisabled // 业务开关联动（自动更新关闭/备份未启用——2026-10-01 用户裁定）
		}
		// 下一槽：定时=NextSlotFn（声明式）；循环=last+interval 兜底
		ti.NextRunAt = m.NextSlot
		if lr := te.LatestRun(m.ID); lr != nil {
			ti.LastRun = &TaskRunInfo{StartedAt: lr.StartedAt, FinishedAt: lr.FinishedAt,
				DurationMs: lr.DurationMs, Trigger: lr.Trigger, Result: lr.Status, Message: lr.Message}
			if ti.NextRunAt == "" && m.IntervalSec > 0 && m.LoopOn && m.Kind == taskengine.KindPeriodic {
				if t, err := time.ParseInLocation("2006-01-02 15:04:05", lr.StartedAt, CurrentLocation()); err == nil {
					ti.NextRunAt = t.Add(time.Duration(m.IntervalSec) * time.Second).Format("2006-01-02 15:04:05")
				}
			}
		}
		// 每任务日志文件大小（tasks/{id}.log stat）
		if info, err := os.Stat(taskengine.TaskLogPath(m.ID)); err == nil {
			ti.LogSizeBytes = info.Size()
		}
		st := te.Stats24h(m.ID)
		ti.Runs24h, ti.Success24h, ti.Fail24h = st.Runs, st.Success, st.Fail
		// 常驻族启动时刻——「常驻 · 启动于」展示位
		if m.Kind == taskengine.KindDaemon {
			ti.StartedAt = te.StartedAt().In(CurrentLocation()).Format("2006-01-02 15:04:05")
		}
		out = append(out, ti)
	}
	return out
}

// TaskLogf 业务摘要行（SPEC §6.5：每个真实执行轮在 tasks/{id}.log 留业务
// 结果——「无临期证书/清理 N 条/摄取 N 条」等；时间戳与 tee 流水同形态）。
func TaskLogf(taskID, stage, format string, args ...any) {
	taskengine.TeeTaskLogTime(taskID, "INFO", stage, fmt.Sprintf(format, args...))
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

func earliestThreatNextUpdate() string {
	var next string
	if err := db.DB.QueryRow(`SELECT MIN(COALESCE(NULLIF(next_update,''), '9999')) FROM security_threat_sources WHERE update_enabled=1`).Scan(&next); err != nil || next == "9999" {
		return ""
	}
	return next
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
		// 漏跑追补：最近过去的槽未被 last_run 覆盖 → 返回该槽（≤now——
		// v2.0 Scheduled 引擎到点立即触发=跨停机窗口补跑）
		if row.lastRun == nil || due.After(*row.lastRun) {
			return due, true
		}
		// 已执行——步进到下一未来槽
		// （R63-P2-4：曾恒 +24h——weekly/monthly 时追不上下一槽，下次执行恒显示过去时刻）
		step := now.In(loc).Add(24 * time.Hour)
		switch row.freq {
		case "weekly":
			step = now.In(loc).Add(7 * 24 * time.Hour)
		case "monthly":
			step = now.In(loc).AddDate(0, 1, 0)
		}
		due, ok = autoBackupDueSlot(step, row.freq, row.hhmm, row.day, loc)
	}
	return due, ok
}
