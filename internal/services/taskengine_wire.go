package services

// 任务引擎接线（v2.3.4 M2）：常驻三族迁入统一引擎——看门狗/安全事件摄取/
// 运行日志清理。引擎驱动节拍（单轮体），原生自循环进程退役；TaskRuntime
// 注册表退役（引擎 StartLoop/StopLoop/IsRunning 承接）。
// main.go 启动顺序变更：InitTaskEngine（含崩溃恢复+注册+启动循环）替代
// 原 StartConfigWatchdog / StartSecurityEventsIngestion / StartRuntimeLogCleanup。

import (
	"time"

	"lazy-balancer-v2/internal/taskengine"
)

var taskEngine *taskengine.Engine

// TaskEngine 返回全局引擎实例（未初始化返回 nil——测试环境）。
func TaskEngine() *taskengine.Engine { return taskEngine }

// InitTaskEngine 建引擎、恢复孤儿运行、注册常驻三族并启动循环。幂等。
// watchdogAdminURL：看门狗检查的 Caddy admin 地址；runtimeLogFile：运行
// 日志清理的日志文件路径（空则跳过该族注册）。
func InitTaskEngine(watchdogAdminURL, runtimeLogFile string) *taskengine.Engine {
	if taskEngine != nil {
		return taskEngine
	}
	taskEngine = taskengine.NewEngine(taskengine.Options{})
	_ = taskEngine.RecoverOrphans()

	// 看门狗：60s 单轮一致性检查（引擎节拍；原生自循环进程不再启动）
	watchdogAdminURLValue = watchdogAdminURL
	taskEngine.Register(taskengine.Descriptor{
		ID:          "config-watchdog",
		Family:      "system",
		Name:        "配置漂移看门狗",
		Description: "每 60 秒比对运行中 Caddy 配置与数据库期望配置，漂移时面板横幅告警并触发对账",
		Category:    "系统",
		Kind:        taskengine.KindContinuous,
		IntervalFn:  func() time.Duration { return 60 * time.Second },
		Run: func(rc taskengine.RunContext) error {
			WatchdogCheckOnce()
			return nil
		},
	})

	// 安全事件摄取：2s 单轮（先采集后轮转——tailer 跨轮复用保 offset 连续）
	taskEngine.Register(taskengine.Descriptor{
		ID:          "security-events-ingestion",
		Family:      "system",
		Name:        "安全事件采集",
		Description: "尾读 coraza WAF 审计日志并摄取为安全事件（安全总览/事件页的数据源），含审计日志轮转跟随",
		Category:    "系统",
		Kind:        taskengine.KindContinuous,
		IntervalFn:  func() time.Duration { return 2 * time.Second },
		Run: func(rc taskengine.RunContext) error {
			SecurityEventsPollOnce()
			return nil
		},
	})

	// 运行日志清理：每日单轮（M3 排程槽统一后切 ScheduleSpec）
	if runtimeLogFile != "" {
		taskEngine.Register(taskengine.Descriptor{
			ID:          "log-cleanup",
			Family:      "system",
			Name:        "运行日志轮转副本清理",
			Description: "删除超过保留期（与审计保留月数同配置）的应用日志轮转副本（app.log.*）",
			Category:    "系统",
			Kind:        taskengine.KindContinuous,
			IntervalFn:  func() time.Duration { return 24 * time.Hour },
			Run: func(rc taskengine.RunContext) error {
				RuntimeLogCleanupOnce(runtimeLogFile)
				return nil
			},
		})
	}

	for _, id := range []string{"config-watchdog", "security-events-ingestion", "log-cleanup"} {
		if id == "log-cleanup" && runtimeLogFile == "" {
			continue
		}
		taskEngine.StartLoop(id)
	}
	return taskEngine
}

// StopTaskEngine 进程退出收尾。
func StopTaskEngine() {
	if taskEngine != nil {
		taskEngine.Stop()
		taskEngine = nil
	}
}
