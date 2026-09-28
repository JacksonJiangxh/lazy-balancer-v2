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
	taskengine.SetLocation(CurrentLocation()) // 引擎时间遵循基础设置时区
	taskEngine = taskengine.NewEngine(taskengine.Options{})
	_ = taskEngine.RecoverOrphans()

	// 看门狗：60s 单轮一致性检查（引擎节拍；原生自循环进程不再启动）
	watchdogAdminURLValue = watchdogAdminURL
	taskEngine.Register(taskengine.Descriptor{
		ID:                 "config-watchdog",
		Family:             "system",
		Name:               "配置漂移看门狗",
		Description:        "每 60 秒比对运行中 Caddy 配置与数据库期望配置，漂移时面板横幅告警并触发对账",
		Category:           "系统",
		Kind:               taskengine.KindContinuous,
		RecordFailuresOnly: true,
		IntervalFn:         func() time.Duration { return 60 * time.Second },
		Run: func(rc taskengine.RunContext) error {
			WatchdogCheckOnce()
			return nil
		},
	})

	// 安全事件摄取：2s 单轮（先采集后轮转——tailer 跨轮复用保 offset 连续）
	taskEngine.Register(taskengine.Descriptor{
		ID:                 "security-events-ingestion",
		Family:             "system",
		Name:               "安全事件采集",
		Description:        "尾读 coraza WAF 审计日志并摄取为安全事件（安全总览/事件页的数据源），含审计日志轮转跟随",
		Category:           "系统",
		Kind:               taskengine.KindContinuous,
		RecordFailuresOnly: true,
		IntervalFn:         func() time.Duration { return 2 * time.Second },
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

	// M3：三更新族排程探测（1min 单轮；内部自带 due/总闸/单飞门；
	// master-only——引擎角色门与族内 is_master 检查双保险）
	taskEngine.Register(taskengine.Descriptor{
		ID: "threat", Family: "security", Name: "威胁情报库更新",
		Description: "每日从 USTC/FireHOL/ET 三源下载恶意 IP 名单，聚合去重后写入威胁库文件并同步从节点——引用名单的安全策略据此拦截",
		Category:    "安全防护", Kind: taskengine.KindContinuous, RunsOn: taskengine.RoleMasterOnly, Cancelable: true,
		IntervalFn:   func() time.Duration { return time.Minute },
		SilentProbes: true,
		CancelHook:   func() bool { return GetThreatUpdateManager() != nil && GetThreatUpdateManager().CancelRunning() },
		Run: func(rc taskengine.RunContext) error {
			ThreatSchedulerTickOnce()
			return nil
		},
	})
	taskEngine.Register(taskengine.Descriptor{
		ID: "crs", Family: "security", Name: "CRS 规则库更新",
		Description: "检查并更新 OWASP CoreRuleSet 规则集到最新版本（保留用户 overrides），供 WAF 拦截模式消费",
		Category:    "安全防护", Kind: taskengine.KindContinuous, RunsOn: taskengine.RoleMasterOnly, Cancelable: true,
		IntervalFn:   func() time.Duration { return time.Minute },
		SilentProbes: true,
		CancelHook:   func() bool { return GetCRSUpdateManager().CancelRunning() },
		Run: func(rc taskengine.RunContext) error {
			CRSSchedulerTickOnce()
			return nil
		},
	})
	taskEngine.Register(taskengine.Descriptor{
		ID: "ip2region", Family: "security", Name: "IP2Region 地理库更新",
		Description: "更新 IP 地理位置离线库（xdb），供 GeoIP 地域拦截与归属地展示使用",
		Category:    "安全防护", Kind: taskengine.KindContinuous, RunsOn: taskengine.RoleMasterOnly, Cancelable: true,
		IntervalFn:   func() time.Duration { return time.Minute },
		SilentProbes: true,
		CancelHook:   func() bool { return GetIP2RegionUpdateManager() != nil && GetIP2RegionUpdateManager().CancelRunning() },
		Run: func(rc taskengine.RunContext) error {
			IP2RegionSchedulerTickOnce()
			return nil
		},
	})

	// M4：自动备份（1min 探测，master-only——补跑/槽判定在体内）+ 两个
	// 每日清理族（本节点本地表，与角色无关）。
	taskEngine.Register(taskengine.Descriptor{
		ID: "auto-backup", Family: "backup", Name: "自动备份",
		Description: "按排程把全量配置打包为 lbbak 落盘 backup 目录（含 CRS/IP2Region/威胁库数据文件），保留份数自动清理",
		Category:    "备份", Kind: taskengine.KindContinuous, RunsOn: taskengine.RoleMasterOnly, SilentProbes: true,
		IntervalFn: func() time.Duration { return time.Minute },
		Run: func(rc taskengine.RunContext) error {
			AutoBackupSchedulerTickOnce()
			return nil
		},
	})
	taskEngine.Register(taskengine.Descriptor{
		ID: "audit-retention", Family: "system", Name: "审计日志保留清理",
		Description: "按「审计保留月数」配置删除 audit 库过期操作日志（基础设置可调）",
		Category:    "系统", Kind: taskengine.KindContinuous,
		IntervalFn: func() time.Duration { return 24 * time.Hour },
		Run: func(rc taskengine.RunContext) error {
			CleanupAuditLogs()
			return nil
		},
	})
	taskEngine.Register(taskengine.Descriptor{
		ID: "security-events-retention", Family: "system", Name: "安全事件保留清理",
		Description: "按保留期配置删除 metrics 库中过期的安全事件记录",
		Category:    "系统", Kind: taskengine.KindContinuous,
		IntervalFn: func() time.Duration { return 24 * time.Hour },
		Run: func(rc taskengine.RunContext) error {
			SecurityEventsRetentionCleanupOnce()
			return nil
		},
	})

	for _, id := range []string{"config-watchdog", "security-events-ingestion", "log-cleanup", "threat", "crs", "ip2region", "auto-backup", "audit-retention", "security-events-retention"} {
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
