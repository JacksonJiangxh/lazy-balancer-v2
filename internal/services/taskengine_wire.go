package services

// 任务引擎接线（v2.3.4 M2）：常驻三族迁入统一引擎——看门狗/安全事件摄取/
// 运行日志清理。引擎驱动节拍（单轮体），原生自循环进程退役；TaskRuntime
// 注册表退役（引擎 StartLoop/StopLoop/IsRunning 承接）。
// main.go 启动顺序变更：InitTaskEngine（含崩溃恢复+注册+启动循环）替代
// 原 StartConfigWatchdog / StartSecurityEventsIngestion / StartRuntimeLogCleanup。

import (
	"time"

	"lazy-balancer-v2/internal/db"
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

	// 运行日志清理：每日单轮（日志文件路径为空时 Run 空转——注册恒在，任务族清单稳定）
	logFile := runtimeLogFile
	taskEngine.Register(taskengine.Descriptor{
		ID:          "log-cleanup",
		Family:      "system",
		Name:        "运行日志轮转副本清理",
		Description: "删除超过保留期（与审计保留月数同配置）的应用日志轮转副本（app.log.*）",
		Category:    "系统",
		Kind:        taskengine.KindContinuous,
		IntervalFn:  func() time.Duration { return 24 * time.Hour },
		Run: func(rc taskengine.RunContext) error {
			if logFile != "" {
				RuntimeLogCleanupOnce(logFile)
			}
			return nil
		},
	})

	// M3：三更新族排程探测（1min 单轮；内部自带 due/总闸/单飞门；
	// master-only——引擎角色门与族内 is_master 检查双保险）
	taskEngine.Register(taskengine.Descriptor{
		ID: "threat", Family: "security", Name: "威胁情报库更新",
		Description: "每日从 USTC/FireHOL/ET 三源下载恶意 IP 名单，聚合去重后写入威胁库文件并同步从节点——引用名单的安全策略据此拦截",
		Category:    "安全防护", Kind: taskengine.KindContinuous, RunsOn: taskengine.RoleMasterOnly, Cancelable: true,
		IntervalFn: func() time.Duration { return time.Minute },
		EnabledFn:  func() bool { return ThreatAutoUpdateEnabled() },
		NextSlotFn: func() string {
			if n := earliestThreatNextUpdate(); n != "" {
				return localDisplayUTC(n)
			}
			return ""
		},
		StatusFn: func() string {
			if m := GetThreatUpdateManager(); m != nil && m.StatusSnapshot().Running {
				return "running"
			}
			return ""
		},
		SilentProbes: true,
		MasterOnly:   true,
		CancelHook:   func() bool { return GetThreatUpdateManager() != nil && GetThreatUpdateManager().CancelRunning() },
		Run: func(rc taskengine.RunContext) error {
			if rc.Trigger == "manual" {
				if m := GetThreatUpdateManager(); m != nil {
					return m.RunUpdate("manual") // 同步全量——manager 编舞原样
				}
				return nil
			}
			ThreatSchedulerTickOnce()
			return nil
		},
	})
	taskEngine.Register(taskengine.Descriptor{
		ID: "crs", Family: "security", Name: "CRS 规则库更新",
		Description: "检查并更新 OWASP CoreRuleSet 规则集到最新版本（保留用户 overrides），供 WAF 拦截模式消费",
		Category:    "安全防护", Kind: taskengine.KindContinuous, RunsOn: taskengine.RoleMasterOnly, Cancelable: true,
		IntervalFn: func() time.Duration { return time.Minute },
		EnabledFn: func() bool {
			var en int
			if err := db.DB.QueryRow("SELECT COALESCE(auto_update,1) FROM security_crs_version WHERE id=1").Scan(&en); err != nil {
				return true
			}
			return en == 1
		},
		NextSlotFn: func() string {
			var next string
			if err := db.DB.QueryRow("SELECT COALESCE(NULLIF(next_update,'','') FROM security_crs_version WHERE id=1").Scan(&next); err == nil && next != "" {
				return localDisplayUTC(next)
			}
			return ""
		},
		StatusFn: func() string {
			m := GetCRSUpdateManager()
			if m == nil {
				return ""
			}
			st := m.StatusSnapshot().Status
			if st == string(CRSStatusIdle) || st == string(CRSStatusSuccess) || st == "" {
				return ""
			}
			return "running"
		},
		SilentProbes: true,
		MasterOnly:   true,
		CancelHook:   func() bool { m := GetCRSUpdateManager(); return m != nil && m.CancelRunning() },
		Run: func(rc taskengine.RunContext) error {
			if rc.Trigger == "manual" {
				m := GetCRSUpdateManager()
				if m == nil {
					return nil
				}
				done, err := m.StartUpdate("manual")
				if err != nil {
					return err
				}
				<-done // 等编舞完成——历史耗时真实
				return nil
			}
			CRSSchedulerTickOnce()
			return nil
		},
	})
	taskEngine.Register(taskengine.Descriptor{
		ID: "ip2region", Family: "security", Name: "IP2Region 地理库更新",
		Description: "更新 IP 地理位置离线库（xdb），供 GeoIP 地域拦截与归属地展示使用",
		Category:    "安全防护", Kind: taskengine.KindContinuous, RunsOn: taskengine.RoleMasterOnly, Cancelable: true,
		IntervalFn: func() time.Duration { return time.Minute },
		EnabledFn: func() bool {
			var en int
			if err := db.DB.QueryRow("SELECT COALESCE(auto_update,1) FROM security_ip2region_version WHERE id=1").Scan(&en); err != nil {
				return true
			}
			return en == 1
		},
		NextSlotFn: func() string {
			var next string
			if err := db.DB.QueryRow("SELECT COALESCE(NULLIF(next_update,'','') FROM security_ip2region_version WHERE id=1").Scan(&next); err == nil && next != "" {
				return localDisplayUTC(next)
			}
			return ""
		},
		StatusFn: func() string {
			var status string
			_ = db.DB.QueryRow("SELECT COALESCE(update_status,'') FROM security_ip2region_version WHERE id=1").Scan(&status)
			if status == "" || status == "idle" || status == "success" {
				return ""
			}
			return "running"
		},
		SilentProbes: true,
		MasterOnly:   true,
		CancelHook:   func() bool { return GetIP2RegionUpdateManager() != nil && GetIP2RegionUpdateManager().CancelRunning() },
		Run: func(rc taskengine.RunContext) error {
			if rc.Trigger == "manual" {
				m := GetIP2RegionUpdateManager()
				if m == nil {
					return nil
				}
				done, err := m.StartUpdate("manual")
				if err != nil {
					return err
				}
				<-done
				return nil
			}
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
		EnabledFn: func() bool {
			row, err := loadAutoBackupSettings()
			return err != nil || row.enabled
		},
		NextSlotFn: func() string {
			if next, ok := nextAutoBackupSlot(time.Now()); ok {
				return next.In(CurrentLocation()).Format(crsTimeLayout)
			}
			return ""
		},
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

	// —— 证书族：四内部循环（引擎接管节拍，原生 ticker 让位）+ 队列镜像 ——
	taskEngine.Register(taskengine.Descriptor{
		ID: "cert-renewal-scan", Family: "certificates", Name: "证书续期扫描",
		Description: "扫描全部证书配置的到期时间，临期证书自动入队续签",
		Category:    "证书", Kind: taskengine.KindContinuous,
		IntervalFn: func() time.Duration { return 6 * time.Hour },
		Run:        func(rc taskengine.RunContext) error { CertRenewalScanOnce(); return nil },
	})
	taskEngine.Register(taskengine.Descriptor{
		ID: "cert-reconcile", Family: "certificates", Name: "证书状态对账",
		Description: "核对证书文件与数据库状态一致性，修复中断任务残留的中间态",
		Category:    "证书", Kind: taskengine.KindContinuous,
		IntervalFn: func() time.Duration { return 6 * time.Hour },
		Run:        func(rc taskengine.RunContext) error { CertReconcileOnce(); return nil },
	})
	taskEngine.Register(taskengine.Descriptor{
		ID: "cert-manual-poll", Family: "certificates", Name: "手动证书任务轮询",
		Description: "处理手工触发或重试的证书任务",
		Category:    "证书", Kind: taskengine.KindContinuous,
		RecordFailuresOnly: true,
		IntervalFn:         func() time.Duration { return 10 * time.Minute },
		Run:                func(rc taskengine.RunContext) error { CertManualCheckOnce(); return nil },
	})
	taskEngine.Register(taskengine.Descriptor{
		ID: "cert-waiting-ca", Family: "certificates", Name: "CA 等待轮询",
		Description: "轮询等待 CA 完成验证/签发的异步订单（LE/ZeroSSL 等），含滞留/断链补扫",
		Category:    "证书", Kind: taskengine.KindContinuous,
		RecordFailuresOnly: true, // 30s 补扫成功静默——仅断链/失败留痕
		IntervalFn:         func() time.Duration { return 30 * time.Second },
		StatusFn: func() string { // 有等待/滞留任务才「运行中」——空闲不空转显示
			var n int
			_ = db.DB.QueryRow(`SELECT COUNT(*) FROM cert_jobs WHERE status IN ('waiting_ca','queued','pending')`).Scan(&n)
			if n > 0 {
				return "running"
			}
			return ""
		},
		NextSlotFn: func() string { // 有等待任务时展示最近 CA 可用时间
			var at string
			if err := db.DB.QueryRow(`SELECT COALESCE(MIN(NULLIF(ca_available_after,'','') FROM cert_jobs WHERE status='waiting_ca'`).Scan(&at); err == nil && at != "" {
				return localDisplayUTC(at)
			}
			return ""
		},
		Run: func(rc taskengine.RunContext) error { CertWaitingCATickOnce(); return nil },
	})
	// —— 集群同步（角色驱动循环：身份入册，执行留集群服务——promote/demote 生命周期） ——
	taskEngine.Register(taskengine.Descriptor{
		ID: "cluster-sync", Family: "cluster", Name: "集群同步",
		Description: "从节点按同步间隔轮询主节点快照并增量回放；主节点为签发方（被动）",
		Category:    "集群", Kind: taskengine.KindInfo,
		StatusFn: func() string {
			var isMaster int
			if err := db.DB.QueryRow("SELECT COALESCE(is_master,1) FROM global_config WHERE id=1").Scan(&isMaster); err != nil {
				return ""
			}
			if isMaster == 1 {
				return "passive"
			}
			return "running"
		},
	})
	// —— 系统配置载入（oneshot：规则库/证书/Caddy 渲染三段合一——完成于
	// 面板监听之前，载入完成前系统不可达（强于只读）；db-init 与引擎启动
	// 为前置设施不入册 ——） ——
	taskEngine.Register(taskengine.Descriptor{
		ID:          "startup:config-load",
		Family:      "startup",
		Name:        "系统配置载入",
		Description: "启动时从数据库装载运行态：规则库（CRS 种子/对账）→ 证书文件物化 → Caddy 配置渲染与应用（失败回退最后已知正确配置）。完成前面板不监听",
		Category:    "触发",
		Kind:        taskengine.KindQueue, // 展示类 oneshot（每次重启一行历史）
		Run:         nil,
	})

	// 任务性质批量标定（展示口径）：排程/固定间隔族由探测轮或间隔驱动，
	// 但性质是「定时」——只有真常驻循环（看门狗/事件摄取）是「常驻」。
	for _, id := range []string{"threat", "crs", "ip2region", "auto-backup", "log-cleanup", "audit-retention", "security-events-retention", "cert-renewal-scan", "cert-reconcile", "cert-manual-poll", "cert-waiting-ca"} {
		taskEngine.SetAsKind(id, taskengine.KindScheduled)
	}

	for _, id := range []string{"config-watchdog", "security-events-ingestion", "log-cleanup", "threat", "crs", "ip2region", "auto-backup", "audit-retention", "security-events-retention", "cert-renewal-scan", "cert-reconcile", "cert-manual-poll", "cert-waiting-ca"} {
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
