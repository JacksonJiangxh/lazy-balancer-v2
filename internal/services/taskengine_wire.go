package services

// 任务引擎接线（v2.3.4 M2）：全部任务族（15 描述符）迁入统一引擎——引擎
// 驱动节拍（单轮体），原生自循环进程退役；TaskRuntime 注册表已删除
// （引擎 StartLoop/StopLoop/IsRunning 承接，U1-P4-1 退役执行）。
// main.go 启动顺序变更：InitTaskEngine（含崩溃恢复+注册+启动循环）替代
// 原 StartConfigWatchdog / StartSecurityEventsIngestion / StartRuntimeLogCleanup。

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"lazy-balancer-v2/internal/db"
	"lazy-balancer-v2/internal/taskengine"
)

var taskEngine *taskengine.Engine

// configLoadRerun 系统配置载入手动重载钩子（main 注入：DB 渲染→强制应用）。
var configLoadRerun func() error

// SetConfigLoadRerun 注入手动重载实现。
func SetConfigLoadRerun(fn func() error) { configLoadRerun = fn }

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
	logsDir := "/app/logs"
	if runtimeLogFile != "" {
		logsDir = filepath.Dir(runtimeLogFile)
	}
	tasksLogDir := filepath.Join(logsDir, "tasks")
	_ = os.MkdirAll(tasksLogDir, 0755)
	taskengine.SetLogDir(tasksLogDir) // 每任务文本日志（统一管理）
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
				removed := RuntimeLogCleanupOnce(logFile)
				TaskLogf("log-cleanup", "cleanup", "运行日志轮转副本清理完成：删除 %d 个过期副本（保留 %d 月，无过期为 0）", removed, 3)
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
		Singleton:  true, // P3-7：任务监控双击窗口防假 failed 行
		Cadence:    "排程槽（可配置星期/时刻）",
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
		ToggleFn:     SetThreatAutoUpdate, // U1-P4-2：调度开关元数据化（handler 读 DescribeAll 路由）
		ToggleName:   "威胁情报库自动更新",
		Run: func(rc taskengine.RunContext) error {
			if rc.Trigger == "manual" {
				if m := GetThreatUpdateManager(); m != nil {
					return m.RunUpdate("manual", &rc) // 同步全量——manager 编舞原样
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
		Singleton:  true,
		Cadence:    "排程槽（可配置）",
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
			if err := db.DB.QueryRow("SELECT COALESCE(NULLIF(next_update,''),'') FROM security_crs_version WHERE id=1").Scan(&next); err == nil && next != "" {
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
		ToggleFn:     SetCRSAutoUpdate,
		ToggleName:   "CRS 自动更新",
		Run: func(rc taskengine.RunContext) error {
			if rc.Trigger == "manual" {
				m := GetCRSUpdateManager()
				if m == nil {
					return nil
				}
				done, err := m.StartUpdate("manual", &rc)
				if err != nil {
					return err
				}
				<-done // 等编舞完成——历史耗时真实
				// 引擎行的终态由 runErr 决定（P2-④ 单写方）——异步编舞失败
				// 经内存快照映射为错误，防引擎行误记 success。
				if snap := m.StatusSnapshot(); snap.Status == string(CRSStatusFailed) {
					return fmt.Errorf("CRS 更新失败: %s", snap.Message)
				}
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
		Singleton:  true,
		Cadence:    "排程槽（可配置）",
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
			if err := db.DB.QueryRow("SELECT COALESCE(NULLIF(next_update,''),'') FROM security_ip2region_version WHERE id=1").Scan(&next); err == nil && next != "" {
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
		ToggleFn:     SetIP2RegionAutoUpdate,
		ToggleName:   "IP2Region 自动更新",
		Run: func(rc taskengine.RunContext) error {
			if rc.Trigger == "manual" {
				m := GetIP2RegionUpdateManager()
				if m == nil {
					return nil
				}
				done, err := m.StartUpdate("manual", &rc)
				if err != nil {
					return err
				}
				<-done
				if snap := m.StatusSnapshot(); snap.Status == string(IP2RegionStatusFailed) {
					return fmt.Errorf("IP2Region 更新失败: %s", snap.Message)
				}
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
		Singleton:  true,
		Cadence:    "按备份排程（日/周/月）",
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
			if rc.Trigger == "manual" {
				exec := currentAutoBackupExecutor()
				if exec == nil {
					return errors.New("备份执行器未就绪")
				}
				// rc.RunID=引擎预插行——执行器跳过自记（P2-④ 单写方）；
				// operator 经引擎通道传入（U1-P3-1 手动操作归人）。
				return exec("manual", rc.Operator, rc.RunID)
			}
			AutoBackupSchedulerTickOnce()
			return nil
		},
	})
	taskEngine.Register(taskengine.Descriptor{
		ID: "audit-retention", Family: "system", Name: "审计日志保留清理",
		Description: "按「审计保留月数」配置删除 audit 库过期操作日志（基础设置可调）；并清理 90 天前的任务运行历史（task_runs）",
		Category:    "系统", Kind: taskengine.KindContinuous, Cadence: "每日（保留月数可配）",

		IntervalFn: func() time.Duration { return 24 * time.Hour },
		Run: func(rc taskengine.RunContext) error {
			auditDeleted := CleanupAuditLogs()
			runsDeleted := taskengine.PurgeTaskRuns(90) // 运行历史保留 90 天（API 只显 50 次，表内超期自动清理）
			TaskLogf("audit-retention", "cleanup", "清理完成：审计日志 %d 条、任务运行历史 %d 行（无过期数据时为 0）", auditDeleted, runsDeleted)
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
			TaskLogf("security-events-retention", "cleanup", "安全事件保留清理完成（按保留期与条数上限，明细见运行日志）")
			return nil
		},
	})

	// —— 证书族：四内部循环（引擎接管节拍，原生 ticker 让位）+ 队列镜像 ——
	// RunsOn=RoleMasterOnly（U7-P3-2）：原生循环时代仅 master 跑（StartACME
	// 只在主节点/promote 调用）——引擎接管后以显式角色门复刻，消除对
	// activeCertService=nil 隐性让位的依赖（cert-reconcile 曾在从节点真实执行）。
	taskEngine.Register(taskengine.Descriptor{
		ID: "cert-renewal-scan", Family: "certificates", Name: "证书续期扫描",
		Description: "扫描全部证书配置的到期时间，临期证书自动入队续签",
		Category:    "证书", Kind: taskengine.KindContinuous, RunsOn: taskengine.RoleMasterOnly,
		IntervalFn: func() time.Duration { return 6 * time.Hour },
		Run:        func(rc taskengine.RunContext) error { CertRenewalScanOnce(); return nil },
	})
	taskEngine.Register(taskengine.Descriptor{
		ID: "cert-reconcile", Family: "certificates", Name: "证书状态对账",
		Description: "核对证书文件与数据库状态一致性，修复中断任务残留的中间态",
		Category:    "证书", Kind: taskengine.KindContinuous, RunsOn: taskengine.RoleMasterOnly,
		IntervalFn: func() time.Duration { return 6 * time.Hour },
		Run:        func(rc taskengine.RunContext) error { CertReconcileOnce(); return nil },
	})
	taskEngine.Register(taskengine.Descriptor{
		ID: "cert-manual-poll", Family: "certificates", Name: "手动证书任务轮询",
		Description: "处理手工触发或重试的证书任务",
		Category:    "证书", Kind: taskengine.KindContinuous, RunsOn: taskengine.RoleMasterOnly,
		RecordFailuresOnly: true,
		IntervalFn:         func() time.Duration { return 10 * time.Minute },
		Run:                func(rc taskengine.RunContext) error { CertManualCheckOnce(); return nil },
	})
	taskEngine.Register(taskengine.Descriptor{
		ID: "cert-waiting-ca", Family: "certificates", Name: "CA 等待轮询",
		Description: "证书任务在途时的兜底补扫：CA 冷却到期重排、滞留 queued 重入队、断链部署重试重建。门控——有非终态任务才扫描，全部完成即静默；可经调度开关停用",
		Category:    "证书", Kind: taskengine.KindContinuous, RunsOn: taskengine.RoleMasterOnly,
		RecordFailuresOnly: true, // 30s 补扫成功静默——仅断链/失败留痕
		IntervalFn:         func() time.Duration { return 30 * time.Second },
		StatusFn: func() string { // 有活=运行中/无活=空闲/关停=已停止（门控后零空转）
			if certJobsActive() { // U7-P5-1：复用 certificates.go 单一实现（曾同 COUNT 两处重复）
				return "running"
			}
			if te := TaskEngine(); te != nil && te.IsRunning("cert-waiting-ca") {
				return "idle"
			}
			return "stopped"
		},
		NextSlotFn: func() string { // 有等待任务时展示最近 CA 可用时间
			var at string
			// P2-③：原 SQL 缺 2 右括号且 NULLIF 误传 3 参（M2 接线笔误）——恒语法
			// 错误且 err 被吞，「下次 CA 可用时间」上线即恒空。
			if err := db.DB.QueryRow(`SELECT COALESCE(MIN(NULLIF(ca_available_after,'')),'') FROM cert_jobs WHERE status='waiting_ca'`).Scan(&at); err != nil {
				Logf("warn", "cert-waiting-ca: 查询下次 CA 可用时间失败: %v", err)
				return ""
			}
			if at != "" {
				return localDisplayUTC(at)
			}
			return ""
		},
		Run: func(rc taskengine.RunContext) error { CertWaitingCATickOnce(); return nil },
	})
	// —— 集群同步（角色驱动循环：身份入册，执行留集群服务——promote/demote 生命周期） ——
	taskEngine.Register(taskengine.Descriptor{
		ID:          "cluster-sync",
		Family:      "cluster",
		Name:        "集群同步",
		Description: "从节点按用户配置的同步间隔轮询主节点快照并增量回放；主节点为签发方（空闲）",
		Category:    "集群",
		Kind:        taskengine.KindInfo,
		StatusFn: func() string { // 定时语义：从节点回放中=运行中/主节点签发方=空闲
			var isMaster int
			if err := db.DB.QueryRow("SELECT COALESCE(is_master,1) FROM global_config WHERE id=1").Scan(&isMaster); err != nil {
				return ""
			}
			if isMaster == 1 {
				return "idle"
			}
			return "running"
		},
		NextSlotFn: func() string { // 从节点：最近同步 + 间隔（自适应退避期如实按基准间隔展示）
			var isMaster int
			var interval int
			var lastSync string
			if err := db.DB.QueryRow("SELECT COALESCE(is_master,1), COALESCE(sync_interval,60), COALESCE(last_sync,'') FROM global_config WHERE id=1").Scan(&isMaster, &interval, &lastSync); err != nil || isMaster == 1 || lastSync == "" {
				return ""
			}
			if t, err := time.Parse(time.RFC3339, lastSync); err == nil {
				return t.Add(time.Duration(interval) * time.Second).In(CurrentLocation()).Format("2006-01-02 15:04:05")
			}
			return ""
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
		Category:    "系统",
		Kind:        taskengine.KindOneshot, // 类型「触发」——启动单次+可手动重载
		ManualRun:   true,
		Run: func(rc taskengine.RunContext) error {
			if rc.Trigger != "manual" {
				return nil // 启动执行由 main startupPhase 记录——引擎 Run 仅承载手动重载
			}
			if configLoadRerun == nil {
				return errors.New("配置重载未接线")
			}
			return configLoadRerun()
		},
	})

	// 任务性质批量标定（展示口径）：排程/固定间隔族由探测轮或间隔驱动，
	// 但性质是「定时」——只有真常驻循环（看门狗/事件摄取）是「常驻」。
	for _, id := range []string{"threat", "crs", "ip2region", "auto-backup", "log-cleanup", "audit-retention", "security-events-retention", "cert-renewal-scan", "cert-reconcile", "cert-manual-poll", "cluster-sync"} {
		taskEngine.SetAsKind(id, taskengine.KindScheduled)
	}

	// 手动触发语义（仅定时性质族——常驻族无「立即执行」概念，启停即可）：
	// 更新族 Run 内含 manual 分支；清理/证书循环 Run 即单轮工作；自动备份
	// manual=直接执行一轮备份；系统配置载入 manual=重渲染重应用。
	for _, id := range []string{"threat", "crs", "ip2region", "log-cleanup", "audit-retention", "security-events-retention", "cert-renewal-scan", "cert-reconcile", "cert-manual-poll", "auto-backup", "startup:config-load"} {
		taskEngine.SetManualRun(id, true)
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
